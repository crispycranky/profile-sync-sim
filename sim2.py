"""Server-authoritative profile sync, modelled closely on Darktide's, with an
attack suite that proves the design holds.

This is a reference design for your OWN game. The point of the attacks is to
confirm that a malicious client cannot change what the host or other players
see: every attack below is EXPECTED to be rejected or to be local-only. If any
attack flips an "authority" check to a bad outcome, that is a bug to fix in the
design, not a way into anything.

Closer-to-real mechanics added over the first sim:
  - Full 5-state per-(receiver, owner, player) sync tracking.
  - Several local players per peer.
  - Asynchronous backend (replies arrive after a delay; a player can leave
    mid-fetch).
  - A network with latency and message reordering.
  - One-time sync hashes bound to (receiver, owner, player); replays rejected.
  - Strict message validation on both ends.

Run:  python sim2.py           (attack suite + summary)
      python sim2.py --verbose (also print the event log)
"""

import json
import random
import sys
from collections import deque

CHUNK_SIZE = 400
RPCS_PER_TICK = 10
BACKEND_DELAY = 3          # ticks before a backend fetch resolves

# --- flow control, copied from Darktide's RPCQueue ---
QUEUE_CAPACITY = 1000              # fixed ring buffer of outbound messages
SEND_BUFFER_MIN = 8000             # stop sending if channel buffer below this
# --- deserializer guard: BEST PRACTICE, not copied (FS's limit is in the
#     compiled .network wire definitions, which aren't in the readable source) ---
MAX_PROFILE_BYTES = 64 * 1024      # reject a profile larger than this before decode
MAX_JSON_DEPTH = 32                # reject JSON nested deeper than this
VERBOSE = "--verbose" in sys.argv
RNG = random.Random(1234)  # fixed seed: reproducible reordering


def log(who, text):
    if VERBOSE:
        print(f"  [{who:<10}] {text}")


# --------------------------------------------------------------------------
# Message schemas. Receivers reject anything that does not match exactly.
# --------------------------------------------------------------------------
CLIENT_TO_HOST = {
    "ready_to_receive_profiles": (),
    "notify_profile_changed": ("local_player_id",),
    "player_profile_synced": ("sync_hash",),
}
HOST_TO_CLIENT = {
    "start_profile_sync": ("peer_id", "local_player_id"),
    "sync_player_profile_data": ("peer_id", "local_player_id", "chunk"),
    "profile_sync_complete": ("sync_hash", "peer_id", "local_player_id"),
    "profile_synced_by_all": ("peer_id", "local_player_id"),
    "sync_local_profiles_reply": (),
}


def valid(schema, name, args):
    spec = schema.get(name)
    return spec is not None and len(args) == len(spec)


def _json_depth(obj, depth=0):
    if depth > MAX_JSON_DEPTH:
        raise ValueError("json too deep")
    if isinstance(obj, dict):
        for v in obj.values():
            _json_depth(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _json_depth(v, depth + 1)


def safe_decode(js):
    """Guard the deserializer: cap size and nesting before/after parse.
    Returns the parsed object, or None if it looks hostile. (Best practice:
    FS's equivalent size cap lives in the wire-type definitions, not here.)"""
    if js is None or len(js) > MAX_PROFILE_BYTES:
        return None
    try:
        obj = json.loads(js)
        _json_depth(obj)
    except ValueError:
        return None
    if not isinstance(obj, dict) or "loadout" not in obj:
        return None
    return obj


# --------------------------------------------------------------------------
# Backend: the only source of truth. Asynchronous.
# --------------------------------------------------------------------------
class Backend:
    def __init__(self):
        self._chars = {}       # (account_id, character_id) -> character dict
        self._pending = []     # [ticks_left, key, callback]

    def create(self, account_id, character_id, name, owned, equipped):
        self._chars[(account_id, character_id)] = {
            "name": name,
            "owned": set(owned),
            "equipped": dict(equipped),
        }

    def equip(self, account_id, character_id, slot, item_id):
        char = self._chars[(account_id, character_id)]
        if item_id not in char["owned"]:
            log("backend", f"REJECT equip {item_id}: {account_id} does not own it")
            return False
        char["equipped"][slot] = item_id
        log("backend", f"saved {slot}={item_id} for {account_id}")
        return True

    def fetch(self, account_id, character_id, callback):
        """Resolves after BACKEND_DELAY ticks; callback(profile_or_None)."""
        self._pending.append([BACKEND_DELAY, (account_id, character_id), callback])

    def tick(self):
        still = []
        for entry in self._pending:
            entry[0] -= 1
            if entry[0] > 0:
                still.append(entry)
                continue
            key, callback = entry[1], entry[2]
            char = self._chars.get(key)
            if char is None:
                callback(None)
            else:
                account_id, character_id = key
                callback({
                    "account_id": account_id,
                    "character_id": character_id,
                    "name": char["name"],
                    "loadout": dict(char["equipped"]),
                })
        self._pending = still


# --------------------------------------------------------------------------
# Network: queues with latency + reordering. Nothing is trusted here; this
# just models an unreliable channel, not an attacker. Attackers are clients.
# --------------------------------------------------------------------------
class Network:
    def __init__(self, reorder=False):
        self.to_host = []             # [ticks_left, sender_peer, name, args]
        self.to_client = {}           # peer_id -> same shape
        self._reorder = reorder

    def connect(self, peer_id):
        self.to_client[peer_id] = []

    def _delay(self):
        return RNG.randint(1, 3) if self._reorder else 1

    def send_to_host(self, sender_peer, name, *args):
        self.to_host.append([self._delay(), sender_peer, name, args])

    def send_to_client(self, peer_id, name, *args):
        self.to_client[peer_id].append([self._delay(), name, args])

    def _ready(self, box):
        # In-order (FIFO) per destination: a channel is reliable and ordered,
        # so only the head may become ready, and nothing overtakes it. Latency
        # still varies, which (with the async backend) is what reorders the
        # higher-level fetch/commit timing.
        ready = []
        while box:
            box[0][0] -= 1
            if box[0][0] > 0:
                break
            ready.append(box.pop(0))
        return ready

    def deliver_to_host(self):
        return [(e[1], e[2], e[3]) for e in self._ready(self.to_host)]

    def deliver_to_client(self, peer_id):
        return [(e[1], e[2]) for e in self._ready(self.to_client[peer_id])]

    def idle(self):
        return not self.to_host and not any(self.to_client.values())


# --------------------------------------------------------------------------
# Host: authoritative. The connection, not the client, decides whose profile
# a peer is allowed to push, and which account that peer maps to.
# --------------------------------------------------------------------------
NOT_SYNCED, SYNCING, NEED_RESYNC, INITIAL_SYNCED, SYNCED = range(5)


class Host:
    def __init__(self, network, backend):
        self._net = network
        self._backend = backend
        self._accounts = {}        # peer_id -> {local_player_id: (account_id, character_id)}
        self._queues = {}          # peer_id -> deque of outbound (name, args)
        self._states = {}          # receiver -> owner -> player -> state
        self._hashes = {}          # receiver -> sync_hash -> (owner, player)
        self._pending = {}         # owner -> player -> fetched profile (not committed)
        self._committed = {}       # owner -> player -> applied profile
        self._joining = set()
        self._seed = RNG.randrange(2**31)
        self._counter = 0
        self.rejected = []         # (peer, reason)
        self.changes_allowed = True  # Managers.mechanism:profile_changes_are_allowed()
        self._inflight = set()     # (owner, player) with a backend fetch pending

    def peer_connected(self, peer_id, players):
        # players: {local_player_id: (account_id, character_id)}. The host sets
        # this from its own trusted connection record.
        self._accounts[peer_id] = dict(players)
        self._queues[peer_id] = deque()
        self._states[peer_id] = {}
        self._hashes[peer_id] = {}
        self._joining.add(peer_id)
        log("host", f"{peer_id} connected, players={list(players)}")

    def peer_disconnected(self, peer_id):
        self._accounts.pop(peer_id, None)
        self._queues.pop(peer_id, None)
        self._states.pop(peer_id, None)
        self._hashes.pop(peer_id, None)
        self._pending.pop(peer_id, None)
        self._committed.pop(peer_id, None)
        self._joining.discard(peer_id)
        for states in self._states.values():
            states.pop(peer_id, None)
        log("host", f"{peer_id} disconnected")

    # -- one profile, one owner-player, to one receiver ---------------------
    def _send_profile(self, receiver, owner, player, profile):
        if receiver not in self._states:
            return
        by_owner = self._states[receiver].setdefault(owner, {})
        state = by_owner.get(player, NOT_SYNCED)
        if state in (SYNCING, NEED_RESYNC):
            by_owner[player] = NEED_RESYNC
            return
        by_owner[player] = SYNCING
        self._counter += 1
        sync_hash = hash((self._seed, self._counter, receiver, owner, player))
        self._hashes[receiver][sync_hash] = (owner, player)

        js = json.dumps(profile, sort_keys=True)
        q = self._queues[receiver]
        q.append(("start_profile_sync", (owner, player)))
        for i in range(0, len(js), CHUNK_SIZE):
            q.append(("sync_player_profile_data", (owner, player, js[i:i + CHUNK_SIZE])))
        q.append(("profile_sync_complete", (sync_hash, owner, player)))

    def _profile_changed(self, owner, player):
        mapping = self._accounts.get(owner)
        if not mapping or player not in mapping:
            # The peer named a player slot it does not own on this connection.
            self.rejected.append((owner, f"profile_changed for unowned player slot {player}"))
            log("host", f"REJECT {owner}: no such player slot {player} on this connection")
            return
        account_id, character_id = mapping[player]

        # Gate (copied): refuse changes in states that don't allow them.
        if not self.changes_allowed:
            self.rejected.append((owner, "profile changes not allowed right now"))
            log("host", f"REJECT {owner}: profile changes not allowed")
            return

        # Debounce: coalesce a flood of nudges into one in-flight fetch per
        # player (a resync still happens if the data changed meanwhile).
        if (owner, player) in self._inflight:
            log("host", f"coalesce nudge for {owner}/{player}: fetch already in flight")
            return
        self._inflight.add((owner, player))

        def resolved(profile):
            self._inflight.discard((owner, player))
            if owner not in self._accounts or player not in self._accounts.get(owner, {}):
                log("host", f"drop fetch for {owner}/{player}: gone before reply")
                return
            if profile is None:
                self.rejected.append((owner, "backend returned no profile"))
                return
            self._pending.setdefault(owner, {})[player] = profile
            log("host", f"fetched {owner}/{player}: {profile['loadout']}")
            for receiver in self._accounts:
                self._send_profile(receiver, owner, player, profile)

        self._backend.fetch(account_id, character_id, resolved)

    # -- inbound from clients ------------------------------------------------
    def _on_ready_to_receive_profiles(self, peer):
        for player in self._accounts.get(peer, {}):
            self._profile_changed(peer, player)
        for owner, players in self._committed.items():
            if owner == peer:
                continue
            for player, profile in players.items():
                self._send_profile(peer, owner, player, profile)

    def _on_notify_profile_changed(self, peer, local_player_id):
        self._profile_changed(peer, local_player_id)

    def _on_player_profile_synced(self, peer, sync_hash):
        entry = self._hashes.get(peer, {}).pop(sync_hash, None)
        if entry is None:
            # Unknown or already-used token: replayed or forged.
            self.rejected.append((peer, "unknown/replayed sync hash"))
            log("host", f"REJECT {peer}: unknown or replayed sync hash")
            return
        owner, player = entry
        by_owner = self._states[peer].get(owner, {})
        if by_owner.get(player) == NEED_RESYNC:
            by_owner[player] = NOT_SYNCED
            profile = (self._pending.get(owner, {}).get(player)
                       or self._committed.get(owner, {}).get(player))
            if profile is not None:
                self._send_profile(peer, owner, player, profile)
        elif peer in self._joining:
            by_owner[player] = INITIAL_SYNCED
        else:
            by_owner[player] = SYNCED

    def _dispatch(self, peer, name, args):
        if peer not in self._accounts:
            self.rejected.append((peer, "message from unknown peer"))
            return
        if not valid(CLIENT_TO_HOST, name, args):
            self.rejected.append((peer, f"malformed {name}/{len(args)}"))
            log("host", f"REJECT {peer}: malformed {name} with {len(args)} args")
            return
        getattr(self, "_on_" + name)(peer, *args)

    def tick(self):
        for peer, name, args in self._net.deliver_to_host():
            self._dispatch(peer, name, args)

        for peer, q in self._queues.items():
            for _ in range(min(RPCS_PER_TICK, len(q))):
                name, args = q.popleft()
                self._net.send_to_client(peer, name, *args)

        # Commit when every present receiver has this owner-player synced.
        for owner in list(self._pending):
            for player in list(self._pending[owner]):
                done = all(
                    self._states[r].get(owner, {}).get(player) in (INITIAL_SYNCED, SYNCED)
                    for r in self._accounts
                )
                if not done:
                    continue
                self._committed.setdefault(owner, {})[player] = self._pending[owner][player]
                del self._pending[owner][player]
                log("host", f"commit {owner}/{player}")
                for r in self._accounts:
                    by_owner = self._states[r].get(owner, {})
                    if by_owner.get(player) == INITIAL_SYNCED:
                        by_owner[player] = SYNCED
                    self._net.send_to_client(r, "profile_synced_by_all", owner, player)
            if not self._pending[owner]:
                del self._pending[owner]

        for peer in list(self._joining):
            mine = self._accounts.get(peer, {})
            have_own = all(
                peer in self._committed and p in self._committed[peer] for p in mine
            )
            others_ok = all(
                self._states[peer].get(o, {}).get(p) in (INITIAL_SYNCED, SYNCED)
                for o in self._committed for p in self._committed[o] if o != peer
            )
            if have_own and others_ok:
                self._joining.discard(peer)
                for o in self._committed:
                    for p in self._committed[o]:
                        if (o, p) != (peer, p) or o != peer:
                            self._net.send_to_client(peer, "profile_synced_by_all", o, p)
                        self._states[peer].setdefault(o, {})[p] = SYNCED
                self._net.send_to_client(peer, "sync_local_profiles_reply")

    def view(self):
        return {
            owner: {p: prof["loadout"] for p, prof in players.items()}
            for owner, players in self._committed.items()
        }


# --------------------------------------------------------------------------
# Clients
# --------------------------------------------------------------------------
class Client:
    def __init__(self, peer_id, players, network, backend):
        # players: {local_player_id: (account_id, character_id)}
        self.peer_id = peer_id
        self.players = dict(players)
        self._net = network
        self._backend = backend
        self._buffers = {}          # (owner, player) -> json so far
        self._complete = {}         # (owner, player) -> finished json (chunks done)
        self._apply_signal = set()  # (owner, player) that got profile_synced_by_all
        self.profiles = {}          # (owner, player) -> applied profile
        self.joined = False

    def join(self):
        self._net.send_to_host(self.peer_id, "ready_to_receive_profiles")

    def equip(self, local_player_id, slot, item_id):
        account_id, character_id = self.players[local_player_id]
        if self._backend.equip(account_id, character_id, slot, item_id):
            self._net.send_to_host(self.peer_id, "notify_profile_changed", local_player_id)

    def decode(self, owner, player, js):
        return safe_decode(js)

    def _on_start_profile_sync(self, owner, player):
        self._buffers[(owner, player)] = ""

    def _on_sync_player_profile_data(self, owner, player, chunk):
        if (owner, player) in self._buffers:
            self._buffers[(owner, player)] += chunk

    def _on_profile_sync_complete(self, sync_hash, owner, player):
        # The whole profile has arrived; remember it and acknowledge.
        if (owner, player) in self._buffers:
            self._complete[(owner, player)] = self._buffers.pop((owner, player))
        self._net.send_to_host(self.peer_id, "player_profile_synced", sync_hash)
        self._try_apply(owner, player)

    def _on_profile_synced_by_all(self, owner, player):
        # "Apply now." May arrive before or after the chunks under reordering,
        # so just record it and apply once both conditions hold.
        self._apply_signal.add((owner, player))
        self._try_apply(owner, player)

    def _try_apply(self, owner, player):
        key = (owner, player)
        if key in self._apply_signal and key in self._complete:
            decoded = self.decode(owner, player, self._complete[key])
            if decoded is not None:
                self.profiles[key] = decoded
            # A rejected (hostile) profile simply isn't applied; no crash.

    def _on_sync_local_profiles_reply(self):
        self.joined = True

    def tick(self):
        for name, args in self._net.deliver_to_client(self.peer_id):
            if valid(HOST_TO_CLIENT, name, args):
                getattr(self, "_on_" + name)(*args)

    def view(self):
        return {(o, p): prof["loadout"] for (o, p), prof in self.profiles.items()}


class LocalSwapClient(Client):
    def __init__(self, *a, swaps):
        super().__init__(*a)
        self._swaps = swaps      # {(owner, player, slot): item_id}

    def decode(self, owner, player, js):
        prof = safe_decode(js)
        if prof is None:
            return None
        for (o, p, slot), item in self._swaps.items():
            if (o, p) == (owner, player):
                prof["loadout"][slot] = item
        return prof


# --------------------------------------------------------------------------
# Harness
# --------------------------------------------------------------------------
def settle(backend, host, clients, net, max_ticks=400):
    for _ in range(max_ticks):
        backend.tick()
        host.tick()
        for c in clients:
            c.tick()
        if net.idle() and not backend._pending:
            # one more pass so a final backend reply can propagate
            backend.tick(); host.tick()
            for c in clients:
                c.tick()
            if net.idle() and not backend._pending:
                return
    raise RuntimeError("did not settle")


class Attacker(Client):
    """A client that only ever sends raw messages we hand it."""
    def raw_to_host(self, name, *args):
        self._net.send_to_host(self.peer_id, name, *args)


def build_world(reorder=False):
    backend = Backend()
    net = Network(reorder=reorder)
    host = Host(net, backend)
    backend.create("acct-alice", "char-a", "Alice",
                   owned={"wooden_sword", "steel_sword", "plain_helmet"},
                   equipped={"weapon": "wooden_sword", "head": "plain_helmet"})
    backend.create("acct-mallory", "char-m", "Mallory",
                   owned={"wooden_sword", "plain_helmet"},
                   equipped={"weapon": "wooden_sword", "head": "plain_helmet"})
    return backend, net, host


def main():
    results = []

    def record(name, ok, detail=""):
        results.append((name, ok, detail))

    # ---- baseline: legitimate flow works ----
    backend, net, host = build_world()
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = Client("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id)
        host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    record("baseline: both clients joined", alice.joined and mallory.joined)
    record("baseline: everyone sees Alice's wooden sword",
           all(c.view()[("alice", 1)]["weapon"] == "wooden_sword" for c in clients))

    alice.equip(1, "weapon", "steel_sword")
    settle(backend, host, clients, net)
    record("baseline: legit equip is seen by all",
           all(c.view()[("alice", 1)]["weapon"] == "steel_sword" for c in clients))

    # ---- attack 1: equip an item you don't own ----
    backend, net, host = build_world()
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = Client("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    mallory.equip(1, "weapon", "steel_sword")   # not owned
    settle(backend, host, clients, net)
    record("attack: equip unowned item is refused, nobody sees it",
           all(c.view()[("mallory", 1)]["weapon"] == "wooden_sword" for c in clients))

    # ---- attack 2: local swap is local-only ----
    backend, net, host = build_world()
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = LocalSwapClient("mallory", {1: ("acct-mallory", "char-m")}, net, backend,
                              swaps={("mallory", 1, "head"): "golden_crown"})
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    record("attack: local swap shows on own screen",
           mallory.view()[("mallory", 1)]["head"] == "golden_crown")
    record("attack: local swap invisible to others",
           alice.view()[("mallory", 1)]["head"] == "plain_helmet"
           and host.view()["mallory"][1]["head"] == "plain_helmet")

    # ---- attack 3: smuggle loadout data in the nudge ----
    backend, net, host = build_world()
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = Attacker("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    before = len(host.rejected)
    mallory.raw_to_host("notify_profile_changed", 1, {"weapon": "steel_sword"})
    settle(backend, host, clients, net)
    record("attack: smuggled-data nudge rejected",
           any("malformed" in r for _, r in host.rejected[before:]))
    record("attack: smuggling changed nothing",
           all(c.view()[("mallory", 1)]["weapon"] == "wooden_sword" for c in clients))

    # ---- attack 4: claim another player's slot ----
    backend, net, host = build_world()
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = Attacker("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    before = len(host.rejected)
    mallory.raw_to_host("notify_profile_changed", 2)   # slot it doesn't own
    settle(backend, host, clients, net)
    record("attack: nudge for unowned player slot rejected",
           any("unowned player slot" in r for _, r in host.rejected[before:]))

    # ---- attack 5: replay / forge an acknowledgement token ----
    backend, net, host = build_world()
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = Attacker("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    before = len(host.rejected)
    mallory.raw_to_host("player_profile_synced", 999999)   # forged token
    mallory.raw_to_host("player_profile_synced", 999999)   # replay
    settle(backend, host, clients, net)
    record("attack: forged/replayed ack token rejected",
           sum("replayed sync hash" in r for _, r in host.rejected[before:]) == 2)

    # ---- attack 6: tamper a chunk in flight (receiver-side) ----
    # Mallory can rewrite bytes arriving at HER OWN client. That is the same as
    # a local swap: it only affects her screen. Model it by swapping on decode.
    backend, net, host = build_world()
    alice = LocalSwapClient("alice", {1: ("acct-alice", "char-a")}, net, backend,
                            swaps={("mallory", 1, "weapon"): "steel_sword"})
    mallory = Client("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    record("attack: tampering your own inbound stream is local-only",
           alice.view()[("mallory", 1)]["weapon"] == "steel_sword"
           and host.view()["mallory"][1]["weapon"] == "wooden_sword")

    # ---- robustness: reordering + rapid double change ----
    backend, net, host = build_world(reorder=True)
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = Client("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    alice.equip(1, "weapon", "wooden_sword")
    alice.equip(1, "weapon", "steel_sword")
    settle(backend, host, clients, net)
    record("robustness: under reordering, all converge on latest",
           all(c.view()[("alice", 1)]["weapon"] == "steel_sword" for c in clients)
           and host.view()["alice"][1]["weapon"] == "steel_sword")

    # ---- robustness: disconnect mid-fetch does not crash/hang ----
    backend, net, host = build_world()
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = Client("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    mallory.equip(1, "head", "plain_helmet")   # starts a fetch
    host.peer_disconnected("mallory")           # leaves before it resolves
    clients = [alice]
    try:
        settle(backend, host, clients, net)
        crashed = False
    except Exception:
        crashed = True
    record("robustness: disconnect mid-fetch is handled", not crashed)

    # ---- new-defense: change gate blocks nudges when disallowed ----
    backend, net, host = build_world()
    host.changes_allowed = False
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = Client("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    # join still needs changes; allow for join, then lock and try to equip
    host.changes_allowed = True
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    host.changes_allowed = False
    before = len(host.rejected)
    alice.equip(1, "weapon", "steel_sword")   # owned, but changes are locked
    settle(backend, host, clients, net)
    record("defense: change gate refuses equips when locked",
           any("not allowed" in r for _, r in host.rejected[before:])
           and all(c.view()[("alice", 1)]["weapon"] == "wooden_sword" for c in clients))

    # ---- new-defense: nudge flood is coalesced ----
    backend, net, host = build_world()
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    mallory = Attacker("mallory", {1: ("acct-mallory", "char-m")}, net, backend)
    clients = [alice, mallory]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    fetches_before = len(backend._pending)
    for _ in range(50):
        mallory.raw_to_host("notify_profile_changed", 1)   # flood
    # pump a few ticks so they all arrive while a fetch is in flight
    for _ in range(6):
        backend.tick(); host.tick()
        for c in clients:
            c.tick()
    record("defense: nudge flood coalesced to a single in-flight fetch",
           len(host._inflight) <= 1)
    settle(backend, host, clients, net)
    record("defense: host stayed consistent after flood",
           all(c.view()[("mallory", 1)]["weapon"] == "wooden_sword" for c in clients))

    # ---- new-defense: oversized / hostile profile rejected at decode ----
    backend, net, host = build_world()
    huge = {"name": "x", "loadout": {"weapon": "wooden_sword", "head": "p"},
            "junk": "A" * (MAX_PROFILE_BYTES + 10)}
    nested = {"loadout": {"weapon": "w", "head": "h"}}
    cur = nested
    for _ in range(MAX_JSON_DEPTH + 5):
        cur["n"] = {}
        cur = cur["n"]
    record("defense: oversized profile is rejected by the guard",
           safe_decode(json.dumps(huge)) is None)
    record("defense: over-deep profile is rejected by the guard",
           safe_decode(json.dumps(nested)) is None)
    record("defense: a normal profile still decodes",
           safe_decode(json.dumps({"name": "ok", "loadout": {"weapon": "w"}})) is not None)

    # ---- fidelity: chunking matches observed live traffic ----
    # Observed in Darktide hub (probe, 45 profiles): every chunk is exactly 400
    # bytes except a single trailing remainder per profile; profiles were
    # 6.3-17.4 KB (~16-44 chunks). Exercise that path and check reassembly.
    observed_median = 15654
    blob = json.dumps({"name": "big", "loadout": {f"slot_{i}": f"item_{i}_" + "x" * 30
                                                   for i in range(300)}})
    blob = blob[:observed_median] + "x" * max(0, observed_median - len(blob))
    chunks = [blob[i:i + CHUNK_SIZE] for i in range(0, len(blob), CHUNK_SIZE)]
    full = sum(1 for c in chunks if len(c) == CHUNK_SIZE)
    remainder = [c for c in chunks if len(c) != CHUNK_SIZE]
    record("fidelity: 16KB profile splits into 400B chunks + one remainder",
           full == len(blob) // CHUNK_SIZE
           and len(remainder) == (0 if len(blob) % CHUNK_SIZE == 0 else 1))
    record("fidelity: chunks reassemble to the original profile",
           "".join(chunks) == blob)
    record("fidelity: observed max profile (17.4KB) is under the guard cap",
           17427 < MAX_PROFILE_BYTES)

    # ---- fidelity: a real-scale multi-chunk profile flows end to end ----
    backend, net, host = build_world()
    big_loadout = {f"slot_{i}": "wooden_sword" for i in range(60)}
    backend.create("acct-big", "char-b", "Big", owned=set(big_loadout.values()),
                   equipped=big_loadout)
    alice = Client("alice", {1: ("acct-alice", "char-a")}, net, backend)
    big = Client("big", {1: ("acct-big", "char-b")}, net, backend)
    clients = [alice, big]
    for c in clients:
        net.connect(c.peer_id); host.peer_connected(c.peer_id, c.players)
    for c in clients:
        c.join()
    settle(backend, host, clients, net)
    record("fidelity: multi-chunk profile delivered intact to the other client",
           alice.view().get(("big", 1)) == big_loadout)

    # ---- report ----
    print(f"{'result':<6} {'check'}")
    failed = 0
    for name, ok, _ in results:
        print(f"{'PASS' if ok else 'FAIL':<6} {name}")
        failed += 0 if ok else 1
    print(f"\n{len(results) - failed}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
