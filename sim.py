"""Mini simulation of a server-authoritative profile sync.

Three parts, all in one process, talking only through message queues:

  Backend  - the account database. The only place that knows what a player
             owns and has equipped. Validates equip requests.
  Host     - the mission server. Never takes loadout data from a client; on a
             "my profile changed" nudge it fetches the profile from the Backend
             and distributes it to every connected client in chunks.
  Client   - a player's game. Receives profiles, acknowledges them, and builds
             its own view of every player from what the host sent.

Run:  python sim.py            (scripted demo with a log)
      python sim.py --quiet    (just the checks and the final views)
"""

import json
import random
import sys
from collections import deque

CHUNK_SIZE = 400          # characters of profile JSON per data message
RPCS_PER_TICK = 10        # how many queued messages the host sends per tick

QUIET = "--quiet" in sys.argv


def log(who, text):
    if not QUIET:
        print(f"  [{who:<8}] {text}")


# --------------------------------------------------------------------------
# Message schemas. A message that does not match its declared shape is
# rejected by the receiver before any handler runs.
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


def valid_message(schema, name, args):
    return name in schema and len(args) == len(schema[name])


# --------------------------------------------------------------------------
# Backend: the source of truth
# --------------------------------------------------------------------------
class Backend:
    def __init__(self):
        self._characters = {}   # account_id -> {"name", "owned", "equipped"}

    def create_character(self, account_id, name, owned, equipped):
        self._characters[account_id] = {
            "name": name,
            "owned": set(owned),
            "equipped": dict(equipped),
        }

    def equip(self, account_id, slot, item_id):
        """Equip request from a player's client. Ownership is checked here."""
        character = self._characters[account_id]

        if item_id not in character["owned"]:
            log("backend", f"REJECT equip {item_id} for {account_id}: not owned")
            return False

        character["equipped"][slot] = item_id
        log("backend", f"equip {item_id} in {slot} for {account_id}: saved")
        return True

    def fetch_character(self, account_id):
        character = self._characters[account_id]

        return {
            "account_id": account_id,
            "name": character["name"],
            "loadout": dict(character["equipped"]),
        }


# --------------------------------------------------------------------------
# Network: two queues per connection, delivered one tick later
# --------------------------------------------------------------------------
class Network:
    def __init__(self):
        self.to_host = deque()      # (peer_id, name, args)
        self.to_client = {}         # peer_id -> deque of (name, args)

    def connect(self, peer_id):
        self.to_client[peer_id] = deque()

    def send_to_host(self, peer_id, name, *args):
        self.to_host.append((peer_id, name, args))

    def send_to_client(self, peer_id, name, *args):
        self.to_client[peer_id].append((name, args))


# --------------------------------------------------------------------------
# Host: fetches from the backend, distributes, tracks acknowledgements
# --------------------------------------------------------------------------
NOT_SYNCED, SYNCING, NEED_RESYNC, SYNCED = "not_synced", "syncing", "need_resync", "synced"


class Host:
    def __init__(self, network, backend):
        self._network = network
        self._backend = backend
        self._accounts = {}        # peer_id -> account_id (set at connect, by the host)
        self._send_queues = {}     # peer_id -> deque of (name, args)
        self._sync_states = {}     # receiver peer -> owner peer -> state
        self._sync_hashes = {}     # receiver peer -> hash -> owner peer
        self._pending = {}         # owner peer -> newest fetched profile, not yet committed
        self._committed = {}       # owner peer -> profile every peer has acknowledged
        self._joining = set()      # peers still in their join handshake
        self._hash_seed = random.randrange(2**31)
        self._hash_counter = 0
        self.rejected_messages = []

    # -- connection ---------------------------------------------------------
    def peer_connected(self, peer_id, account_id):
        self._accounts[peer_id] = account_id
        self._send_queues[peer_id] = deque()
        self._sync_states[peer_id] = {}
        self._sync_hashes[peer_id] = {}
        self._joining.add(peer_id)
        log("host", f"{peer_id} connected (account {account_id})")

    # -- sending one profile to one peer -------------------------------------
    def _sync_profile_to(self, receiver, owner, profile):
        states = self._sync_states[receiver]
        state = states.get(owner)

        if state in (SYNCING, NEED_RESYNC):
            # A transfer of this profile is already in flight: resend once
            # it has been acknowledged instead of interleaving two.
            states[owner] = NEED_RESYNC
            return

        states[owner] = SYNCING
        self._hash_counter += 1

        sync_hash = hash((self._hash_seed, self._hash_counter, receiver, owner))
        self._sync_hashes[receiver][sync_hash] = owner

        profile_json = json.dumps(profile, sort_keys=True)
        queue = self._send_queues[receiver]

        queue.append(("start_profile_sync", (owner, 1)))

        for start in range(0, len(profile_json), CHUNK_SIZE):
            queue.append(("sync_player_profile_data", (owner, 1, profile_json[start:start + CHUNK_SIZE])))

        queue.append(("profile_sync_complete", (sync_hash, owner, 1)))

    def _profile_changed(self, owner):
        # The profile always comes from the backend, keyed by the account the
        # host recorded for this connection. Nothing from the client is used.
        profile = self._backend.fetch_character(self._accounts[owner])
        log("host", f"fetched {owner}'s profile from backend: {profile['loadout']}")

        self._pending[owner] = profile

        for receiver in self._accounts:
            self._sync_profile_to(receiver, owner, profile)

    # -- incoming messages ---------------------------------------------------
    def _on_ready_to_receive_profiles(self, peer_id):
        # Join: send the newcomer every known profile (its own included), and
        # send the newcomer's profile to everyone already here.
        self._profile_changed(peer_id)

        for owner, profile in self._committed.items():
            if owner != peer_id:
                self._sync_profile_to(peer_id, owner, profile)

    def _on_notify_profile_changed(self, peer_id, local_player_id):
        log("host", f"nudge from {peer_id}: profile changed")
        self._profile_changed(peer_id)

    def _on_player_profile_synced(self, peer_id, sync_hash):
        owner = self._sync_hashes[peer_id].pop(sync_hash, None)

        if owner is None:
            log("host", f"ignored unknown sync hash from {peer_id}")
            return

        states = self._sync_states[peer_id]

        if states[owner] == NEED_RESYNC:
            states[owner] = NOT_SYNCED
            self._sync_profile_to(peer_id, owner, self._pending.get(owner) or self._committed[owner])
        else:
            states[owner] = SYNCED

    def _dispatch(self, peer_id, name, args):
        if not valid_message(CLIENT_TO_HOST, name, args):
            self.rejected_messages.append((peer_id, name, args))
            log("host", f"REJECT malformed message from {peer_id}: {name} with {len(args)} args")
            return

        getattr(self, "_on_" + name)(peer_id, *args)

    # -- per tick -------------------------------------------------------------
    def update(self):
        network = self._network

        while network.to_host:
            self._dispatch(*network.to_host.popleft())

        for peer_id, queue in self._send_queues.items():
            for _ in range(min(RPCS_PER_TICK, len(queue))):
                name, args = queue.popleft()
                network.send_to_client(peer_id, name, *args)

        # Commit a pending profile only once every peer has acknowledged it,
        # then tell everyone to apply it at the same time.
        for owner in list(self._pending):
            if all(states.get(owner) == SYNCED for states in self._sync_states.values()):
                self._committed[owner] = self._pending.pop(owner)
                log("host", f"all peers have {owner}'s profile: committing")

                for receiver in self._accounts:
                    network.send_to_client(receiver, "profile_synced_by_all", owner, 1)

        for peer_id in list(self._joining):
            states = self._sync_states[peer_id]

            if peer_id in self._committed and all(state == SYNCED for state in states.values()):
                self._joining.discard(peer_id)

                # Profiles that were committed before this peer arrived never
                # get another "synced by all" broadcast, so tell the newcomer
                # to apply the copies it has just buffered.
                for owner in self._committed:
                    if owner != peer_id:
                        network.send_to_client(peer_id, "profile_synced_by_all", owner, 1)

                network.send_to_client(peer_id, "sync_local_profiles_reply")

    def idle(self):
        return not self._pending and not self._joining and not any(self._send_queues.values())

    def view(self):
        return {owner: profile["loadout"] for owner, profile in self._committed.items()}


# --------------------------------------------------------------------------
# Client: buffers chunks, acknowledges, applies when told
# --------------------------------------------------------------------------
class Client:
    def __init__(self, peer_id, account_id, network, backend):
        self.peer_id = peer_id
        self.account_id = account_id
        self._network = network
        self._backend = backend
        self._buffers = {}      # owner peer -> JSON received so far
        self.profiles = {}      # owner peer -> applied profile (what this game shows)
        self.joined = False

    def join(self):
        self._network.send_to_host(self.peer_id, "ready_to_receive_profiles")

    def equip(self, slot, item_id):
        """What the inventory screen does: ask the backend, then nudge the host."""
        if self._backend.equip(self.account_id, slot, item_id):
            self._network.send_to_host(self.peer_id, "notify_profile_changed", 1)

    # Overridden by the cheating clients below.
    def decode_profile(self, owner, profile_json):
        return json.loads(profile_json)

    def _on_start_profile_sync(self, owner, local_player_id):
        self._buffers[owner] = ""

    def _on_sync_player_profile_data(self, owner, local_player_id, chunk):
        self._buffers[owner] += chunk

    def _on_profile_sync_complete(self, sync_hash, owner, local_player_id):
        self._network.send_to_host(self.peer_id, "player_profile_synced", sync_hash)

    def _on_profile_synced_by_all(self, owner, local_player_id):
        self.profiles[owner] = self.decode_profile(owner, self._buffers[owner])

    def _on_sync_local_profiles_reply(self):
        self.joined = True
        log(self.peer_id, "join handshake finished")

    def update(self):
        queue = self._network.to_client[self.peer_id]

        while queue:
            name, args = queue.popleft()

            if valid_message(HOST_TO_CLIENT, name, args):
                getattr(self, "_on_" + name)(*args)

    def view(self):
        return {owner: profile["loadout"] for owner, profile in self.profiles.items()}


class LocalSwapClient(Client):
    """Edits its own incoming profile before applying it (a local visual swap)."""

    def __init__(self, *args, swaps):
        super().__init__(*args)
        self._swaps = swaps

    def decode_profile(self, owner, profile_json):
        profile = json.loads(profile_json)

        if owner == self.peer_id:
            for slot, item_id in self._swaps.items():
                log(self.peer_id, f"local swap: showing {item_id} instead of {profile['loadout'][slot]}")
                profile["loadout"][slot] = item_id

        return profile


class SmugglingClient(Client):
    """Tries to turn the nudge into a delivery vehicle for loadout data."""

    def smuggle(self, slot, item_id):
        log(self.peer_id, f"sending nudge with smuggled loadout {slot}={item_id}")
        self._network.send_to_host(self.peer_id, "notify_profile_changed", 1, {slot: item_id})


# --------------------------------------------------------------------------
# Scenario
# --------------------------------------------------------------------------
def run_until_idle(host, clients, max_ticks=200):
    for _ in range(max_ticks):
        host.update()

        for client in clients:
            client.update()

        network = host._network

        if host.idle() and not network.to_host and not any(network.to_client.values()):
            return

    raise RuntimeError("simulation did not settle")


def step(title):
    if not QUIET:
        print(f"\n== {title}")


def main():
    backend = Backend()
    network = Network()
    host = Host(network, backend)

    backend.create_character("acct-alice", "Alice", owned={"wooden_sword", "steel_sword", "plain_helmet"},
                             equipped={"weapon": "wooden_sword", "head": "plain_helmet"})
    backend.create_character("acct-bob", "Bob", owned={"wooden_sword", "plain_helmet"},
                             equipped={"weapon": "wooden_sword", "head": "plain_helmet"})
    backend.create_character("acct-carol", "Carol", owned={"wooden_sword", "plain_helmet"},
                             equipped={"weapon": "wooden_sword", "head": "plain_helmet"})

    alice = Client("alice", "acct-alice", network, backend)
    bob = LocalSwapClient("bob", "acct-bob", network, backend, swaps={"head": "golden_crown"})
    carol = SmugglingClient("carol", "acct-carol", network, backend)
    clients = [alice, bob, carol]
    checks = []

    def check(description, condition):
        checks.append((description, condition))

    step("1. Everyone joins")
    connected = []

    for client in clients:
        network.connect(client.peer_id)
        host.peer_connected(client.peer_id, client.account_id)
        connected.append(client)
        client.join()
        run_until_idle(host, connected)

    check("all three finished the join handshake", all(c.joined for c in clients))
    check("everyone sees Alice with the wooden sword",
          all(c.view()["alice"]["weapon"] == "wooden_sword" for c in clients))

    step("2. Alice equips an item she owns")
    alice.equip("weapon", "steel_sword")
    run_until_idle(host, clients)
    check("everyone now sees Alice with the steel sword",
          all(c.view()["alice"]["weapon"] == "steel_sword" for c in clients))

    step("3. Bob asks the backend for an item he does not own")
    bob.equip("weapon", "steel_sword")
    run_until_idle(host, clients)
    check("backend refused: everyone still sees Bob's wooden sword",
          all(c.view()["bob"]["weapon"] == "wooden_sword" for c in clients))

    step("4. Bob swaps his own incoming profile locally")
    # (Bob's swap has been active since he joined; this step just reports it.)
    check("Bob's own game shows the golden crown", bob.view()["bob"]["head"] == "golden_crown")
    check("Alice and Carol still see Bob's plain helmet",
          alice.view()["bob"]["head"] == "plain_helmet" and carol.view()["bob"]["head"] == "plain_helmet")
    check("the host still has Bob's plain helmet", host.view()["bob"]["head"] == "plain_helmet")

    step("5. Carol smuggles loadout data in the nudge")
    carol.smuggle("weapon", "steel_sword")
    run_until_idle(host, clients)
    check("host rejected the malformed message", len(host.rejected_messages) == 1)
    check("everyone still sees Carol's wooden sword",
          all(c.view()["carol"]["weapon"] == "wooden_sword" for c in clients))

    step("6. Two changes land back to back (resync path)")
    alice.equip("weapon", "wooden_sword")
    alice.equip("weapon", "steel_sword")
    run_until_idle(host, clients)
    check("everyone ends on Alice's latest choice (steel sword)",
          all(c.view()["alice"]["weapon"] == "steel_sword" for c in clients))

    print("\nFinal views (who sees what):")
    print(f"  {'viewer':<8} {'alice':<28} {'bob':<28} {'carol':<28}")

    for name, view in [("host", host.view())] + [(c.peer_id, c.view()) for c in clients]:
        cells = [f"{view[o]['weapon']} / {view[o]['head']}" for o in ("alice", "bob", "carol")]
        print(f"  {name:<8} {cells[0]:<28} {cells[1]:<28} {cells[2]:<28}")

    print("\nChecks:")
    failed = 0

    for description, condition in checks:
        print(f"  {'PASS' if condition else 'FAIL'}  {description}")
        failed += 0 if condition else 1

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
