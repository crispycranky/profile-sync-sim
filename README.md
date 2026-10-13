# Profile-sync simulation

A standalone model of a **server-authoritative profile/loadout sync** for a
multiplayer game, built to understand and stress-test the design — not to attack
any live service. It reproduces the shape of Warhammer 40,000: Darktide's
profile synchronisation and then runs an attack suite proving a malicious client
cannot change what the host or other players see.

Everything here runs in one process with in-memory queues. There are no sockets,
no connection to any game, and no connection to any backend.

## Files

| File | What it is |
|------|------------|
| `sim.py`  | First, teaching-level model. Backend + host + 3 clients, scripted demo with a readable log. |
| `sim2.py` | Closer-to-real model: 5-state sync tracking, multiple local players per peer, asynchronous backend, latency, one-time sync tokens, strict message validation, plus the copied/best-practice defenses and a 23-check attack, robustness, defense and fidelity suite. |
| `FINDINGS.md` | Short summary of what was confirmed, what was only inferred, and the design rules worth copying. |
| `README.md` | This file. |

## Running

```
python sim.py            # scripted demo + checks
python sim.py --quiet    # just the checks and final views
python sim2.py           # attack + robustness + defense + fidelity suite (23 checks)
python sim2.py --verbose # same, with the full event log
```

Python 3.8+. No third-party packages.

## The design in one paragraph

A profile (name, class, loadout of item IDs) lives only in the **backend**, the
one source of truth. A **client** never sends its loadout. To change gear it
asks the backend to equip an item it owns, then sends the **host** a contentless
"my profile changed" nudge carrying only a local-player slot number. The host
maps that slot to an account using its *own* authenticated connection record,
fetches the profile from the backend, splits the JSON into fixed-size chunks,
and streams them to every client with a one-time token per transfer. Each client
buffers the chunks, acknowledges with the token, and applies the new profile only
when the host says every client has it. Because the client only ever says
"something changed" and never "here is what I have", there is nothing for it to
forge.

## Provenance — what is copied vs. invented

The protocol shape and several defenses were read from a public mirror of
Darktide's **Lua** source
([github.com/Aussiemon/Darktide-Source-Code](https://github.com/Aussiemon/Darktide-Source-Code)).
That mirror is Lua only; it does **not** contain the backend services, the
dedicated-server half of the handshake, the compiled `.network` wire-type
definitions, or the native C++ engine. So anything that lives in those places
could not be copied and is either modelled from first principles (and labelled)
or left as a recommendation.

Source files consulted (verified against the running game's class/method list):

- `scripts/loading/profile_synchronizer_host.lua`
- `scripts/loading/profile_synchronizer_client.lua`
- `scripts/utilities/profile_utils.lua`
- `scripts/utilities/rpc_queue.lua`
- `scripts/multiplayer/connection/local_states/local_profiles_sync_state.lua`

### Faithfully reproduced from the Lua source

| Mechanism | Real source | Where in the sim |
|-----------|-------------|------------------|
| Nudge carries only `local_player_id`, no loadout | `ProfileSynchronizerHost.rpc_notify_profile_changed` | `Client.equip` / `_on_notify_profile_changed` |
| Host derives identity from the authenticated peer, not the packet | `profile_changed` → `Managers.player:player(peer_id, local_player_id)` | `Host._profile_changed` maps `peer_id`→account |
| Profile always fetched from the backend | `_profile_changed` → `fetch_account_character` | `Host._profile_changed` → `Backend.fetch` |
| Change gate refuses nudges in disallowed states | `Managers.mechanism:profile_changes_are_allowed()` | `Host.changes_allowed` |
| start / data-chunks / complete transfer framing | `sync_player_profile` | `Host._send_profile` |
| JSON split into fixed-size chunks | `ProfileUtils.split_for_network`, `max_string_length = 400` | `CHUNK_SIZE = 400` |
| One-time sync token per (receiver, owner) transfer | `Application.make_hash(...)`, consumed in `rpc_player_profile_synced` | `Host._send_profile` / `_on_player_profile_synced` |
| 5-state sync tracking incl. need-resync | `SYNC_STATES` enum, `_update_sync_states` | `NOT_SYNCED … SYNCED`, `_send_profile` |
| Apply-to-all only after everyone acks | `update` → `rpc_profile_synced_by_all` | `Host.tick` commit loop |
| Outbound flow control: 1000-slot ring buffer, N-per-send, stop under buffer pressure | `RPCQueue` (`REMAINING_BUFFER_SIZE_MINIMUM = 8000`, `Network.reliable_send_buffer_left`) | Constants `QUEUE_CAPACITY`, `SEND_BUFFER_MIN`, `RPCS_PER_TICK` (see "known simplifications") |

### Modelled from first principles (NOT copied — labelled in code)

- **Ownership / equip validation** (`Backend.equip`). The readable
  client-side check `_validate_profile_from_backend_data` only confirms the
  archetype exists — it is **not** an ownership check. Real ownership and
  slot-legality validation runs on Fatshark's backend servers, which are not in
  the source. The sim's version is a reasonable stand-in, written here, not theirs.
- **Deserializer guard** (`safe_decode`: `MAX_PROFILE_BYTES`, `MAX_JSON_DEPTH`).
  Best practice. Darktide's equivalent size/type limits live in the compiled
  `.network` wire definitions, which the mirror does not contain, so this is not
  a copy.
- **Nudge coalescing** (`Host._inflight`). One backend fetch in flight per
  player. This matches the *intent* of the real in-flight/resync bookkeeping but
  is a simplified construction, not a line-for-line port.
- **The network layer** (`Network`): latency and in-order channel delivery are a
  toy model to exercise timing, not the real transport.

### Not represented at all (out of scope / unreadable)

- Transport encryption and per-message authentication (native engine).
- Native packet parsing and bounds-checking of lengths/counts (C++ engine) —
  the deepest real attack surface.
- The dedicated-server side of the join handshake (not shipped).
- The full profile shape: talents, voice, per-item overrides, separate instance
  vs. catalogue IDs, visual-loadout reconstruction.

## What the attack suite demonstrates

Every attack is **expected to be contained**. A test that showed an attack
*succeeding* against the host or other players would mean a design bug to fix.

| Attack | Expected outcome |
|--------|------------------|
| Equip an item you don't own | Backend refuses; nobody sees it |
| Edit your own incoming profile | Shows on your screen only; host + others unchanged |
| Stuff loadout data into the nudge | Rejected as malformed |
| Nudge claiming another player's slot | Rejected (identity from the connection) |
| Forge or replay an acknowledgement token | Rejected (one-time tokens) |
| Rewrite chunks arriving at your own client | Local-only, same as an edit |
| Change gate locked, then equip | Refused |
| Flood 50 nudges | Coalesced to one fetch; state stays consistent |
| Oversized / over-deep profile | Rejected by the guard; no crash |

Plus robustness: convergence on the latest loadout under timing jitter, and a
clean disconnect mid-fetch.

## Takeaways for your own game

1. The client sends a **dataless nudge**; it never asserts what it owns.
2. The server maps the connection to an **account from its own record**, never
   from a packet field.
3. The **truth always comes from the backend**, and ownership is validated
   **server-side** on every equip (and ideally re-validated on use).
4. New state is applied **only after every client acknowledges**.
5. **Guard the deserializer** (size + depth + schema) before trusting any
   profile, and **rate-limit / coalesce** inbound nudges.
6. The design is the easy part. A serious attacker goes for the **parser, the
   validator, the identity mapping, and the native packet code** — the places
   where attacker data meets an assumption. Encrypt and authenticate the
   transport, and fuzz the native handlers.

## Validated against live traffic

On 2026-10-07 a read-only probe (Lua hooks on the client's profile-sync
handlers that log and then call the original — nothing sent, dropped, or
altered; the probe itself is not part of this repository) captured 1602
real profile-sync events in the Mourningstar hub, as a normal client
(`is_host=false`). Observed, and now matched by the sim:

| Property | Live capture | Sim |
|----------|--------------|-----|
| Framing | 45 `start` → chunks → 45 `complete` | start → chunks → complete |
| Chunk size | 1553 chunks at exactly 400 B | `CHUNK_SIZE = 400` |
| Trailing remainder | exactly 45 sub-400 chunks (one per profile) | one remainder per profile |
| Ack granularity | 45 `complete` = one token per profile | one ack per profile |
| Apply signal | 5 `synced_by_all` (one per committed player) | commit-then-broadcast per owner |
| Host handlers on a client | zero fired | host logic runs only on the host |
| Loadout data inbound in a nudge | none ever observed | nudge is dataless |
| Profile size | 6.3-17.4 KB, median ~15.7 KB (~16-44 chunks) | `fidelity` tests exercise this |

The one correction the capture forced: the original tests used tiny,
single-chunk profiles, so the multi-chunk path and the trailing remainder were
never actually run. The `fidelity:` checks now split a ~16 KB profile and send a
60-slot loadout end to end, confirming reassembly matches the live shape. The
`MAX_PROFILE_BYTES = 64 KB` guard sits safely above the 17.4 KB largest real
profile seen.

Caveat: the probe only sees messages that reach *your* client. It confirms the
client half and that no loadout-bearing message arrives from the server, but it
cannot inspect the dedicated server's own handlers (those never run on a client).

## Known simplifications

- Most scenario profiles are tiny and fit in one 400-byte chunk; only the
  `fidelity:` checks push a realistic ~16 KB multi-chunk profile through.
- The RPCQueue constants are documented, but backpressure is not wired into the
  toy network (it has no real send buffer).
- One process, in-memory queues: no real sockets, packet loss, or encryption.

## Provenance note

The Darktide Lua source was read from a public third-party mirror for study.
It remains the property of its owner; none of it is copied verbatim into the
simulation, which is an independent re-implementation of the *pattern*.
