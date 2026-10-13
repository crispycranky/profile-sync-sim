# Findings: Darktide's client-side profile sync

A summary of a read-only study: the Darktide client Lua was read from a public
mirror, the running client was observed live with read-only LuaExec hooks, and
the design was reproduced and stress-tested in `sim2.py`. Nothing was sent to,
forged against, or altered on any Fatshark service. See `README.md` for the
full provenance and the live-capture table.

## Confirmed (from client source + live capture)

- **The server is authoritative for loadouts.** A client never sends what it is
  wearing. It sends a dataless nudge (`rpc_notify_profile_changed`) carrying
  only a local player-slot number.
- **The host maps that nudge to an account from its own connection record**, not
  from anything in the packet — a client cannot claim another player's identity.
- **The profile always comes from the backend.** On a nudge the host fetches the
  character fresh (`fetch_account_character`) and distributes that.
- **Distribution is a fixed handshake:** `start` -> ~40 chunks of 400 bytes (one
  sub-400 remainder per profile) -> `complete` with a one-time token -> client
  acks with that token -> host broadcasts `synced_by_all` -> everyone applies at
  once. Watched live: 45 profiles, 1553 full 400 B chunks, one ack per profile.
- **Real profiles are ~16 KB** (6.3-17.4 KB observed).
- **Host logic never runs on a client** (`is_host=false` throughout the
  capture), and no loadout-bearing message ever arrives inbound.
- **Equips go to an authenticated REST backend** (`PUT characters/<id>/
  inventory/<slot>`), with the account identity taken from the login token
  (`account.sub`), not a free parameter.

## Inferred, NOT seen (server-side code is not readable)

- The ownership / slot-legality check lives inside that backend endpoint. It was
  never observed; the sim's `Backend.equip` is a stand-in written by us, not
  Fatshark's code. This check is the real root of the whole security model.

## Consequences we proved out (sim: 23 checks pass)

- Editing a profile as it arrives, stuffing data into the nudge, claiming another
  player's slot, or replaying an ack token all change nothing the host or other
  players see — only your own screen.
- Packet capture would not reveal more: backend traffic is TLS, and even
  decrypted it shows requests, not the server's decision logic.

## Big-picture lesson

- **Anti-cheat (EAC) protects client integrity; server authority protects the
  truth.** They are different jobs.
- Server authority is **the developer's responsibility**, not the anti-cheat
  vendor's. No anti-cheat product knows your game's rules, so it cannot decide
  who may own what.
- If a cheat changes **what is true** (items, currency, unlocks, stats) that is a
  server-authority problem the developer can design out of existence. If a cheat
  changes **how well the client plays** (aim, vision, automation) that is a
  detection problem anti-cheat can only make harder.
- Fatshark's design removes the item/entitlement spoofing class by construction:
  the client only requests, the server decides. That is the pattern to copy.

## Design rules worth copying

1. The client sends a **dataless nudge**; it never asserts what it owns.
2. The server maps the connection to an **account from its own record**, never a
   packet field.
3. The **truth comes from the backend**, and ownership is validated
   **server-side** on every change (ideally re-validated on use).
4. New state is applied **only after every client acknowledges**.
5. **Guard the deserializer** (size + depth + schema) and **rate-limit / coalesce**
   inbound nudges.
6. The protocol is the easy part. A serious attacker targets the parser, the
   validator, the identity mapping, and the native packet code — encrypt and
   authenticate the transport, validate server-side, and fuzz the handlers.
