# Tincan — Nostr Dead-Drop

## Context

A tincan dead-drop is an untrusted, shared byte store: the admin publishes one
sealed directory blob, every node fetches and decrypts it, and there is no
control plane. The existing backends (`file`, `http`, `s3`, `dns`) all reduce to
"a place to PUT and GET one small blob."

Nostr is a natural fit and adds properties the others lack:

- **Decentralized / censorship-resistant.** Publish to N independent relays;
  reads survive any subset going down, blocking, or pruning.
- **No account or provider API.** A reader needs only a public key and a relay
  URL — like the `dns` drop reading a zone with a plain lookup. There is nothing
  to sign up for, and many relays are free and public.
- **Uniform protocol.** Every relay speaks the same WebSocket/JSON protocol, so —
  unlike the `dns` drop, which needs a per-host provider abstraction — a single
  backend talks to all relays.

## Decisions (locked in)

- **Slot = NIP-78 parameterized-replaceable event, kind `30078`.** Relays keep
  only the latest event per `(pubkey, kind, d-tag)` tuple, which is exactly a
  single mutable slot. Kind `30078` ("application-specific data") plus a
  `["d", <identifier>]` tag (default `_tincan`) namespaces the slot, so one admin
  key can host multiple networks. The kind is a fixed constant, like the `dns`
  drop's `tc1` record prefix; the identifier is configurable.
  - A *regular* kind would make relays keep every historical directory forever.
  - A plain *replaceable* kind (10000–19999) has no `d` tag, so it gives exactly
    one slot per key, shared with any other app using that kind. Rejected.
- **Content = `base64(sealed blob)`.** The Nostr `content` field is a JSON
  string; the sealed directory is binary (age ciphertext), so it is base64
  (`StdEncoding`, the Nostr-ecosystem default) inside `content`. No chunking is
  needed — a directory is a few KB and a single event holds it (contrast the
  `dns` drop, forced to chunk by the 255-byte TXT limit).
- **No second layer of encryption.** The blob is already age-encrypted and
  ed25519-signed by the directory layer. NIP-04/44 would add nothing and would
  break the "drop sees only opaque bytes" boundary. The drop is content-agnostic,
  exactly like `file`/`s3`/`http`/`dns`.
- **A separate secp256k1 key.** Nostr signs with BIP-340 schnorr over secp256k1,
  a different curve than the directory's ed25519 publisher key. The admin
  therefore has a Nostr keypair *in addition to* the publisher keypair. `tincan
  init --drop-type nostr` generates it automatically so the operator never
  hand-crafts an nsec.
- **Keys accept npub/nsec or hex.** Operators paste the bech32 forms they get
  from Nostr clients; 64-char hex is also accepted. Canonical hex is stored
  internally. NIP-19 bech32 (bare entities only) is hand-rolled — no dependency.

## Trust model (why two keys is fine)

The Nostr signature authorizes **who may write the relay slot**. It is *not* what
makes the directory trustworthy. Authenticity and freshness are unchanged from
every other backend:

- The blob is **age-encrypted** to each node's recipient and **ed25519-signed**
  by the publisher key (`directory.Seal`). A relay — or anyone with the nsec —
  cannot forge directory contents; a forged or substituted blob fails `Open`.
- **Rollback** is caught by the directory's monotonic `Serial`
  (`directory.IsRollback`), which sits above the drop. Relay `created_at` is *not*
  trusted as a freshness signal — and cannot be forged anyway, since the admin
  signs it.

So the worst a hostile or compromised relay (or a leaked nsec) can do is withhold
or replay — handled by publishing to multiple relays, the serial guard, and the
optional `max_directory_age` staleness warning. This is worth stating loudly
because operators will otherwise conflate the Nostr key with the publisher key.

## Wire format

A published event:

```json
{
  "kind": 30078,
  "created_at": 1700000000,
  "tags": [["d", "_tincan"]],
  "content": "<base64(sealed directory blob)>",
  "pubkey": "<admin x-only pubkey, hex>",
  "id":  "<sha256 of the NIP-01 serialization>",
  "sig": "<BIP-340 schnorr signature, hex>"
}
```

The `id` is `sha256` of the canonical NIP-01 serialization
`[0,pubkey,created_at,kind,tags,content]` — compact JSON with NIP-01's exact
escape set (`\b \t \n \f \r \" \\`, other control chars as `\uXXXX`, everything
else literal UTF-8). This is hand-rolled rather than delegated to `encoding/json`,
which escapes `\b`/`\f` as ``/`` and HTML-escapes `< > &`; diverging
by one byte produces a different `id` than every other implementation and the
event is rejected as invalid. A byte-exact serialization test is the interop gate.

## Read: the verification gauntlet

Relays are untrusted and need not honor the `authors`/`#d` filter, so the drop
re-checks everything (the analog of the `dns` drop ignoring foreign TXT records).
`Get` queries all relays concurrently and, for every returned event, requires:

1. `pubkey == configured author`,
2. `kind == 30078`,
3. d-tag `== identifier`,
4. `id == sha256(serialization)`,
5. valid schnorr signature.

Among survivors it selects the newest by `created_at`, breaking ties on the
lowest `id` (NIP-01) so every client deterministically picks the same event.

`Get` distinguishes two empty outcomes: **no valid event but at least one relay
answered** → `ErrNotFound` (treated as "no directory yet"); **every relay errored**
→ a joined transport error (so sync keeps its cached directory instead of
discarding it). One dead relay never blocks the others.

## Write: multi-relay publish

`Put` signs the event once and publishes it to all relays concurrently. It
succeeds if **at least one** relay returns `OK,true` — a dead drop is durable as
long as one relay holds the event, and readers merge across all of them. If every
relay rejects, `Put` returns a joined error naming each relay's reason (size
limit, `auth-required`, `rate-limited`, …). Without an nsec the drop is read-only
and `Put` returns `ErrReadOnly`, like the `http` and `dns` backends.

## Operational notes

- **Auto-generated key.** `tincan init --drop-type nostr` mints the keypair and
  fills `[drop.admin].nsec` + `.author` and `[drop.client].author`. The client
  config (and the bootstrap derived from it) carries the npub and relays but never
  the nsec.
- **Republish cadence.** As with any drop, a withholding relay or stalled admin
  can serve a still-valid directory forever; pair a cron'd `tincan publish` with
  `[sync].max_directory_age` (≈ two cadences) to notice a freeze.
- **`ws://` is allowed.** Unlike the `http` drop (which rejects cleartext when it
  would leak credentials), no secret travels in a relay URL — the nsec stays
  local and the blob is already encrypted. `ws://` leaks only metadata (which
  author/network is active), so it is permitted.
- **Pick ≥3 reliable relays** for durability; relays prune and go offline.

## Limitations

- **Relay size caps.** Many relays reject events whose `content` exceeds ~64 KB;
  a few cap lower. Directories are normally a few KB, so this rarely bites, but
  very large networks should prefer relays with generous limits. The hard read
  ceiling stays `directory.MaxBlobSize` (4 MiB).
- **Weak-quorum writes.** "≥1 relay accepted" can lose the slot if that single
  relay prunes aggressively; list several relays and republish on a cadence.
- **Metadata exposure.** The author pubkey and d-tag are visible to relays and
  observers; only the directory *contents* are confidential (age).

## Module layout

- `internal/nostr/` — protocol primitives, no dependency on `config` or `drop`:
  - `event.go` — NIP-01 `Event`, canonical `Serialize`/`ComputeID`/`Verify`.
  - `key.go` — schnorr sign, key parse (hex/bech32), `GenerateKey`.
  - `bech32.go` — minimal NIP-19 bech32 codec for `npub`/`nsec`.
  - `relay.go` — `Filter`, the `Conn`/`Dialer` transport seam, and the
    `coder/websocket` implementation. Injecting `Dialer` lets tests run with a
    fake relay (mirroring the `dns` drop's `lookupFunc`).
- `internal/drop/nostr.go` — the `Drop` implementation (`Get`/`Put`/`Stat`/`Name`,
  `NewNostr`). Takes scalar args, not a `config.DropBackend`, so `config` can
  import `nostr` for key validation without an import cycle.
- Config: `Relays`/`Author`/`Nsec`/`Identifier` on `config.DropBackend`; a
  `nostr` case in `validateDropBackend` (relay-URL + key-format + author/nsec
  pairing checks) and `SkeletonDrop`; the d-tag default in `applyBackendDefaults`.
- CLI: `nostr` in the `init`/`join` `--drop-type` enums, with keypair generation
  in `init`.
