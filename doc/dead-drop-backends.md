# Dead-drop backends

[← Back to overview](../README.md)

Every config has two drop sections: `[drop.admin]` is how this node writes the
directory (admin only); `[drop.client]` is how everyone reads it. Keeping them
separate means client nodes never see admin credentials, and admins can write
locally while clients pull from HTTP/CDN.

## S3-compatible object storage

```toml
[drop.admin]
type = "s3"
endpoint = "s3.amazonaws.com"   # or your MinIO/Backblaze/etc. host
region = "us-east-1"
bucket = "my-tincan-net"
object_key = "directory.bin"    # defaults to "directory.bin"
access_key = "..."              # admin's read+write key
secret_key = "..."
# tls = false                   # set to false for HTTP-only endpoints (e.g. local MinIO)

[drop.client]
type = "s3"
endpoint = "s3.amazonaws.com"
region = "us-east-1"
bucket = "my-tincan-net"
object_key = "directory.bin"
# access_key / secret_key — omit for anonymous read, or provision read-only keys
```

> Anonymous client reads work only if the object is already public. tincan does
> not manage bucket permissions — make the object public with your provider's own
> tooling (bucket policy / console), or give `[drop.client]` a read-only key.

## HTTP (read-only for clients)

```toml
[drop.admin]
type = "file"
path = "/var/www/tincan/directory.bin"   # admin writes the file; web server serves it

[drop.client]
type = "http"
url = "https://example.com/_vpn/directory.bin"
# username = "bob"
# password = "letmein"
```

The directory blob is encrypted regardless, but `username`/`password` (or
credentials embedded in the URL) are rejected over a cleartext `http://` URL
unless the host is loopback — use `https` so the drop credentials aren't
broadcast on every poll. A dead-drop is fetched directly; tincan refuses to
follow HTTP redirects.

HTTP is download-only — admins cannot `publish` to an HTTP drop. Combine a
file `[drop.admin]` (written into a web root) with an HTTP `[drop.client]` so
clients fetch through a CDN or static host.

## Local filesystem

```toml
[drop.admin]
type = "file"
path = "/mnt/shared/tincan/directory.bin"

[drop.client]
type = "file"
path = "/mnt/shared/tincan/directory.bin"
```

Useful for testing or when every node mounts a shared filesystem (NFS, SMB,
Syncthing, etc.).

## DNS TXT records

The directory can live in a DNS zone you control as a set of TXT records.
Clients read it with an ordinary DNS lookup — **no credentials and no provider
account** — which makes this the lightest-weight backend for client nodes. Only
the admin needs provider credentials, used to write the records.

```toml
[drop.admin]
type = "dns"
provider = "digitalocean"     # or "linode", "cloudflare", "desec", "hetzner", "route53"
zone = "example.com"          # a DNS zone hosted at the provider
record_name = "_tincan"       # host label the TXT records live at (default "_tincan")
api_token = "..."             # provider API token with DNS write access
# ttl = 300                   # optional record TTL in seconds

[drop.client]
type = "dns"
zone = "example.com"
record_name = "_tincan"
# resolver = "1.1.1.1"        # optional: query this resolver (host[:port]) instead of the system one
```

Clients never set a `provider` or any write credentials — they just resolve
`<record_name>.<zone>`. A `[drop.admin]` without a provider is read-only (like
`http`), so admins must configure a provider to `publish`.

Supported providers and how they authenticate:

- **`linode`, `digitalocean`, `cloudflare`, `desec`, `hetzner`** — a single
  `api_token` (shown above), scoped to DNS write access. For Cloudflare, create
  an API token with the Zone:Read and DNS:Edit permissions on the zone. deSEC
  uses your account API token and enforces a minimum TTL (3600s by default), so
  tincan defaults `ttl` to 3600 when it is unset. For Hetzner, create a token on
  the DNS Console's API-tokens page (`https://dns.hetzner.com/settings/api-token`).
- **`ovh`** — OVH signs each request with three application credentials and a
  regional endpoint rather than a bearer token:

  ```toml
  [drop.admin]
  type = "dns"
  provider = "ovh"
  endpoint = "ovh-eu"        # OVH API region: ovh-eu (default), ovh-ca, ovh-us
  zone = "example.com"
  record_name = "_tincan"
  app_key = "..."
  app_secret = "..."
  consumer_key = "..."
  # ttl = 300
  ```

  Create the keys at OVH's token page (e.g. `https://eu.api.ovh.com/createToken/`)
  and grant the consumer key `GET`/`POST`/`PUT`/`DELETE` on `/domain/zone/*`.
  The `[drop.client]` side is identical to the example above (no credentials).
- **`route53`** — Amazon Route 53 signs each request with AWS Signature Version 4
  using an access key id and secret access key (the same `access_key`/`secret_key`
  fields as the S3 backend) rather than a bearer token:

  ```toml
  [drop.admin]
  type = "dns"
  provider = "route53"
  zone = "example.com"
  record_name = "_tincan"
  access_key = "AKIA..."
  secret_key = "..."
  # ttl = 300
  ```

  The IAM credentials need permission to look up the zone and change its records:
  `route53:ListHostedZonesByName`, `route53:ListResourceRecordSets`, and
  `route53:ChangeResourceRecordSets` on the hosted zone. Route 53 is a global
  service, so tincan always talks to the standard endpoint (no region setting).
  The `[drop.client]` side is identical to the example above (no credentials).

The zone must already be hosted at the provider — tincan writes records into it
but does not create the zone.

The sealed directory is base64-encoded and split across multiple TXT records
(each ≤255 bytes), tagged so clients reassemble them in order and ignore any
unrelated TXT records at the same name. Publishing is not atomic: during DNS
propagation a client that reads a half-updated set fails to reassemble or verify
it, keeps its cached directory, and picks up the change on the next sync — so a
short `ttl` is worthwhile. A directory needing more than ~100 records (≈16 KB, a
large network) is rejected; use S3 or HTTP for that.

## Nostr relays

The directory can live as a [Nostr](https://nostr.com) event on one or more
relays. Clients read it with **just the admin's public key and a relay list — no
account and no credentials** — the same low-friction read story as the DNS
backend, with the added benefit that publishing to several independent relays
makes the drop decentralized and hard to censor.

`tincan init --drop-type nostr` generates the Nostr keypair for you and fills it
in; you normally only edit the relay list.

```toml
[drop.admin]
type = "nostr"
relays = ["wss://relay.damus.io", "wss://nos.lol"]   # publish to all of these
author = "npub1..."        # the admin's Nostr public key (npub or 64-char hex)
nsec = "nsec1..."          # the admin's secret key (nsec or hex) — admin only
# identifier = "_tincan"   # NIP-33 d-tag naming the slot (default "_tincan")

[drop.client]
type = "nostr"
relays = ["wss://relay.damus.io", "wss://nos.lol"]
author = "npub1..."        # same public key; clients pin it to verify the slot
# identifier = "_tincan"
```

Clients never set `nsec` — they only read events from `author` and verify them.
A `[drop.admin]` without an `nsec` is read-only (like `http`), so the admin needs
the secret key to `publish`.

How it works: the sealed directory is published as a NIP-78 replaceable event
(kind 30078) tagged with the `identifier`; relays keep only the latest event per
key, so it acts as a single mutable slot. Reads query every relay, verify each
event's author, kind, tag, id, and signature, and take the newest valid one — so
an untrusted or hostile relay cannot substitute a forged or stale directory.
A write succeeds as long as one relay accepts the event.

The Nostr key only controls **who may write the relay slot**. The directory blob
is independently age-encrypted and Ed25519-signed by the publisher key, and
rollback is caught by its monotonic serial — so even a leaked `nsec` cannot forge
a directory, only withhold or replay one (mitigated by listing several relays and
republishing on a cadence; see `max_directory_age` in the
[configuration reference](configuration.md)). Most relays cap event size
near 64 KB — ample for a directory, but smaller than the `s3`/`http` ceiling — so
very large networks should pick relays with generous limits. See
[Nostr backend design](../spec/nostr.md) for the full design.
