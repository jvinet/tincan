Tincan is a simple mesh-VPN system built on Wireguard.

## What is it?

Tincan lets you easily enroll Linux computers into a mesh-based VPN network
running Wireguard. Unlike regular `wg-quick` Wireguard, Tincan helps LAN peers
discover each other, has smart relay fallback for nodes buried behind NAT, and
has simple DNS resolution.

It also tolerates plain-Wireguard nodes, so any device with a Wireguard app can
participate. These nodes do not benefit from all of Tincan's higher-level
features, but they can still hang out.

## Who Might Like Tincan?

- If you want something more put-together than plain `wg-quick`, but much less
  put-together than Tailscale/Nebaula/Netbird.
- If you want a _bit_ of coordination, but don't want to rely on a server
  someone else controls.
- If you prefer to keep things as simple as you can, but no simpler.
- If wg-quick mostly works, but it's getting onerous having to manually update
  every node in your network each time you add a new one.

## What Does Tincan Look Like?

Tincan tries to make a typical setup easy.

Start with an admin node. It's an admin because it has write access to the network directory, which is the central thing replacing a control plane.

### The Quickest of Starts

```sh
[root@alice ~]# tincan init --name alice --dns-domain=tc --drop-type s3 --endpoint 123.123.123.123:51820
# Configure the real bucket and credentials in /etc/tincan/config.toml:
# [drop.admin] for admin reads/writes; [drop.client] for client reads.
[root@alice ~]# tincan publish
[root@alice ~]# tincan up --daemon
[root@alice ~]# tincan add-node --name bob --bootstrap bob.json
```

_(hand `bob.json` to Bob)_

```sh
[root@bob ~]# tincan join --bootstrap bob.json
[root@bob ~]# tincan up --daemon
```

### The Full Thing

This includes the actual output (or similar).

#### Admin

Initialize a new network.

```sh
$ bin/tincan init --name alice --dns-domain=tc --drop-type s3 --endpoint 123.123.123.123:51820
✓ initialized admin node "alice"

Paths
  config:            /etc/tincan/config.toml
  state directory:   /var/lib/tincan
  network bootstrap: /var/lib/tincan/netboot.json

Tunnel
  allocated IP: 10.42.0.1
  VPN domain:   tc

WireGuard keypair
  public key:  FCxyEN0Bv/asBs7DLMIoWFZalIrJBvF31BRGWjkkTBI=
  private key: OHr/LalVnJo4Mjcyv0tNvE+Bw69SmIwJWx3C6lDJxHQ= [secret]

Node identity (age)
  identity:  AGE-SECRET-KEY-1YUJ8U4X4TLU3UB708NK8D2JRH9FAJAQGKJY0GYTZ434KJRYR626SGL7542 [secret]
  recipient: age126w8j2q37l2lnsuhwx608qhsywrce9cz4k80pasjgn0r0keq4qdqt93xz4

Publisher keypair
  public key:  Z1aea75ENiT9AH+ixfX1MbqbPGvEgrJOrBJbF0ulsBY=
  private key: 3c5Cc+XeWbwvFxXz3MTNLz5LROJ4fhPx49jj1x9nuw5nVp5rvkQ2JP0Af63F9fUxups8a8SCsk6sElsXS6WwFg== [secret]

Next steps: edit the [drop.admin] and [drop.client] sections, then run `tincan publish`
This admin observes NAT'd peer endpoints by default; set [observe].enabled = false to turn it off
```

Edit `[drop.admin]` and `[drop.client]` in `/etc/tincan/config.toml` with your
actual backend coordinates and credentials, then publish and fire it up.

```sh
$ tincan publish
$ tincan up --daemon
```

Now add another node.

```sh
$ bin/tincan add-node --name bob --bootstrap bob.json
✓ added node "bob"

Assignment
  allocated IP: 10.42.0.2
  public key:   YeZ/zZvMuBQc9XcGRJj4WuIxf5D26HBnoJLyO9Zdz10=

Bootstrap
  file: /home/jvinet/tincan/bob.json

! the bootstrap file contains the node's WireGuard private key and age identity; transmit it over a secure channel
```

Now, get that `bob.json` over to Bob. Careful, it's got secrets in it.

#### Client

Over on Bob's machine, he runs:

```sh
$ bin/tincan --config /tmp/tincan.toml join --bootstrap bob.json  --state-dir /tmp/tincan
✓ initialized client node "bob"

Paths
  config: /tmp/tincan.toml

WireGuard
  public key: YeZ/zZvMuBQc9XcGRJj4WuIxf5D26HBnoJLyO9Zdz10=

Next steps: run `tincan up`
Firewall: allow inbound UDP 51821 (LAN discovery beacons) so same-LAN peers can be found
WireGuard will bind a random port; set [wireguard].listen_port and allow it through the firewall so peers can connect directly
```
