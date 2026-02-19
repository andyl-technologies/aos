# Network Architecture

> Part of the [Nix Daemon Isolation Architecture](README.md)

Two systemd-nspawn containers -- fetch-proxy and nix-daemon -- are connected by
a point-to-point veth pair over a /30 subnet. The fetch-proxy container has
internet access via a macvlan interface on the host's internet-facing NIC. The
nix-daemon container has no host network interfaces at all; its only route to
the outside world is through the proxy.

## 3.1 Network Topology

```
fetch-proxy container                   nix-daemon container
┌──────────────────────┐               ┌───────────────────────┐
│ mv-eth0 (macvlan)    │               │ --private-network     │
│  internet access     │               │  no host interface    │
│                      │               │                       │
│ veth-proxy:          │               │ veth-nixd:            │
│  172.30.0.1/30       ├───────────────┤  172.30.0.2/30        │
│                      │   veth pair   │  gw: 172.30.0.1       │
│ squid :3128          │               │  dns: 172.30.0.1      │
│ dnsmasq :53          │               │                       │
└──────────────────────┘               └───────────────────────┘
```

The nix-daemon container sees exactly one network interface (`veth-nixd`) with
exactly one default route (172.30.0.1). All DNS queries go to dnsmasq on the
proxy. All HTTP/HTTPS fetches go through Squid on the proxy. There is no path
from the nix-daemon container to the host network or any other interface.

## 3.2 Why Manual veth, Not `--network-zone=`

systemd-nspawn's `--network-zone=` option creates a shared bridge and gives
every container in that zone NAT access to the host network. This is the
opposite of what we want:

| `--network-zone=` | Manual veth pair |
|--------------------|------------------|
| Creates a shared bridge with NAT | Point-to-point link, no bridge |
| Both containers get outbound internet | Only fetch-proxy gets internet |
| Implicit routing through host stack | Explicit single route to proxy |
| Cannot restrict which container reaches the internet | nix-daemon has exactly ONE interface with ONE route |

A point-to-point veth pair requires no bridge for a two-endpoint link. The
nix-daemon container starts with `--private-network` (an empty network
namespace with only `lo`), and the veth endpoint is injected after the
container is running. This gives us complete control over what the daemon
can reach.

## 3.3 macvlan for Multi-Homed Servers

AOS build servers are typically multi-homed: `eth0` faces the internet (for
fetching source tarballs) and `eth1` faces the intranet (for serving the
binary cache to internal clients). The daemon isolation design ensures that
neither container can reach the intranet.

The fetch-proxy container uses `--network-macvlan=eth0` to create a virtual
interface (`mv-eth0`) on the internet-facing NIC only:

- macvlan creates a new MAC address on `eth0`, giving the proxy a real IP on
  the `eth0` segment (via DHCP or static assignment)
- The intranet NIC (`eth1`) is never passed to either container -- it exists
  only in the host namespace
- Host-level nftables rules (see section 3.6) drop any container traffic that
  attempts to reach `eth1`, as a defense-in-depth measure

**Alternative**: `--network-veth` with host-side NAT is simpler to configure
but adds NAT overhead and requires `iptables`/`nftables` MASQUERADE rules on
the host. macvlan avoids this indirection entirely -- the proxy speaks directly
on the `eth0` segment.

## 3.4 IP Addressing

Static addressing on a minimal /30 subnet:

| Interface | Container | Address | Role |
|-----------|-----------|---------|------|
| `veth-proxy` | fetch-proxy | 172.30.0.1/30 | Proxy endpoint, default gateway for nix-daemon |
| `veth-nixd` | nix-daemon | 172.30.0.2/30 | Daemon endpoint |
| `mv-eth0` | fetch-proxy | DHCP or static on eth0 segment | Internet access |

The 172.30.0.0/30 subnet provides exactly two usable host addresses
(172.30.0.1 and 172.30.0.2). There is no need for DHCP on the veth link --
both endpoints are statically configured and there will never be more than
two participants.

The 172.30.0.0/12 range is chosen from RFC 1918 private space to avoid
conflicts with typical corporate intranet ranges (10.0.0.0/8, 192.168.0.0/16).

## 3.5 systemd-networkd Configuration

Both containers run systemd-networkd to manage interface configuration. The
`.network` files are baked into each container's rootfs at image build time.

### nix-daemon container

```ini
# /etc/systemd/network/10-veth-nixd.network
[Match]
Name=veth-nixd

[Network]
Address=172.30.0.2/30
Gateway=172.30.0.1
DNS=172.30.0.1

[Link]
RequiredForOnline=yes
```

The `RequiredForOnline=yes` directive ensures that `systemd-networkd-wait-online`
blocks until `veth-nixd` has an address and a route. The nix-daemon service is
ordered after `network-online.target`, so it will not start until the veth link
is up and configured.

### fetch-proxy container

```ini
# /etc/systemd/network/10-veth-proxy.network
[Match]
Name=veth-proxy

[Network]
Address=172.30.0.1/30
IPForward=yes
```

`IPForward=yes` enables IP forwarding on the veth interface, allowing the proxy
container to route traffic between the veth link and the macvlan interface.

```ini
# /etc/systemd/network/10-mv-eth0.network
[Match]
Name=mv-eth0

[Network]
DHCP=yes
# Or for static:
# Address=203.0.113.10/24
# Gateway=203.0.113.1
# DNS=1.1.1.1
```

The macvlan interface acquires its address via DHCP on the `eth0` segment (or
static assignment, depending on the site). This is the proxy's path to the
internet for source fetches.

## 3.6 nftables Rules

Firewall rules enforce the network isolation invariants at multiple levels. Each
container has its own ruleset, and the host has rules protecting the intranet
interface.

### nix-daemon container

The daemon container allows only proxy and DNS traffic to the fetch-proxy, and
nothing else:

```
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow loopback
        iif "lo" accept

        # Allow established/related return traffic on veth
        iif "veth-nixd" ct state established,related accept
    }

    chain output {
        type filter hook output priority 0; policy drop;

        # Allow loopback
        oif "lo" accept

        # Allow Squid proxy traffic to fetch-proxy
        oif "veth-nixd" ip daddr 172.30.0.1 tcp dport 3128 accept

        # Allow DNS to fetch-proxy (dnsmasq)
        oif "veth-nixd" ip daddr 172.30.0.1 tcp dport 53 accept
        oif "veth-nixd" ip daddr 172.30.0.1 udp dport 53 accept
    }
}
```

This means the nix-daemon process can only open connections to three
destinations: Squid on port 3128, and dnsmasq on port 53 (TCP and UDP). Any
attempt to connect to any other address or port is dropped.

### fetch-proxy container

The proxy container accepts traffic from the veth link and makes outbound
connections to the internet. It does not forward any traffic.

```
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept

        # Accept proxy connections from nix-daemon
        iif "veth-proxy" ip saddr 172.30.0.2 tcp dport 3128 accept

        # Accept DNS queries from nix-daemon
        iif "veth-proxy" ip saddr 172.30.0.2 tcp dport 53 accept
        iif "veth-proxy" ip saddr 172.30.0.2 udp dport 53 accept

        # Allow return traffic from internet
        iif "mv-eth0" ct state established,related accept
    }

    chain output {
        type filter hook output priority 0; policy drop;

        oif "lo" accept

        # Allow HTTP/HTTPS to internet (source fetches)
        oif "mv-eth0" tcp dport { 80, 443 } accept

        # Allow DNS to upstream resolvers
        oif "mv-eth0" tcp dport 53 accept
        oif "mv-eth0" udp dport 53 accept

        # Allow replies to nix-daemon
        oif "veth-proxy" ct state established,related accept
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        # No forwarding -- proxy is an application-layer gateway
    }
}
```

The forward chain drops everything. The proxy is an application-layer gateway
(Squid), not a network-layer router. Traffic from the nix-daemon is terminated
at the Squid process, which makes a separate outbound connection to the origin
server. This means the nix-daemon cannot reach any internet host directly --
Squid's domain ACLs (see [04-forward-proxy.md](04-forward-proxy.md)) are always
in the path.

### Host

The host's nftables rules protect the intranet interface and govern traffic
between the containers:

```
table inet container-isolation {
    chain forward {
        type filter hook forward priority 0; policy accept;

        # DENY: no container traffic to intranet (eth1)
        oif "eth1" drop

        # ALLOW: fetch-proxy to internet on permitted ports
        iif "mv-eth0" oif "eth0" tcp dport { 80, 443, 53 } accept
        iif "mv-eth0" oif "eth0" udp dport 53 accept

        # ALLOW: return traffic from internet to fetch-proxy
        iif "eth0" oif "mv-eth0" ct state established,related accept

        # ALLOW: traffic on the veth pair (already restricted by container rules)
        iif "veth-*" oif "veth-*" accept
    }
}
```

The critical rule is the first one: any packet with `oif "eth1"` is dropped
unconditionally. Even if a container is somehow misconfigured, it cannot reach
the intranet.

## 3.7 Startup Ordering

Container startup follows a two-phase sequence to avoid circular dependencies.
The nix-daemon cannot start fetching until the proxy is reachable, and the veth
link must be created after both containers have running network namespaces.

### Sequence

1. **Start fetch-proxy** with `--network-macvlan=eth0 --private-network`
2. **Start nix-daemon** with `--private-network`
3. **Host-side script** creates the veth pair and injects each endpoint into
   the correct container's network namespace
4. **systemd-networkd** inside each container detects the new interface via
   udev/netlink and applies the `.network` configuration
5. **nix-daemon container**: `systemd-networkd-wait-online` blocks until
   `veth-nixd` is routable (has address + default route)
6. **nix-daemon service** starts after `network-online.target`

### systemd unit dependencies

```ini
# /etc/systemd/system/nix-daemon-container.service
[Unit]
Description=Nix daemon container (isolated)
After=fetch-proxy.service container-network-setup.service
Requires=fetch-proxy.service

[Service]
ExecStart=systemd-nspawn --machine=nix-daemon --private-network ...
```

```ini
# /etc/systemd/system/container-network-setup.service
[Unit]
Description=Create veth pair between fetch-proxy and nix-daemon containers
After=fetch-proxy.service nix-daemon-container.service
Requires=fetch-proxy.service nix-daemon-container.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/container-network-setup.sh
```

The `container-network-setup.service` is a oneshot that runs after both
containers are up. It creates the veth pair and moves each end into the
correct namespace. `RemainAfterExit=yes` keeps systemd from re-running it
on every dependency check.

**Note**: the nix-daemon container starts with `--private-network` (empty
network namespace) and has no connectivity until the veth pair is injected.
This is intentional -- the daemon's services are ordered after
`network-online.target`, which will not be reached until `veth-nixd` is
configured by systemd-networkd.

## 3.8 Interface Injection

The host-side `container-network-setup.sh` script creates the veth pair and
moves each endpoint into the correct container's network namespace:

```bash
#!/bin/sh
# container-network-setup.sh -- create veth pair between containers
# Runs on the host after both containers have started.

set -eu

# Get the leader PID of each container (the PID 1 inside the container,
# as seen from the host's PID namespace)
PROXY_PID=$(machinectl show fetch-proxy -p Leader --value)
NIXD_PID=$(machinectl show nix-daemon -p Leader --value)

# Create the veth pair in the host namespace
ip link add veth-nixd type veth peer name veth-proxy

# Move each end into the respective container's network namespace
ip link set veth-nixd netns "$NIXD_PID"
ip link set veth-proxy netns "$PROXY_PID"

# Bring up interfaces inside each container.
# systemd-networkd will apply the .network files and configure addresses,
# but the link must be up for networkd to act on it.
nsenter -t "$PROXY_PID" -n -- ip link set veth-proxy up
nsenter -t "$NIXD_PID" -n -- ip link set veth-nixd up
```

**Why `nsenter` instead of letting systemd-networkd handle link-up?**
systemd-networkd applies `.network` files when a matching interface appears,
but it only configures interfaces that are in the `UP` state. Moving a veth
endpoint into a namespace creates it in the `DOWN` state, so we explicitly
bring it up with `ip link set ... up` before networkd takes over with address
and route configuration.

**Alternative approach**: instead of relying on `nsenter` for link-up only and
letting networkd handle addressing, the script can do full manual configuration:

```bash
# Full manual configuration (alternative to systemd-networkd)
nsenter -t "$PROXY_PID" -n -- ip addr add 172.30.0.1/30 dev veth-proxy
nsenter -t "$PROXY_PID" -n -- ip link set veth-proxy up

nsenter -t "$NIXD_PID" -n -- ip addr add 172.30.0.2/30 dev veth-nixd
nsenter -t "$NIXD_PID" -n -- ip link set veth-nixd up
nsenter -t "$NIXD_PID" -n -- ip route add default via 172.30.0.1
```

The systemd-networkd approach is preferred because it integrates with
`systemd-networkd-wait-online` and provides a consistent configuration model
across all interfaces in each container.

## 3.9 Failure Modes

| Failure | Effect on nix-daemon | Recovery |
|---------|---------------------|----------|
| Proxy crash (Squid exits) | `builtin:fetchurl` gets `ECONNREFUSED` from 172.30.0.1:3128 | Nix retries per `connect-timeout` and `download-attempts` in nix.conf. systemd restarts Squid (`Restart=on-failure`). |
| Proxy overloaded | Slow responses, potential `ETIMEDOUT` | `stalled-download-timeout` in nix.conf triggers retry. Squid's `cache_peer` load balancing not needed (single instance). |
| veth link down | All network access fails immediately | `container-network-setup.service` is `RemainAfterExit=yes`; systemd will not re-run it automatically. Manual intervention or a health-check timer that re-creates the veth pair. |
| macvlan interface down | Proxy cannot reach the internet; DNS fails | dnsmasq returns SERVFAIL. Squid returns 503. Nix daemon sees fetch failures and retries. |
| DNS resolution failure | `builtin:fetchurl` cannot resolve hostnames | dnsmasq on fetch-proxy returns NXDOMAIN or SERVFAIL. Nix retries the fetch. |
| Host eth0 down | Same as macvlan down -- no internet path | Nix daemon retries; builds using cached sources still succeed. |

### Health check

A simple TCP connectivity test validates the data path end-to-end:

```bash
# Run inside nix-daemon container (or via nsenter from host)
# Attempt to connect to the proxy port -- success means the full path works:
#   veth-nixd -> veth-proxy -> squid process
exec 3<>/dev/tcp/172.30.0.1/3128 && echo "OK" || echo "FAIL"
exec 3>&-
```

For a more thorough check, issue an HTTP request through the proxy:

```bash
# Test that the proxy can reach the internet and DNS resolves
http_proxy=http://172.30.0.1:3128 \
  curl -s -o /dev/null -w '%{http_code}' http://cache.nixos.org/nix-cache-info
# Expected: 200
```

## 3.10 nix.conf Timeout Settings

The nix daemon inside the container is configured with generous timeouts and
retry counts to handle transient proxy failures gracefully:

```ini
# /etc/nix/nix.conf (inside nix-daemon container)

# Connection timeout to the proxy (seconds)
connect-timeout = 30

# Number of retry attempts for each download
download-attempts = 5

# Kill a download if no data received for this many seconds
stalled-download-timeout = 300

# Use HTTP/2 multiplexing (reduces connection overhead through the proxy)
http2 = true

# Allow fallback to other substituters if one fails
fallback = true

# Proxy configuration (libcurl reads these from the environment, but
# they can also be set explicitly here for clarity)
# Note: these are set via the systemd unit's Environment= directive,
# not in nix.conf. See 02-container-isolation.md for the unit file.
```

The `connect-timeout = 30` value is deliberately high because the proxy may
need time to establish its own outbound connection (DNS resolution + TCP
handshake + TLS negotiation to the origin server). The default of 5 seconds
is too aggressive for a proxied setup.

`download-attempts = 5` with exponential backoff means a transient proxy
restart (which takes ~2 seconds under systemd `Restart=on-failure`) will be
transparent to the build. The daemon retries the fetch and the build continues.

`stalled-download-timeout = 300` (5 minutes) accommodates large source
tarballs (e.g., LLVM at ~120 MB) over slow upstream mirrors. If no data
arrives for 5 minutes, the download is considered stalled and retried.

`http2 = true` enables HTTP/2 multiplexing, which is beneficial when fetching
through a proxy: multiple concurrent fetches can share a single TCP connection
to the proxy, reducing connection setup overhead on the veth link.
