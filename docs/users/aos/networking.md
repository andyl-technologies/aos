# Configure networking

AOS uses systemd-networkd for links and addresses and systemd-resolved for
name resolution. Networking is release-time image policy in the current early
preview. Runtime `host.nix` understands these options but does not activate
them yet. The examples below document the active policy and are for release
maintainers; see
[Build and customize release images](../../maintainers/system-images.md).

Keep console access while changing static addressing. An incorrect interface
name, gateway, VLAN, or bond can make an otherwise healthy image unreachable.

## Use DHCP

With no explicit interfaces, the default policy enables DHCP on Ethernet
interfaces whose names begin with `en`:

```nix
{
  aos.networking = {
    hostName = "api-01";
    useDHCP = true;
  };
}
```

The default match intentionally does not include every possible kernel name.
If the target presents `eth0`, or if a specific interface must use DHCP,
declare it explicitly:

```nix
{
  aos.networking.interfaces.eth0 = {};
}
```

An explicit interface with an empty address uses DHCP. Once any interface is
declared, the catch-all `en*` DHCP unit is not generated; declare every link
that AOS should configure.

## Configure a static address

Use the predictable interface name reported by the target platform:

```nix
{
  aos.networking = {
    hostName = "api-01";
    useDHCP = false;
    nameservers = ["10.0.0.53" "10.0.0.54"];
    search = ["prod.example.com"];

    interfaces.ens3 = {
      address = "10.0.0.20/24";
      gateway = "10.0.0.1";
      dns = "10.0.0.53";
    };
  };
}
```

Each interface accepts one address, one gateway, and one per-link DNS server.
The current high-level module does not model multiple addresses, policy
routing, or explicit route tables. Use a reviewed raw networkd unit through
`environment.etc` only when the generated interface is insufficient, and
avoid defining two units that match the same link.

Release maintainers should inspect the generated networkd and resolved files
in the evaluated system closure before publishing an image.

## Configure DNS

Global resolvers and search domains are written to `resolved.conf`.
DNS-over-TLS is opportunistic, multicast DNS and LLMNR are disabled, and the
default DNSSEC mode is `allow-downgrade`.

Require DNSSEC only when every deployment network supports it:

```nix
{
  aos.networking = {
    nameservers = ["9.9.9.9" "149.112.112.112"];
    resolved.dnssec = "yes";
  };
}
```

The accepted DNSSEC values are `yes`, `no`, and `allow-downgrade`. Disabling
systemd-resolved removes the generated service enablement and configuration;
the deployment must then provide a complete resolver path itself.

## Know the advanced-networking boundary

The module declares `mtu`, `vlans`, and `bonds`, but those options are not a
complete production interface today:

- `aos.networking.mtu` is not rendered into a link or network unit;
- VLAN netdevs are created, but the parent link is not told to attach them;
- bond netdevs are created, but member interfaces are not enslaved to them;
- VLAN and bond address models omit gateways and per-link DNS.

Do not rely on those options for production connectivity until their rendered
networkd topology and VM coverage are completed. If a deployment must use one
of these layouts now, provide the complete `.netdev` and `.network` files as
build-time configuration and test the exact image on representative hardware.

## Tune network sysctls carefully

The `tuning` map writes a sysctl drop-in:

```nix
{
  aos.networking.tuning = {
    "net.core.somaxconn" = "4096";
    "net.ipv4.tcp_syncookies" = "1";
  };
}
```

Do not copy a generic tuning list into every host. Record the workload or
threat model for each override and verify that the active value matches:

```sh
systemd-sysctl --cat-config
sysctl net.core.somaxconn
sysctl net.ipv4.tcp_syncookies
```

## Diagnose a running host

Start with the rendered policy and networkd's view:

```sh
networkctl list
networkctl status
ip -brief link
ip -brief address
ip route
resolvectl status
systemctl status systemd-networkd.service systemd-resolved.service
journalctl -b -u systemd-networkd.service -u systemd-resolved.service
```

Compare the observed interface name with the system variant. If a static unit
matches no link, correct the variant and rebuild the image; runtime
`host.nix` does not currently activate general network changes.
