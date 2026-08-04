# Customize AOS

AOS currently has two active configuration paths and one incomplete path. Pick
the path based on when the setting must take effect.

| Configuration source | Use it for | Current behavior |
| --- | --- | --- |
| System module under `systems/` | Hostname, networking, SSH, users, services, firewall, packages baked into the image | Evaluated at build time and active in the resulting image |
| Metadata `host.nix` under `aos.provisioning.storage` | First-boot partition layout | Applied once, then frozen |
| Other metadata `host.nix` settings | Future runtime configuration | Evaluated to `/run/aos/manifest.json`, but not activated end to end |

For now, build every setting needed to reach and operate the host into a system
variant. Do not rely on metadata to install SSH keys or bring up custom runtime
services.

## Create a system variant

Files under `systems/` are discovered automatically. A file named
`systems/acme-server.nix` produces image outputs such as
`acme-server-image-qcow2` and an evaluated system at
`systems.acme-server`.

```nix
# systems/acme-server.nix
{...}: {
  imports = [./server.nix];

  aos.networking.hostName = "web-01";

  aos.networking.interfaces.eth0 = {
    address = "10.0.0.20/24";
    gateway = "10.0.0.1";
    dns = "10.0.0.53";
  };

  aos.services.ssh = {
    enable = true;
    port = 2222;
  };

  environment.etc."ssh/authorized_keys/root" = {
    text = "ssh-ed25519 AAAA_REPLACE_ME ops@example.com\n";
    mode = "0600";
  };

  aos.users.groups.myapp = {
    gid = 500;
    members = [];
  };

  aos.users.users.myapp = {
    uid = 500;
    group = "myapp";
    home = "/var/lib/myapp";
    shell = "/sbin/nologin";
    description = "My application";
    extraGroups = [];
  };

  aos.firewall.allowedTCP = [443];
}
```

Interface names are deployment-specific. The image default enables DHCP on
Ethernet interfaces matching `en*` when no explicit interface is declared.

Build the system closure before producing an image:

```sh
nix-build -A systems.acme-server.build.toplevel
nix build .#acme-server-image-qcow2
```

The flake source contains tracked files. If the new variant is not yet tracked,
use `nix-build` while iterating, or add it to the deployment branch before
using the flake output.

System modules are ordinary source inputs. Keep deployment policy in version
control, review it like code, and keep secret material elsewhere. Public SSH
keys may be baked into an image; private keys and service credentials should
not be.

## Compose deployment modules

Keep shared policy in an underscore-prefixed module so automatic system
discovery does not publish it as a standalone image:

```nix
# systems/_acme-common.nix
{pkgs, ...}: {
  aos.system = {
    locale = "C.UTF-8";
    timezone = "UTC";
  };

  aos.roles.server.enable = true;

  environment.systemPackages = [
    pkgs.curl
    pkgs.jq
  ];

  aos.firewall = {
    enable = true;
    defaultPolicy = "drop";
  };
}
```

Import it into concrete variants:

```nix
# systems/acme-edge.nix
{...}: {
  imports = [
    ./server.nix
    ./_acme-common.nix
  ];

  aos.networking.hostName = "edge-01";
}
```

The module system merges contributions from every imported module. Use
`lib.mkDefault` in reusable modules when a concrete system should be able to
override a value without conflict.

## Configure network identity

The default network policy uses DHCP on Ethernet interfaces matching `en*`.
Set only a hostname to retain DHCP:

```nix
{
  aos.networking.hostName = "api-01";
}
```

For a static interface:

```nix
{
  aos.networking = {
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

Confirm the target's predictable interface name before committing a static
configuration. A wrong name can leave the installed image unreachable.

## Configure SSH access

SSH uses key authentication by default and reads system-wide authorized keys
from `/etc/ssh/authorized_keys/%u`.

```nix
{
  aos.services.ssh = {
    enable = true;
    port = 22;
    permitRootLogin = "prohibit-password";
    passwordAuthentication = false;
    kbdInteractiveAuthentication = false;
  };

  environment.etc."ssh/authorized_keys/root" = {
    text = ''
      ssh-ed25519 AAAA_FIRST_PUBLIC_KEY ops-1@example.com
      ssh-ed25519 AAAA_SECOND_PUBLIC_KEY ops-2@example.com
    '';
    mode = "0600";
  };
}
```

The SSH module adds its configured port to the firewall. Keep the key file in
the image until runtime cloud-key activation is implemented; cloud metadata
keys are currently recorded as facts but are not installed.

For a non-root operator account, declare both the group and user, then write the
matching authorized-key file:

```nix
{pkgs, ...}: {
  aos.users.groups.operator = {
    gid = 1000;
    members = ["operator"];
  };

  aos.users.users.operator = {
    uid = 1000;
    group = "operator";
    home = "/var/lib/operator";
    shell = "${pkgs.bash}/bin/bash";
    description = "Host operator";
    extraGroups = ["adm"];
  };

  environment.etc."ssh/authorized_keys/operator" = {
    text = "ssh-ed25519 AAAA_REPLACE_ME operator@example.com\n";
    mode = "0600";
  };
}
```

Declaring an account does not create mutable home-directory contents. Keep
system service state under `/var/lib` and arrange application initialization
through its systemd unit.

## Add files under `/etc`

Use `environment.etc` rather than modifying the image in an imperative build
step:

```nix
{
  environment.etc."acme/agent.conf" = {
    text = ''
      endpoint=https://control.example.com
      log_level=info
    '';
    mode = "0644";
  };
}
```

An entry can also use a Nix `source` path. Inline `text` and `source` are
alternatives; do not set both. Configuration embedded this way is readable to
the Nix build and belongs in the immutable system closure, so it is not a
secret-delivery mechanism.

## Add system packages and services

`environment.systemPackages` puts tools in the base system profile and its
default `PATH`:

```nix
{pkgs, ...}: {
  environment.systemPackages = [
    pkgs.curl
    pkgs.jq
    pkgs.rsync
  ];
}
```

For an application service, reference the AOS-built package by store path and
declare the unit's ordering, restart policy, identity, and state directory:

```nix
{pkgs, ...}: {
  aos.users.groups.acme-agent = {
    gid = 501;
    members = [];
  };

  aos.users.users.acme-agent = {
    uid = 501;
    group = "acme-agent";
    home = "/var/lib/acme-agent";
    shell = "/sbin/nologin";
    description = "Acme host agent";
    extraGroups = [];
  };

  systemd.services.acme-agent = {
    description = "Acme host agent";
    wantedBy = ["multi-user.target"];
    after = ["network-online.target"];
    wants = ["network-online.target"];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.acme-agent}/bin/acme-agent --config /etc/acme/agent.conf";
      Restart = "on-failure";
      RestartSec = "5s";
      User = "acme-agent";
      Group = "acme-agent";
      StateDirectory = "acme-agent";
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
    };
  };
}
```

`pkgs.acme-agent` is a placeholder for a package defined in `pkgs/`. The
package must be added to the hermetic AOS package graph before this example can
evaluate.

When the repository already provides a typed service module, prefer that
module to a hand-written unit. For example, a native Hub host can enable:

```nix
{
  aos.registry-hub = {
    enable = true;
    listen = "127.0.0.1:8420";
    externalUrl = "https://hub.example.com";
  };
}
```

The [native AOS Hub guide](../aos-hub/native.md) covers its service-specific
storage and deployment requirements.

## Seed registries and trust

Registries required on first boot can be built into the image with their trust
anchors:

Replace the public-key placeholder before evaluating the variant. Its value is
the base64 field from the registry's Ed25519 OpenSSH public key.

```nix
{
  aos.apm.registries.acme = {
    url = "https://packages.example.com/";
    priority = 10;
    trustKeys = [
      "acme:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAA_REPLACE_ME"
    ];
  };
}
```

This writes the read-only seed under `/etc/apm`. Runtime registry changes use
the writable `/var/lib/apm/config` overlay. See [Manage packages](packages.md)
for the layering and trust model.

## Inspect and validate a variant

Use the generated reference to browse option names and types:

```sh
aos doc
```

Evaluate the complete closure before building a disk image:

```sh
nix-instantiate --eval --strict \
  -A systems.acme-server.config.aos.networking.hostName
nix-build -A systems.acme-server.build.toplevel
nix build .#acme-server-image-qcow2
```

Boot the exact image in a staging environment and check at least:

```sh
systemctl is-system-running
systemctl --failed
systemctl status sshd.service
systemctl status nftables.service
cat /etc/hostname
cat /etc/ssh/sshd_config
cat /etc/nftables.conf
```

Some administration binaries are deliberately not placed on the base `PATH`.
If a check is part of your operating procedure, add the relevant AOS package to
`environment.systemPackages` in the variant.

## Configure first-boot storage

A metadata-provided `host.nix` can change the closed
`aos.provisioning.storage.partitions` schema. The image supplies two defaults:

```text
swap  fixed 2 GiB, formatted as swap
var   minimum 4 GiB, grows into remaining free space
```

This example reduces swap, raises the `/var` minimum, and creates a fixed data
partition on the boot disk:

```nix
{
  aos.provisioning.storage.partitions = {
    swap = {
      sizeMin = "1G";
      sizeMax = "1G";
    };

    var.sizeMin = "8G";

    data = {
      label = "data";
      type = "linux-generic";
      sizeMin = "20G";
      sizeMax = "20G";
      format = "ext4";
      priority = 1000;
    };
  };
}
```

For an additional disk, set `device` to a stable identifier:

```nix
{
  aos.provisioning.storage.partitions.data = {
    device = "/dev/disk/by-id/virtio-aos-data";
    label = "data";
    sizeMin = "20G";
    sizeMax = "20G";
    format = "ext4";
  };
}
```

Explicit devices must use `/dev/disk/by-id/...`. AOS preflights every target
device before it mutates any of them.

Partition fields are:

| Field | Meaning |
| --- | --- |
| `device` | Stable target device, or `null` for the disk containing `root-a` |
| `label` | GPT partition label; defaults to the attribute name |
| `type` | `linux-generic`, `swap`, or an allowed raw GPT type GUID |
| `sizeMin` | Positive integer with optional uppercase `K`, `M`, `G`, `T`, or `P` suffix |
| `sizeMax` | Optional maximum; `null` is unbounded |
| `weight` | Relative share of unallocated space |
| `format` | `ext4`, `vfat`, `swap`, or `null` |
| `uuid` | Optional deterministic partition UUID |
| `grow` | Whether the partition consumes remaining space |
| `growFs` | Whether an existing filesystem may be grown |
| `priority` | Deterministic placement order |

The complete plan is committed on the first successful provisioning boot.
Subsequent boots compare the requested plan with the recorded plan and report
differences as drift. AOS does not currently expose a factory-reset command or
an automatic recovery command for an interrupted provisioning marker. Reimage
the host when its committed storage layout must change.

See [Understand and operate `host.nix`](host-nix.md) for delivery channels,
signed input, the boot lifecycle, additional storage recipes, drift behavior,
and the files used to inspect the accepted plan.

## Understand runtime `host.nix`

At boot, AOS can evaluate a delivered `host.nix` with the image's module
library and emit `/run/aos/manifest.json`. That evaluator understands settings
such as hostname, networking, users, services, SSH policy, and
`aos.apm.desiredPackages`.

The current boot graph does not materialize and atomically activate that
manifest as a live generation. In practical terms:

- hostname and network changes in metadata are not made live;
- users, groups, and authorized keys are not installed from metadata;
- service changes are not applied to systemd;
- package selection may affect evaluation, but is not a complete runtime
  package activation path.

`apm switch` is also not a replacement for `nixos-rebuild switch`; its live
activation path is incomplete. Use system variants for running configuration
and use [`apm install --system --from`](packages.md#manage-machine-wide-packages)
for implemented runtime package reconciliation.

## Inspect configuration results

On a running host:

```sh
systemctl status aos-eval.service
journalctl -b -u aos-eval.service
test -s /run/aos/manifest.json && echo "host input evaluated"

cat /var/lib/aos-provisioning/audit.json
if test -r /run/aos-metadata/storage-coherence; then
  cat /run/aos-metadata/storage-coherence
fi
```

An evaluated manifest proves that parsing and module evaluation succeeded. It
does not prove that the resulting settings became active.
