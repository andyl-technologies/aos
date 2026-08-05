# Configure an AOS host

AOS is intended to take machine-specific policy from `host.nix`, without
requiring each user to build a private system image. That interface is only
partly active in the current early preview.

| Configuration path | Use it for | Current behavior |
| --- | --- | --- |
| Metadata `host.nix` under `aos.provisioning.storage` | First-boot partition layout | Applied once, then checked for drift |
| Other metadata `host.nix` settings | Hostname, networking, users, access, services, and desired packages | Evaluated to `/run/aos/manifest.json`, but not activated end to end |
| `apm` | User packages and implemented machine-wide package reconciliation | Active at runtime |
| System modules in the source tree | Golden-image and release policy | Maintainer workflow, evaluated when the image is built |

The image must currently include the network and access policy needed to reach
the host. Do not rely on `host.nix` to create users, install SSH keys, or start
custom services until runtime activation is complete.

## Configure first-boot storage

Deliver `host.nix` through a supported metadata transport. This example keeps
swap at 1 GiB, requires at least 8 GiB for `/var`, and creates a fixed data
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

For an additional disk, identify the target by a stable `/dev/disk/by-id/...`
path:

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

AOS preflights every target before changing any disk. The accepted plan is
committed on the first successful provisioning boot. Later changes are
reported as drift rather than applied automatically.

The [`host.nix` guide](host-nix.md) documents every storage field, metadata
delivery, signatures, multi-disk layouts, first-boot state, drift, and
recovery. Read it before deploying a storage policy.

## Install packages at runtime

Use `apm` instead of baking ordinary tools into a private image:

```sh
apm search curl
apm install curl jq
apm list --installed
```

Machine-wide package sets can be reconciled from a reviewed desired-state
file with `apm install --system --from`. See [Manage packages](packages.md) for
registry trust, user and system scopes, upgrades, and rollback.

## Understand runtime `host.nix`

The current evaluator understands settings such as hostname, networking,
users, services, SSH policy, and `aos.apm.desiredPackages`. It writes the result
to `/run/aos/manifest.json`, but the boot graph does not yet materialize and
atomically activate that result as a live system generation. In practice:

- hostname and network changes from metadata do not become live;
- users, groups, and authorized keys are not installed from metadata;
- service changes are not applied to systemd;
- desired packages in the evaluated manifest are not a complete activation
  path.

`apm switch` is not a replacement for a full host-configuration switch; that
live activation path is also incomplete.

## Inspect configuration state

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
does not prove that the settings became active.

Release maintainers who need to change the golden image should use
[Build and customize release images](../../maintainers/system-images.md).
