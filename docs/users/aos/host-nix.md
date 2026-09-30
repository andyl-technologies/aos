# Understand and operate `host.nix`

`host.nix` is the machine-owned Nix module delivered at boot. It is separate
from the system variant used to build the image:

- the system variant defines what is present and active in the immutable image;
- `host.nix` carries deployment-time intent for one machine;
- instance facts describe what the platform reports about that machine.

AOS applies the `aos.provisioning.storage` projection during first boot, then
evaluates and activates the complete module during stage 2. Storage intent is
committed once; the stage-2 result is a replaceable, numbered configuration
generation.

## Start with the supported form

Use a self-contained literal Nix module:

```nix
{
  aos.provisioning.storage.partitions.var.sizeMin = "8G";
}
```

The file is not JSON, YAML, TOML, or cloud-config. AOS imports the exact bytes
as a Nix module. Keep it self-contained: a relative import from a deployment
checkout will not exist in the initrd or on the target host.

The function form is also a valid module, but the argument set is image-owned
and should not be used as an escape hatch to the build package graph. For
portable provisioning input, prefer a plain attribute set.

## Follow the boot lifecycle

The same `host.nix` bytes pass through two deliberately separate evaluations:

```text
metadata transport
  -> detect platform or config drive
  -> fetch exact user-data and facts
  -> authorize host.nix
  -> restricted initrd evaluation of aos.provisioning
  -> validate and commit the first-boot storage plan
  -> switch_root
  -> pure stage-2 evaluation and provider fixpoint
  -> authenticated package closure fetch and config render
  -> resolve opaque secretRef handles
  -> build a durable EROFS /etc lower
  -> atomically activate the configuration generation
```

The initrd evaluation can see only the closed provisioning schema shipped in
the image. It cannot fetch registry modules or select arbitrary build packages.
This is the path that runs before disk mutation.

The stage-2 evaluator is a pure function of the image's ABI-pinned module
library, authenticated package `config` outputs, the exact accepted `host.nix`,
and normalized instance facts. It runs with a cleared environment, restricted
filesystem access, no import-from-derivation, and bounded systemd resources.
The resolver fetches only signed providers compatible with the running module
ABI. It records its provider trace and emits `/run/aos/manifest.json` only after
the fixpoint converges.

The systemd graph then fetches pinned package closures, validates and stages
each package's signed configuration projection, and drops a failed soft package
from the projected manifest. Activation resolves credential handles before
consumers restart, materializes `gen-N/config-lower/etc.erofs`, atomically
switches the configuration pointer and `/etc`, and publishes an activation
record. A failed evaluation or pre-swap activation retains the previous live
generation; a post-swap service failure is recorded as degraded and remains
retriable.

## Choose a delivery channel

Offline media is checked before DMI-based cloud detection.

| Channel | Where AOS reads the module | Signature location |
| --- | --- | --- |
| AOS metadata drive, label `aos-metadata` | `/host.nix` | `/host.nix.sig` |
| NoCloud drive, label `cidata` | `/user-data` | `/user-data.sig` |
| OpenStack config drive, label `config-2` | `/openstack/latest/user_data` | `/openstack/latest/user_data.sig` |
| QEMU `fw_cfg` | `opt/org.andyl/host-nix` | `opt/org.andyl/host-nix.sig` |
| AWS | Native user-data as literal Nix or a pointer document | Pointer `sig_url` only |
| GCP, Azure, DigitalOcean, OpenStack | Native user-data as literal Nix | Not available through native metadata |

The native network metadata agents support AWS IMDSv2, GCP, Azure,
DigitalOcean, and OpenStack. Other providers are treated as bare metal unless
an offline metadata or config drive is attached; AOS does not guess at an
unrecorded provider API.

Create an AOS metadata ISO with `xorriso` on the deployment workstation:

```sh
mkdir -p metadata
cp host.nix metadata/host.nix
xorriso -as mkisofs \
  -V aos-metadata \
  -o metadata.iso \
  metadata
```

For QEMU, pass the literal file directly:

```sh
-fw_cfg name=opt/org.andyl/host-nix,file=host.nix
```

AWS user-data can contain a strict JSON pointer document when the module is too
large for the inline limit:

```json
{
  "host_nix_url": "https://config.example/hosts/web-01.nix",
  "sha256": "LOWERCASE_HEX_SHA256",
  "sig_url": "https://config.example/hosts/web-01.nix.sig"
}
```

The SHA-256 value pins the fetched bytes. In signed mode, the detached
signature independently authenticates those exact bytes. Other native cloud
fetchers treat all user-data as literal `host.nix` and do not carry a detached
signature. Use an offline config drive when those platforms require signed
provisioning.

## Choose the trust policy

The image owns the trust decision.

### Platform trust

`aos.config.evalAtBoot.trust = "platform"` is the default. It treats control of
the selected metadata channel as authority to supply the machine's input. This
fits cloud deployments where instance user-data is already protected by the
control plane.

Offline media in platform mode is trusted because it wins metadata detection.
Protect attachment and replacement of that media as a privileged deployment
operation.

### Signed trust

Use signed mode when the metadata transport is not itself sufficient authority.
Bake dedicated operator keys into the system variant:

Replace the public-key placeholder before evaluating the variant. Its value is
the base64 field from the dedicated Ed25519 OpenSSH public key.

```nix
{...}: {
  imports = [./server.nix];

  aos.config.evalAtBoot.trust = "signed";
  aos.apm.configKeys.ops = [
    "ops:Ed25519:AAAAC3NzaC1lZDI1NTE5AAAA_REPLACE_WITH_PUBLIC_KEY"
  ];
}
```

The value after `Ed25519:` is the base64 key field from a dedicated Ed25519
OpenSSH public key. The `ops` prefix must match the attribute name. Multiple
entries allow key-rotation overlap.

Sign the exact file in the `aos-config` SSHSIG namespace:

```sh
ssh-keygen -Y sign -f /secure/path/aos-config-ed25519 -n aos-config host.nix
```

OpenSSH writes the armored detached signature to `host.nix.sig`. Transport both
files without changing `host.nix`; whitespace changes after signing invalidate
the signature.

When first boot receives a `host.nix`, signed mode fails closed if the image has
no matching trust key, the signature is missing, or verification fails. With no
operator input, AOS still provisions the image's fallback storage defaults.
After a host has been successfully provisioned, an unavailable or unauthorized
new input is ignored and the previous active configuration is retained.

## Use the storage schema

Two partitions exist in the default intent:

| Name | Default |
| --- | --- |
| `swap` | Fixed 2 GiB, swap type and format |
| `var` | 4 GiB minimum, grows into remaining space |

Partitions are the only layer most hosts need. Hosts with more than one disk
can additionally bind partitions into MD arrays and, on a measured-boot image,
seal any ext4 volume to the TPM; those layers are described below.

`device = null` selects the disk containing `root-a`. Every explicit device
must use a stable `/dev/disk/by-id/...` path.

### Increase `/var` and keep default swap

```nix
{
  aos.provisioning.storage.partitions.var.sizeMin = "32G";
}
```

Size the target with room for the immutable image, 2 GiB swap, and at least 32
GiB of `/var`.

### Set a fixed swap size

```nix
{
  aos.provisioning.storage.partitions.swap = {
    sizeMin = "8G";
    sizeMax = "8G";
  };
}
```

A partition with `grow = false` is fixed at `sizeMin` when `sizeMax` is omitted
or `null`. Set `grow = true` to consume remaining space; only one grow partition
is allowed per device.

### Add a fixed partition to the boot disk

```nix
{
  aos.provisioning.storage.partitions.backup = {
    label = "backup";
    type = "linux-generic";
    sizeMin = "50G";
    sizeMax = "50G";
    format = "ext4";
    priority = 1000;
  };
}
```

The partition is created and formatted. Declaring it does not itself create a
mount unit; describe mount policy separately in the general host configuration
or the release image.

### Consume remaining space with a data partition

Only one unbounded grow-to-fill partition should own the remaining space on a
device. Disable growth on `/var` before assigning it elsewhere:

```nix
{
  aos.provisioning.storage.partitions = {
    var = {
      sizeMin = "8G";
      sizeMax = "8G";
      grow = false;
    };

    data = {
      label = "data";
      sizeMin = "20G";
      sizeMax = null;
      format = "ext4";
      grow = true;
      weight = 2000;
      priority = 9000;
    };
  };
}
```

### Provision a separate data disk

```nix
{
  aos.provisioning.storage.partitions.data = {
    device = "/dev/disk/by-id/wwn-0x5000c500REPLACE_ME";
    label = "data";
    type = "linux-generic";
    sizeMin = "100G";
    sizeMax = null;
    format = "ext4";
    grow = true;
  };
}
```

AOS preflights all referenced devices before changing any partition table.
Provisioning stops if a referenced device is absent or does not use the required
`/dev/disk/by-id/...` form. Choose an identifier that remains stable across
boots.

### Use deterministic UUIDs

```nix
{
  aos.provisioning.storage.partitions.data = {
    label = "data";
    sizeMin = "20G";
    sizeMax = "20G";
    format = "ext4";
    uuid = "d6fd9d6e-6a1c-4e56-b37d-08e0b21da97f";
  };
}
```

Use a unique GPT partition UUID for each partition. Omit `uuid` to let AOS
derive and record a stable value for the committed plan.

### Prepare an additional disk

AOS seeds each disk's partition UUIDs from that disk's GPT identifier, so a
disk named by the plan must already carry a GUID partition table when the host
first boots. A blank table is enough:

```sh
sudo sgdisk --clear /dev/disk/by-id/REPLACE_WITH_DISK
```

Provisioning stops before any mutation when a referenced disk has no partition
table.

### Mirror the system state

`/var` can live on a Linux MD RAID1 array instead of a single partition. The
root disk always contributes the `var` member; every other member is a
partition on another disk. Members keep `format = null`, because the array
carries the ext4 filesystem, and MD sizes the mirror from its smallest member:

```nix
{
  aos.provisioning.storage = {
    partitions = {
      var = {
        sizeMin = "64G";
        sizeMax = "64G";
        grow = false;
      };

      var-mirror = {
        device = "/dev/disk/by-id/nvme-REPLACE_ME_2";
        sizeMin = "64G";
        sizeMax = "64G";
      };
    };

    arrays.var = {
      level = "raid1";
      members = [ "var" "var-mirror" ];
    };
  };
}
```

The array is exposed as `/dev/md/var` and its filesystem carries the label
`var`; the initrd prefers the array over the member partition that still
answers to the `var` partlabel. On a measured-boot image the array is
LUKS2-sealed exactly as a plain `/var` partition would be. The recovery console
does not yet open a mirrored `/var`; see [recovery](recovery.md#hosts-with-a-mirrored-var). The immutable image slots and the
EFI System Partition stay on the boot disk; a mirror protects state, not the
ability to boot from a second disk.

### Create a data mirror

Any array other than `var` is a data volume. Declare its members, the level,
and where to mount it:

```nix
{
  aos.provisioning.storage = {
    partitions = {
      data-a = {
        device = "/dev/disk/by-id/nvme-REPLACE_ME_3";
        sizeMin = "1T";
        grow = true;
      };

      data-b = {
        device = "/dev/disk/by-id/nvme-REPLACE_ME_4";
        sizeMin = "1T";
        grow = true;
      };
    };

    arrays.data = {
      level = "raid1";
      members = [ "data-a" "data-b" ];
    };
  };

  aos.filesystems.volumes.data.mountPoint = "/srv/data";
}
```

| Level | Minimum members |
| --- | --- |
| `raid0` | 2 |
| `raid1` | 2 |
| `raid10` | 3 |
| `raid5` | 3 |
| `raid6` | 4 |

Arrays use MD metadata 1.2 with homehost `aos`; a disk from another machine
still assembles but never claims a declared array name. An array name is the
array's filesystem label and must not equal any partition label. Set
`format = null` on an array to leave it raw for an operator-managed consumer.

### Choose a filesystem

| Filesystem | Where | Label limit | Notes |
| --- | --- | --- | --- |
| `ext4` | `/var` and data volumes; the default | 16 bytes | Stable tier. General purpose; the only filesystem for `/var`, which the initrd, sealing, and recovery paths format and repair as ext4 |
| `xfs` | Data volumes | 12 bytes | Supported tier. Many parallel writers, very large files, `reflink`; cannot shrink |
| `vfat` | Plain partitions | 11 bytes | Exchange partitions readable by firmware and other systems |

ZFS is not a `format` value; it is selected by the image through
`aos.profiles.bareMetalZfs` and sits at a lower
[support tier](support-status.md#filesystem-support-tiers).

Both ext4 and xfs are created with their tools' defaults, which detect the
stripe geometry of an MD array. Set `format = "xfs"` on a partition or array:

```nix
{
  aos.provisioning.storage.arrays.data = {
    level = "raid1";
    members = [ "data-a" "data-b" ];
    format = "xfs";
  };
}
```

### Encrypt a data volume

On a measured-boot image, a partition or array with an ext4 or xfs filesystem
can be sealed to the TPM the same way `/var` is:

```nix
{
  aos.provisioning.storage.arrays.data = {
    level = "raid1";
    members = [ "data-a" "data-b" ];
    encryption = "tpm2";
  };
}
```

`encryption = "tpm2"` is rejected on an image without measured boot, and
`encryption = "none"` is rejected for `/var` on an image with it. A sealed
volume is created raw in the first-boot transaction and formatted inside its
LUKS2 container by the first boot with Secure Boot enforcing; until then its
mount unit is inactive and the host boots without it. The recovery key for each
sealed data volume is written to `/run/aos-volume-recovery/<name>.key` on that
boot and must be escrowed off the machine, exactly like the `/var` key.

### Mount a data volume

`aos.filesystems.volumes.<name>` names a partition or array from the storage
plan and creates a stage-2 mount unit for it:

```nix
{
  aos.filesystems.volumes.data = {
    mountPoint = "/srv/data";
    mountOptions = [ "nosuid" "nodev" "noatime" ];
  };
}
```

The volume is mounted by filesystem label (`/dev/disk/by-label/<label>`), so
the same declaration works for a plain partition, an array, or a sealed
container. The unit is wanted by `local-fs.target` rather than required, so a
volume that is absent, degraded beyond assembly, or not yet sealed leaves the
mount inactive without blocking boot. `var` is mounted by the initrd and cannot
be listed here.

Mount points must lie under `/srv` or `/var`. The image root is read-only and
is built without `host.nix`, so it cannot carry per-host directories; `/srv`
is a bind mount of the persistent `/var/srv` that every host provides, and the
mount unit creates the final directory beneath it.

## Enable persistent home directories

The image root is read-only, so no home directory can live on it. AOS binds
`/root` from `/var/roothome` on every host, so root's shell history, tool
configuration, and `apm` authoring state survive reboots and image upgrades.
Other accounts get persistent homes only when you enable them:

```nix
{pkgs, ...}: {
  aos.homes.enable = true;

  aos.users.groups.alice = {
    gid = 1000;
    members = [];
  };

  aos.users.users.alice = {
    uid = 1000;
    group = "alice";
    shell = "${pkgs.bash}/bin/bash";
    description = "Workstation user";
  };

  environment.etc."ssh/authorized_keys/alice" = {
    text = "ssh-ed25519 AAAA_REPLACE_ME alice@example.com\n";
    mode = "0600";
  };
}
```

With `aos.homes.enable` set, `/home` is bound from `aos.homes.directory`
(`/var/home` by default) and every account with a UID of 1000 or above
defaults to `/var/home/<name>`. Those homes are created with the account's
ownership and `aos.homes.mode` (`0700`) at boot and again on every
configuration activation, so an account added to `host.nix` has its home
before its first login. Files declared under `aos.homes.skel` are rendered to
`/etc/skel` and copied into a home once; later edits by the user are kept.

Leave homes disabled on single-purpose servers: `/home` then stays an empty
read-only directory and accounts keep the placeholder home `/`. Enable them on
workstations and shared servers. To put homes on their own volume or dataset,
mount that volume at `aos.homes.directory`; the bind mount follows it. On a
measured-boot image that volume can be sealed to the TPM like `/var`:

```nix
{
  aos.homes.enable = true;
  aos.provisioning.storage.partitions.home = {
    sizeMin = "64G";
    sizeMax = "64G";
    encryption = "tpm2";
  };
  aos.filesystems.volumes.home.mountPoint = "/var/home";
}
```

The sealed volume protects homes at rest against removal of the disk; it does
not separate one user's data from root or from other users on the running
host. A factory reset or reimage that recreates `/var` removes every home
directory, so back them up like any other host state.

## Know when the plan becomes immutable

On a fresh disk, AOS creates a provenance marker only after it has authorized,
evaluated, and validated the complete provisioning input. That marker freezes
the storage source and plan.

On later boots:

- `coherent` means every dry-run entry was unchanged;
- `divergent` means source validation failed or the dry run found pending work
  or an error;
- `unavailable` means no valid current plan was available;
- missing current metadata does not erase the committed operator plan;
- a detected interrupted `pending` marker is not replayed automatically;
- a declared array that is not running after assembly is reported as
  `divergent`; arrays declared after the commit are never created.

A changed input can remain coherent if it describes the same final partition
table. AOS reports on the resulting disk plan, not whether the source text
changed.

AOS has no public factory-reset or pending-marker recovery command today. Back
up persistent data and reimage the disk to apply a different committed layout.
Do not delete provisioning markers by hand: they are part of the mutation and
audit protocol.

## Inspect the accepted input and result

The transient boot state is under `/run/aos-metadata`:

```sh
cat /run/aos-metadata/platform.env
cat /run/aos-metadata/provisioning-plan.json
find /run/aos-metadata/repart.d -maxdepth 3 -type f -print

if test -r /run/aos-metadata/storage-coherence; then
  cat /run/aos-metadata/storage-coherence
else
  echo "storage coherence was not evaluated this boot"
fi
```

The durable record is under `/var/lib/aos-provisioning`:

```sh
cat /var/lib/aos-provisioning/audit.json
cat /var/lib/aos-provisioning/initial-plan.json
cmp \
  /var/lib/aos-provisioning/current/host.nix \
  /run/aos-metadata/host.nix
```

The stage-2 source result and activation evidence are:

```sh
test -s /run/aos/manifest.json
cat /run/aos/activation.json
readlink /var/lib/profiles/system/current
cat /var/lib/profiles/system/state.json
systemctl status aos-eval.service
journalctl -b \
  -u aos-eval.service \
  -u aos-graph-compile.service \
  -u aos-activate.service
```

Treat the files in `/run` as diagnostics for the current transaction. The
accepted input under `/var/lib/aos-provisioning` and each numbered generation's
manifest, EROFS lower, input GC roots, and activation record survive reboot.

## Diagnose the boot stages

The relevant initrd units, in order, are:

```text
aos-provisioning-state
aos-metadata-detect
aos-metadata-network       cloud transports only
aos-metadata-fetch
aos-metadata-authorize
aos-provisioning-eval
aos-repart
```

Stage 2 then runs:

```text
aos-provisioning-persist
aos-host-config-restore
aos-eval
  -> aos-host-config-cache
  -> aos-graph-compile
     -> aos-fetch.target
     -> aos-config-render.target
     -> aos-activate
     -> aos-config.target
```

Inspect the current boot with:

```sh
journalctl -b \
  -u aos-metadata-detect.service \
  -u aos-metadata-fetch.service \
  -u aos-metadata-authorize.service \
  -u aos-provisioning-eval.service \
  -u aos-repart.service \
  -u aos-eval.service \
  -u aos-graph-compile.service \
  -u aos-activate.service
```

First-boot authorization, evaluation, or storage validation failures stop disk
mutation. Once provisioning has committed, metadata acquisition failures are
handled as recovery conditions: AOS keeps the active system and can restore the
last fully evaluated host input.

## Understand the runtime boundary

The full module evaluator and activation pipeline can apply a file such as:

```nix
{
  aos.networking.hostName = "web-01";
  aos.services.ssh.port = 2222;
  aos.apm.desiredPackages = ["nginx"];
}
```

The change becomes live only after `aos-config.target` completes. The evaluator
manifest alone is intermediate evidence; confirm the active generation and
activation record as shown above.

Desired packages are part of that same transaction. AOS pins each selected
payload and rendered unit artifact to authenticated registry NAR identities,
places the unit links and package-target preset in the candidate `/etc`, and
enables the package target only after the atomic swap. Removing a package from
`aos.apm.desiredPackages` removes that enablement edge and stops its target;
image-bundled package units remain present but inert when they are not selected.

For an interactive change, preview and apply the same file with:

```sh
apm switch --from ./host.nix --dry-run
apm switch --from ./host.nix
```

That selects a transaction input; it does not rewrite the metadata source or
the durable last-known-good metadata cache. Update the authoritative delivery
channel before reboot. On an image using signed trust, a standalone file also
needs its sibling `.sig`, `--require-signed-host-nix`, and the applicable
`--trusted-config-keys-dir`.

Cloud-supplied public SSH keys are normalized into the typed
`host.facts.ssh_authorized_keys` input. They are data, not implicit
authorization: a trusted `host.nix` or image module must deliberately project
those facts into an account's `environment.etc."ssh/authorized_keys/USER"`
entry. A key merely present in provider metadata is not automatically granted
access.

Secrets are also deliberately outside the value graph. `host.nix` may contain
only opaque `secretRef` handles. Activation can resolve the implemented
system-credential, desired-TOML, and TPM2 credstore forms, place their material
with mode `0600` when materialization is required, and deduplicate the
credential-triggered restart set. A general Vault or cloud secret-manager
delivery backend is not included; see [Manage secrets on AOS](secrets.md).
