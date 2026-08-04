# Understand and operate `host.nix`

`host.nix` is the machine-owned Nix module delivered at boot. It is separate
from the system variant used to build the image:

- the system variant defines what is present and active in the immutable image;
- `host.nix` carries deployment-time intent for one machine;
- instance facts describe what the platform reports about that machine.

Today, AOS applies the `aos.provisioning.storage` part of `host.nix` during
first boot. It also evaluates the full module during stage 2, but does not yet
activate the resulting runtime manifest. This page documents both paths so an
operator can tell what changes the host and what is only diagnostic output.

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
  -> full stage-2 evaluation
  -> /run/aos/manifest.json
```

The initrd evaluation can see only the closed provisioning schema shipped in
the image. It cannot fetch registry modules or select arbitrary build packages.
This is the path that runs before disk mutation.

The stage-2 evaluator uses the image's ABI-pinned module library, the selected
package configuration modules, and `host.nix` to produce a converged manifest.
An evaluation failure does not replace the active system. A successful result
is cached with the accepted input under `/var/lib/aos-provisioning`.

The final materialization and activation step for the general manifest is not
wired into the current boot graph. `/run/aos/manifest.json` is therefore an
evaluation result, not proof of a live configuration change.

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

Create an AOS metadata ISO from the repository's own package:

```sh
nix-build -A pkgs.libisoburn -o result-aos-libisoburn
mkdir -p metadata
cp host.nix metadata/host.nix
./result-aos-libisoburn/bin/xorriso -as mkisofs \
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

Signed mode fails closed on first boot if the image has no matching trust key,
the signature is missing, or verification fails. After a host has been
successfully provisioned, an unavailable or unauthorized new input is ignored
and the previous active configuration is retained.

## Use the storage schema

Two partitions exist in the default intent:

| Name | Default |
| --- | --- |
| `swap` | Fixed 2 GiB, swap type and format |
| `var` | 4 GiB minimum, grows into remaining space |

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

The partition is created and formatted. Declaring it does not create a mount
unit; mount policy still belongs in the build-time system configuration today.

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

AOS preflights all referenced devices before changing any partition table. If a
device is absent or an explicit path is unstable, provisioning stops before
the plan is committed.

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

## Know when the plan becomes immutable

On a fresh disk, AOS creates a provenance marker only after it has authorized,
evaluated, and validated the complete provisioning input. That marker freezes
the storage source and plan.

On later boots:

- the same valid plan is reported as `coherent`;
- changed or invalid storage intent is reported as `divergent` and not applied;
- missing current metadata does not erase the committed operator plan;
- a detected interrupted `pending` marker is not replayed automatically.

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

The stage-2 evaluation result is:

```sh
test -s /run/aos/manifest.json
systemctl status aos-eval.service
journalctl -b -u aos-eval.service
```

Treat the files in `/run` as diagnostics for the current boot. The durable
audit and cached input under `/var/lib/aos-provisioning` survive reboot.

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
aos-host-config-cache
```

Inspect the current boot with:

```sh
journalctl -b \
  -u aos-metadata-detect.service \
  -u aos-metadata-fetch.service \
  -u aos-metadata-authorize.service \
  -u aos-provisioning-eval.service \
  -u aos-repart.service \
  -u aos-eval.service
```

First-boot authorization, evaluation, or storage validation failures stop disk
mutation. Once provisioning has committed, metadata acquisition failures are
handled as recovery conditions: AOS keeps the active system and can restore the
last fully evaluated host input.

## Understand the current runtime boundary

The full module evaluator already understands more than storage. A file such
as this can evaluate successfully:

```nix
{
  aos.networking.hostName = "web-01";
  aos.services.ssh.port = 2222;
  aos.apm.desiredPackages = ["nginx"];
}
```

It does not currently make those settings live. Specifically:

- `/etc/hostname` is not switched to `web-01`;
- the running SSH service is not moved to port 2222;
- package selection is not a complete install-and-activate operation;
- SSH keys found in cloud facts are recorded but not installed as authorized
  keys.

Use a [`systems/*.nix` variant](configuration.md#create-a-system-variant) for
hostname, network, users, SSH, services, firewall, and image contents. Use the
implemented [machine-wide package reconciliation](packages.md#manage-machine-wide-packages)
for runtime packages.

This distinction is also useful in incident response: a valid manifest with an
unchanged live host is expected with the current implementation, not evidence
that systemd ignored an activated generation.
