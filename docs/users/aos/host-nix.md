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
- a detected interrupted `pending` marker is not replayed automatically.

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
