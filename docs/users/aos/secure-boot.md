# Use Secure Boot and verify package trust

AOS composes firmware verification, measured boot, dm-verity, image-baked trust
anchors, and signed package metadata. The immutable operating-system image is
the bridge: its signed UKI authenticates the root hash, and the authenticated
root contains the initial keys used to verify registries and host
configuration.

This guide explains that complete chain and its operational limits. Registry
configuration is covered in [Configure package registries](registries.md), and
runtime confinement is covered in [Understand the package
sandbox](package-sandbox.md).

The checked-in Secure Boot and measured-boot variants use public test keys.
They demonstrate and test the mechanisms but provide no production identity.
Canonical production publication remains disabled until the release launch
gates and deployment exercises are complete.

## Follow the chain of trust

For a Secure Boot plus dm-verity deployment, verification proceeds as follows:

```text
deployment-owned UEFI PK and KEK authorize the firmware db
  -> db verifies systemd-boot and the selected UKI
  -> the UKI signature covers the kernel, initrd, and embedded command line
  -> the embedded command line supplies the expected dm-verity root identity
  -> the initrd validates and opens the immutable EROFS root through dm-verity
  -> the authenticated root supplies /etc/apm trust anchors
  -> those anchors verify registry history, TUF metadata, and the catalog
  -> the signed store graph authorizes every NAR in a selected closure
  -> APM verifies and imports those bytes into /nix/store
  -> activation extends PCR 15 for exposed package roots and permission manifests
```

Secure Boot alone verifies executable PE binaries. It does not hash every disk
block or Nix store object. The signed UKI connects to the root filesystem by
carrying the dm-verity identity; dm-verity then authenticates the bytes that
contain the next trust anchors.

This is a composed chain with separate authorities. The Secure Boot db key can
authorize a new image containing new registry keys. A registry key can
authorize package metadata and closures, but it cannot create a firmware-
bootable UKI. A cache key can authorize narinfo but cannot authorize a registry
release. Preserving those distinctions limits each compromise.

## Understand what the UKI authenticates

The normal AOS boot path uses systemd-boot and a unified kernel image. The UKI
contains the kernel, initrd, embedded kernel command line, OS release identity,
and measured-boot sections inside one PE image. Firmware verifies its
Authenticode signature before execution.

The embedded command line is authoritative. Under enforcing Secure Boot, the
EFI stub discards external command-line additions when the signed UKI contains
one. db-signed PE addons and SMBIOS input are still measured into PCR 12; that
measurement prevents automatic `/var` unlock when the external boot input does
not match policy. Unsigned addons are rejected before they can affect the
command line.

Kernel lockdown extends the boot boundary after firmware execution. It blocks
interfaces that could turn a signed kernel into a loader for unsigned kernel-
privileged code, including unsigned modules and unrestricted kexec. Deployment
module keys remain distinct from the Secure Boot db key.

## Authenticate the immutable root

On dm-verity variants, the UKI's embedded command line names the exact A/B root
and hash devices and supplies the expected root hash. The initrd validates that
tuple before constructing the mapper or touching persistent state.

After creating the mapper, AOS reads the root completely before it may unlock
or mount `/var`. Corruption anywhere in the counted immutable root therefore
blocks access to persistent state and allows boot counting to fall back to a
known-good image.

The authenticated root contains the image-baked trust policy:

| Path | Purpose |
| --- | --- |
| `/etc/apm/registries.d` | Registry URLs, channels, priorities, and bootstrap caches |
| `/etc/apm/trusted-keys.d` | Registry Ed25519 bootstrap anchors |
| `/etc/apm/trusted-sb-certs.d` | Secure Boot db certificates used to re-check cataloged UKIs before upgrade |
| `/etc/apm/trusted-config-keys.d` | Keys allowed to authorize signed `host.nix` input |

An immutable EROFS image without dm-verity resists ordinary writes but does not
receive this cryptographic root binding. Do not describe that configuration as
extending the UKI signature over its filesystem.

The current preview TUF implementation bootstraps its top-level roles from the
active registry keys. The canonical production model additionally requires a
threshold-authenticated TUF root in the image and separate offline and online
role keys. That production path is not enabled merely by building a checked-in
verified-boot variant.

## Authenticate persistent state

Measured-boot systems seal `/var` to a signed PCR policy. PCR 7 records Secure
Boot state, PCR 11 records UKI sections and boot phases, and PCR 12 records
external boot input. The PCR-policy signer authorizes expected UKI measurements
without sharing the firmware db private key.

UEFI Setup Mode is enrollment state, not normal operation. The measured-boot
image uses temporary plaintext `/var` until Secure Boot is enforcing; the first
enforcing boot replaces that filesystem with TPM-sealed storage. Do not install
packages, stage images, or apply state that must survive before enrollment and
that first enforcing boot finish.

The first sealing operation emits the only generated LUKS recovery key to its
configured path under `/run`. A production procedure must escrow it off-host
before it disappears. The recovery key, not physical console access, is the
authorization boundary for persistent-state access in the signed recovery
environment.

See [Recover an AOS host](recovery.md) for recovery UKIs, removable media, and
PCR-policy migration.

## Bootstrap package trust from the image

The built-in registry key and any deployment registry keys configured in the
image are part of the dm-verity-authenticated root. This avoids trust on first
use: APM can authenticate its first registry response without fetching the key
from the same server.

Later verified registry history may rotate or retire keys through an
authenticated roster. A writable machine policy under `/var/lib/apm/config`
may also change the effective registry set. Such a change is trusted only
according to the deployment's configuration authority:

- signed mode requires `host.nix` to verify against an image-baked operator
  key; or
- platform mode deliberately trusts the selected metadata transport.

Secure Boot does not make every future writable policy change trustworthy. It
authenticates the initial code and trust anchors that enforce the chosen update
rules.

## Verify registry packages before import

APM verifies the selected signed registry release and its complete `store/`
realization graph. Each closure member is bound to its NAR hash, size, and
references. Bytes fetched from a Hub, CDN, or binary cache must match that
authenticated identity before import into `/nix/store`.

The transport is therefore not the package authority. A compromised cache can
withhold or corrupt bytes and cause an availability failure, but it cannot make
different bytes satisfy the signed graph. A separate narinfo signature supports
stock Nix substitution and does not replace registry verification.

Registry signatures prove which registry owner authorized exact content. They
do not prove that the package is harmless. Inspect the package's permissions
and local policy as described in [Understand the package
sandbox](package-sandbox.md).

## Connect active packages to measured boot

Packages installed after image construction are not retroactively measured in
PCR 11. When APM activates a machine-wide package with `expose` metadata, it
extends PCR 15 with the package name, version, root digest, and permission-
manifest digest. Configuration generation activation also records its exact
authenticated inputs and running image relationship.

A remote quote over PCRs 7, 11, 12, and 15 can therefore bind:

- enforcing Secure Boot policy;
- the selected UKI and boot phases;
- external boot input;
- explicitly activated exposed packages and their privilege declarations; and
- the active configuration generation.

The verifier must replay the CEL event log and compare it with signed registry
and image policy. PCR values alone do not identify the events that produced
them.

PCR 15 does not measure user-profile packages, inactive downloads, every
dependency as an independent identity, or arbitrary Nix store content. The
signed realization graph authenticates those closure bytes. Only a signed
dm-verity package `RootImage=` supplies block-level verification while an
exposed workload executes.

## Validate an image before installation

Download through the AOS image interface so the signed catalog, NAR identity,
disk size, and disk digest are checked before the final file is installed:

```sh
aos image show \
  --hub https://HUB \
  --registry REGISTRY \
  --channel stable \
  --architecture x86_64 \
  --target qemu-kvm

aos image download \
  --hub https://HUB \
  --registry REGISTRY \
  --channel stable \
  --architecture x86_64 \
  --target qemu-kvm \
  --output aos-server.qcow2
```

Retain the release identity and `image-info.json` with the deployment record.
The signed release metadata and store identity authenticate the downloaded
bytes; target firmware enrollment determines whether that image is authorized
to boot on a particular machine.

## Verify the running chain

After enrollment and the first enforcing boot, inspect each boundary rather
than treating service health as boot-integrity evidence:

```sh
bootctl status
cat /sys/kernel/security/lockdown
cat /proc/cmdline
findmnt /
findmnt /var
systemctl is-system-running
systemctl --failed
cat /var/lib/profiles/image/state.json
cat /var/lib/profiles/system/state.json
cat /run/aos/activation.json
```

Record the effective registry policy and active packages:

```sh
apm registry list
apm list --installed --system
```

For a remote trust decision, use the public runtime-attestation verifier with
an enrolled quote identity, the host CEL and quote bundle, and policy derived
from the signed image and registry catalogs. It validates the quote signature,
nonce, PCR values, dm-verity root, package events, active key roster, module and
store graph, and authenticated configuration inputs.

## Upgrade without breaking the chain

Before writing an inactive root, APM verifies the candidate's signed registry
catalog, store identity, root hash, expected measurement, Secure Boot signer,
and SBAT policy. It also re-authenticates installed normal and recovery UKIs
against the immutable db certificate snapshot carried by the running image.

The candidate uses systemd-boot counting. AOS blesses it only after it boots,
re-evaluates configuration against its own ABI, reaches the ready PCR phase,
and verifies the generation quote against live PCR 7, 11, and 12 values and the
published expected PCR 11. Until then, exhaustion of the boot counter returns
to the known-good slot.

See [Upgrade and roll back an AOS host](upgrades.md) for the complete staging,
blessing, replica synchronization, and rollback procedure.

## Keep the guarantees precise

The chain does not establish that:

- public fixture keys are production identities;
- Secure Boot alone authenticates the root filesystem;
- an authenticated registry package is benign;
- every `/nix/store` object is represented by a PCR event;
- a store-backed workload has dm-verity runtime integrity;
- a physical-console user is authorized to unlock persistent state; or
- a successful build supplies production key custody and enrollment.

Production deployment requires deployment-owned keys, external signing,
firmware enrollment, recovery-key escrow, rotation, incident response, and
qualification on the exact hardware and image. Until those operations are
integrated and exercised together, treat the checked-in verified-boot variants
as validation fixtures.
