# Recover an AOS host

Recovery starts by identifying which layer changed: firmware, A/B image
generation, first-boot storage, configuration generation, APM package
generation, or mutable application state under `/var`.

Keep console access, the deployed image digest, the accepted `host.nix`,
registry trust anchors, and application backups outside the host.

## Understand the initrd access boundary

Normal AOS initrds have a locked root account and do not run the upstream
interactive emergency or rescue login services. A failure before switch-root
therefore stops noninteractively; there is no fleet-wide or image-default
password that grants an initrd shell.

On dm-verity images, the signed embedded kernel command line is authoritative.
External db-signed PE-addon and SMBIOS command-line fragments are measured into
PCR 12 but not appended, so they cannot select an alternate init or target
before recovery validation. Under enforcing Secure Boot, systemd-boot measures
Type #1 entry options into PCR 12 and the stub discards them when an embedded
command line exists. Unsigned addons are rejected by the image loader before
command-line measurement. A malformed, duplicated, or control-bearing field
that does reach the effective command line is rejected before the verity
mapper, `/var` unlock, or `/var` mount can start. The host stops in a passive
boot-identity failure target; it does not honor command-line requests for
emergency, debug, breakpoint, or transient-command units. Treat the console
diagnostic as evidence to preserve, not as a prompt that can be authenticated
locally.

Recovery UKIs are stricter: after measuring a db-signed addon or SMBIOS
command-line fragment, the stub refuses that launch before the kernel starts.
Boot the clean recovery entry again after removing the external input.

The development debug profile can add direct autologin gettys, but enabling it
is an explicit security waiver and it must not be used for production images.

Secure Boot plus dm-verity images build paired `AOS Recovery A` and `AOS
Recovery B` firmware entries. They are uncounted and independent of the normal
candidate counter. Recovery A is paired with immutable slot A and recovery B
with slot B; an inactive-slot update may replace only the matching recovery
copy, leaving the opposite copy intact.

## Use the signed recovery console

Select either recovery entry from the firmware menu. The signed command line
selects `/dev/ttyS0` at 115200 baud and starts a dedicated initrd
that has no normal-root mount, switch-root, TPM
automatic unlock, provisioning, package activation, debug login, or automatic
networking path. Its fixed menu provides:

1. bounded firmware, recovery-copy, and slot status;
2. offline verification of immutable slot A;
3. offline verification of immutable slot B;
4. one-shot boot of slot A after verification in the same session;
5. one-shot boot of slot B after verification in the same session;
6. authenticated removable-media restore of the inactive slot;
7. `/var` unlock with the per-machine recovery key;
8. an authenticated maintenance shell;
9. explicit `/var` lock; and
10. poweroff.

Verification checks the selected normal UKI signature and embedded boot
identity, its release and slot metadata, the cataloged root hash, and the
dm-verity tree without mounting the root. A failed check does not enable the
one-shot boot operation.

Unlock and restore prompt for the off-machine LUKS recovery key through
`systemd-ask-password`. Recovery selects the exact retained
`systemd-recovery` token; it does not guess a keyslot and does not use TPM
automatic unlock. Exiting the maintenance shell unmounts `/var`, closes the
mapping, and returns to the bounded menu. It never blesses a normal image.

Do not treat the presence of this menu as proof that recovery is operational.
Before production use, exercise per-machine key generation, off-host escrow,
retrieval, rotation, removal, wrong-key refusal, and a successful recovery on
representative hardware. If the key is unavailable, or firmware, the ESP,
both recovery copies, or the encrypted volume is lost, use authenticated
external rescue media or reimage the host.

## Restore an inactive slot from removable media

The image build exposes a recovery bundle with a fixed `aos/recovery/`
directory. Copy that directory without renaming or adding files to an ext4
filesystem labeled `AOS-RECOVERY`. It contains the root and verity payloads,
normal and recovery UKIs, both recovery loader entries, image metadata, and a
detached signed manifest.

Recovery mounts only that fixed label and location, read-only with
`nodev,nosuid,noexec`. It validates the manifest's direct signature against
the immutable build-configured deployment-db certificate snapshot, rejects unknown or
non-regular directory members, and verifies
every component before prompting for write authorization. The publisher also
requires this exact manifest to equal the copy in the signed release catalog;
the offline console does not carry or independently replay the registry
catalog chain. Restore can replace only the slot opposite the running recovery
copy. The console displays the authenticated release and requires the exact
confirmation `RESTORE SLOT A` or `RESTORE SLOT B`, followed by the per-machine
recovery key.

The snapshot contains the image signer and any `sbDbCerts` deliberately kept
for certificate-rotation overlap. Removing or revoking an overlap certificate
in registry state does not rewrite an already signed recovery initrd. Retire
it with a newly qualified image that omits the certificate, then complete the
deployment's firmware db/dbx rotation procedure.

The writer disarms the inactive normal UKI before changing its root, performs
read-back verification, publishes the matching recovery UKI and entry, and
makes the restored counted normal UKI discoverable last. It removes disabled
old UKIs only after that publication is synced and verified. A recovery copy
accepts the fixed `AOS-RECOVERY` filesystem only from a kernel-reported
removable device outside the installed disk; a second internal disk carrying
that label is rejected. The manifest, every component digest, every UKI
signature, and each signed slot/copy identity are checked before the key prompt
or any write. A recovery copy
embeds the slot manifest for its own release, so the old running recovery copy
cannot verify a newly restored release. After success, reboot into the newly
installed recovery entry paired with the restored slot, verify that slot from
its menu, and only then select the one-shot normal boot.

## Migrate an existing `/var` TPM policy

Hosts enrolled before PCR 12 was pinned keep their PCR-7-only TPM token until
an operator authorizes replacement with the off-machine recovery key. Perform
the migration only from a known-clean signed boot whose current PCR signature
matches the deployed policy key. Put the recovery key in a root-only file on
tmpfs, as one canonical key line (a trailing line feed is ignored), then run:

```sh
chmod 0600 /run/aos-var-recovery.key
aos-var-policy-migrate \
  /dev/disk/by-partlabel/var \
  /run/aos-var-recovery.key \
  /etc/aos/pcr-sign.pem \
  /run/systemd/tpm2-pcr-signature.json \
  /var/lib/aos/security/var-policy-migration.json
```

The signature argument must use systemd's canonical runtime path shown above.
The command binds the supplied recovery key to its exact recovery token and
keyslot, adds a PCR-7+12 token carrying the supplied PCR-11 public key, and
tests that exact TPM token. It durably records the verified transaction before
removing any older TPM keyslot, and can resume from that boundary after an
interruption. The retained recovery keyslot and new TPM keyslot are explicitly
excluded from cleanup. Preserve the completed evidence JSON with the host's
incident and key-custody records, reboot once, and confirm `/var` unlocks
unattended before deleting the tmpfs key file.

## Collect state before changing it

From a working console or rescue environment, capture what is available:

```sh
cat /etc/os-release
cat /proc/cmdline
systemctl --failed
journalctl -b -p warning
findmnt /
findmnt /var
lsblk -o NAME,SIZE,FSTYPE,PARTLABEL,PARTUUID,MOUNTPOINTS
readlink /var/lib/profiles/system/current
cat /var/lib/profiles/image/state.json
cat /var/lib/profiles/system/state.json
cat /run/aos/activation.json
apm rollback --system --list
cat /var/lib/aos-provisioning/audit.json
```

Do not rerun provisioning or delete generation pointers before preserving this
evidence. The first error often distinguishes an input failure from a later
service failure.

## Recover from a failed first boot

Inspect the provisioning chain:

```sh
systemctl status \
  aos-metadata-detect.service \
  aos-metadata-fetch.service \
  aos-metadata-authorize.service \
  aos-provisioning-eval.service \
  aos-repart.service
journalctl -b \
  -u aos-metadata-detect.service \
  -u aos-metadata-fetch.service \
  -u aos-metadata-authorize.service \
  -u aos-provisioning-eval.service \
  -u aos-repart.service
```

Verify the metadata label and payload, trust mode, detached signature, target
disk identifiers, and available unallocated space. Storage policy is committed
once. After a successful commit, a changed `host.nix` is drift rather than an
instruction to repartition the machine.

If the layout is wrong, preserve required data from `/var`, correct the image
or metadata, and reprovision a replacement disk. Do not edit the recorded plan
to make it agree with an unintended layout.

## Recover a failed configuration activation

An error can occur during evaluation, package fetch/render, secret resolution,
EROFS materialization, `/etc` replacement, or unit reconciliation. First
determine the active pointer and transaction-bound activation result:

```sh
readlink /var/lib/profiles/system/current
cat /etc/os-release
apm rollback --system --list
systemctl --failed
journalctl -b \
  -u aos-eval.service \
  -u aos-graph-compile.service \
  -u aos-activate.service
```

Preview rollback, then switch to the intended generation:

```sh
apm rollback --system --dry-run
apm rollback --system
```

Configuration rollback under the same module ABI reactivates the retained
generation directly. Across an ABI boundary, APM re-evaluates its retained
inputs against the running image before committing a compatible generation.
It does not switch the kernel or root slot.

To select a known-good image for the next boot, use the image axis explicitly:

```sh
apm rollback --system --image --list
apm rollback --system --image --generation N --dry-run
apm rollback --system --image --generation N --reboot
```

The candidate is accepted only after its boot-time configuration transaction
commits. If a pending image exhausts its sd-boot attempts, boot counting falls
back to the other slot; inspect both state files after reaching the console.

If activation status indicates an incomplete `/etc` swap, treat the system as
indeterminate. Use console access, preserve `/var`, and restore a known-good
image or generation according to a procedure tested for that release.

## Recover an application package

Inspect installed package generations and the package target. This example
uses the `acme-agent` package from the [configuration guide](configuration.md);
replace it with the affected package and unit:

```sh
apm list --installed --system
systemctl status aos-pkg-acme-agent.target
systemctl status acme-agent.service
journalctl -u acme-agent.service -b
```

The current CLI has no supported rollback command for the machine-wide runtime
package profile: `apm rollback --system` rolls back configuration, while
`--system --image` selects an A/B image. Restore a known-good image or follow a
release-specific recovery procedure that has been tested before the incident.
Do not move a registry channel backward; registry
consumers enforce a monotonic release floor. Stop the rollout and publish a
higher corrected release.

## Recover from a full `/var`

Find the consumer before deleting anything:

```sh
df -h /var
du -x -h -d 2 /var | sort -h
journalctl --disk-usage
```

The journal has configured retention and size limits; vacuuming it may recover
space during an incident:

```sh
journalctl --vacuum-size=250M
```

Use application-specific cleanup for application state and AOS Hub storage.
`apm clean --generations --keep N` cleans the invoking user's package profile;
`apm clean --system --generations --keep N` safely prunes both machine-wide
package and configuration generations while retaining each current generation.
Run `apm gc` afterward to collect store paths released by pruned configuration
roots. A/B image generations are not pruned by this command. Do not remove
profile directories or current links by hand.

When no supported cleanup can restore a safe margin, preserve application
state and reimage onto a correctly sized disk.

## Recover AOS Hub state

Stop the Hub before copying its native state. Restore `hub.db`, SQLite WAL
files, `secret.key`, local storage bindings, external binding data, and service
configuration from one consistent recovery point. A database without the
matching sealing key cannot read sealed credentials or hosted keys.

After restoration:

```sh
systemctl start aos-hub.service
curl -fsS http://127.0.0.1:8420/healthz
systemctl status aos-hub.service
journalctl -u aos-hub.service -b
```

See [Deploy the native AOS Hub](../aos-hub/native.md) for backup and restore
details.

## Decide when to reimage

Reimage when:

- firmware, GPT, the EFI System Partition, kernel, UKI, or immutable root is
  damaged or does not match the intended release;
- first-boot storage was committed incorrectly;
- recovery would require manual edits to immutable system content;
- A/B image generations consume space that cannot be pruned safely, or
  supported package/configuration pruning cannot restore a safe margin;
- host trust or identity can no longer be established.

An immutable system makes replacement a normal recovery tool. The critical
precondition is that application state, trust material, and deployment inputs
are recoverable independently of the machine.
