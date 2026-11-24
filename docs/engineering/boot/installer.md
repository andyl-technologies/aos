# Unattended installer

AOS installs onto bare metal from a USB stick that carries a signed installer
UKI (unified kernel image), the release image, and the operator's `host.nix`.
The stick boots an initrd that runs the same detect, acquire, authorize, and
evaluate operations as a normal first boot. Instead of provisioning storage,
it writes the release image to the disk that `host.nix` names and hands the
next boot to that disk. The installer never partitions or formats storage:
the installed system's own first boot does that, from the same `host.nix`,
which it reads from the still-attached stick.

The operator procedure is in
[Install from a USB stick](../../users/aos/installation.md#install-from-a-usb-stick).

## Source map

| Path | Role |
| --- | --- |
| `lib/build/installer-media.nix` | `lib.build.installerMedia`: derives media from an evaluated system |
| `modules/image/installer.nix` | `aos.image.installer` options, the `aos-installer.target` initrd target, and the reboot unit |
| `pkgs/system/_systemd-abilities/platform/_installer-media.nix` | Assembles the raw GPT media image and the installer UKI |
| `pkgs/system/_aos-storage-provisioning-provider/install.nix` | The `installation` ability: `install` and `unattended` operations, `aos.installer` options |
| `pkgs/system/_aos-storage-provisioning-provider/installer-media-policy/module.nix` | Initrd policy that selects installer mode |
| `crates/boot/aos-installer/` | The `aos-installer` handler program |
| `crates/boot/aos-storage-layout/src/install.rs` | The evaluated `aos.provisioning.install` projection and its validation |
| `tests/fleet/install-from-usb.nix` | End-to-end check |

## Building media

Media is a second evaluation of a system. `lib.build.installerMedia` extends
the system's modules with `aos.image.installer.media = true`, so that
evaluation's kernel and initrd become the installer UKI, while the original
evaluation supplies the raw release image that is installed. Both evaluations
share every authored module, so `host.nix` is evaluated against the same base
library at install time and at first boot.

Each system exposes the result as a function:

```text
systems.<variant>.installerMedia { hostConfiguration ? null }
```

`hostConfiguration` is a `host.nix` to place on the media; left null, the
media ships blank for the operator to fill in. `aos-dev build image
<variant>:installer` builds the same attribute, and `aos-dev list images`
shows the name only for systems that can build it
(`tools/dev/targets.nix`, `tools/dev/lib/targets.bash`).

The media evaluation asserts that Secure Boot is enabled with local signing
and that a raw release image exists. An externally finalized system publishes
no raw image and therefore cannot build media. Because media is not reached
through `system.build.toplevel`, `installer-media.nix` evaluates those
assertions itself and throws their messages.

## Media layout

`_installer-media.nix` builds a raw GPT disk with three partitions:

| Partition | Filesystem | Contents |
| --- | --- | --- |
| `aos-installer-esp` | FAT32, ESP type | The signed installer UKI as the removable-media fallback loader. It is not labeled `ESP`, so it never collides with the installed disk's ESP. |
| `aos-payload` | ext4, mounted read-only | The compressed raw disk, its image metadata, and a db-signed manifest over them |
| `aos-meta` | FAT32, filesystem label `AOS-META` | The operator's `host.nix`. FAT keeps it editable from any workstation. |

The installer UKI boots the image's own kernel. Its command line keeps only
the console and diagnostics parameters of the system and adds
`rd.systemd.unit=aos-installer.target rd.luks=0`. It carries no root hash and
no PCR policy: it never mounts an immutable root and must not unseal
installed-system state.

### Payload

The payload format is owned by `crates/boot/aos-installer/src/payload.rs`:

```text
aos-payload/
├── installer-payload.json       manifest below
├── installer-payload.json.sig   detached SHA-256 signature, db key
├── aos-<system>.img.zst         compressed raw GPT disk
├── image-info.json              provider image metadata
└── image-delivery.json          delivery metadata
```

```json
{
  "schema": "aos.installer-payload/v1",
  "release": "2026.10.2",
  "architecture": "x86_64",
  "platform": "x86_64-linux",
  "disk": { "byte_size": 4294967296, "sha256": "<logical disk digest>" },
  "components": [
    { "id": "disk-image", "path": "aos-server.img.zst", "byte_size": 1, "sha256": "..." },
    { "id": "image-info", "path": "image-info.json", "byte_size": 1, "sha256": "..." },
    { "id": "image-delivery", "path": "image-delivery.json", "byte_size": 1, "sha256": "..." }
  ]
}
```

Nothing else may be present on the partition. Verification order matters: the
manifest signature is checked before the manifest is parsed, every component
is hashed before any metadata is read, and the metadata must agree with the
signed logical-disk identity. The signature is verified against the db
certificates the media policy package copies into the initrd
(`active-db-certs.pem`), so the payload is authenticated by the same key that
signs the release's boot binaries.

## Installer initrd

The installer UKI selects `aos-installer.target` instead of `initrd.target`,
so no root device, switch-root, or persistent-state unit is started. The
target pulls in `basic.target`, `aos-ability-initrd-controller.service`, and
`aos-installer-reboot.service`. The reboot unit requires the controller, so a
failed installation leaves the controller failed, the machine does not
reboot, and the console keeps the diagnostic.

The media policy module sets `aos.boot.installerMedia = true`, disables
`aos.storageProvisioning`, and enables `aos.installer`. The controller then
runs `installation.operations.unattended` in place of
`storageProvisioning.operations.prepare`. Its children up to `evaluate` are
the ones a normal first boot runs (see
[host configuration](../host-configuration.md#boot-pipeline)), so the stick's
`host.nix` is authorized and evaluated exactly as the installed system later
evaluates it. The final child is `installation.operations.install`, whose
handler is the `aos-installer` program. Installer media has no ESP journal,
so this one transaction journals in memory.

`aos.installer.countdownSeconds` (1 to 300, default 10) sets the console
countdown.

## Install operation

`aos_installer::handle` receives the evaluated install plan, the storage
plan, the trust bundle, the countdown, and exact store paths for every tool
it runs. On `apply` it:

1. Requires `aos.provisioning.install.mode = "unattended"` and a
   `targetDevice`; without them it stops with a console diagnostic.
2. Finds the unique `aos-payload` partition, mounts it read-only with
   `nodev,nosuid,noexec`, and verifies the payload.
3. Checks that every secondary storage device in the plan is present, and
   computes the capacity the target needs: the image, the minimum size of
   each root-disk partition first boot will create, and 16 MiB of slack.
4. Resolves the target (`target.rs`). It must be a whole, non-removable,
   unused disk that is not the installer media, carries no AOS partition, and
   is large enough.
5. Announces the release and target on the console and counts down. The
   countdown cannot be skipped; powering the machine off is the abort.
6. Streams the image through `zstd -dc` onto the target and verifies it by
   reading it back against the signed size and digest.
7. Runs `sgdisk -e` to move the backup GPT header to the end of the disk and
   waits for udev to settle.
8. Registers the target ESP's fallback loader as a firmware boot entry,
   places it first in `BootOrder`, and sets `BootNext` (`firmware.rs`).
   systemd-boot's one-shot variables cannot do this, because they select an
   entry inside the boot manager on the installer media. If the firmware
   entry cannot be created the installation still counts as complete: the
   media boots again, finds the AOS layout, and refuses to reinstall.

`observe` reports `retry-safe` only when the target carries no AOS partition
label, and `indeterminate` otherwise, so an interrupted write is never
replayed onto a partially written disk.

Progress goes to `/dev/console` and to stderr, because the handler's stdout
carries its result document (`console.rs`).

## Tests

`checks.fleet.install-from-usb` (`tests/fleet/install-from-usb.nix`) boots
two machines with `bootMode = "installer"`, each with a blank virtio disk, a
vTPM, and a stick built from `systems/server-verity.nix`:

- `target` opts in through `host.nix`. The check asserts that the installed
  system reaches `multi-user.target` from the virtio disk, that first boot
  created the expected partitions and the operator provenance marker, that
  `var` honors the requested minimum size, and that the stick is still
  attached and unwritten.
- `refused` omits the opt-in. The check asserts that the serial console shows
  the refusal and "no reboot will occur", and that no write, countdown, or
  switch-root happened.
