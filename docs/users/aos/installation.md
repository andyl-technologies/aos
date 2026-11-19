# Install an AOS image

AOS is installed from a signed UEFI disk image published by an AOS
registry. A Hub can provide discovery, but static Git/HTTP registries also
work. There is no `aos install` command that writes a disk: installation
means downloading a verified image, importing it into a hypervisor, writing
it with the target platform's normal imaging tool, or booting
[USB installer media](#install-from-a-usb-stick) on bare metal.

The download commands below use the `aos` CLI on a workstation or operations
host, not on the machine being installed; an AOS image puts only `apm` on its
`PATH`. [Use the AOS command-line tools](cli.md) describes how to run `aos`.
This guide abbreviates the unified kernel image as UKI and the EFI System
Partition as ESP.

Before enrollment or first boot, read [Use Secure Boot and verify package
trust](secure-boot.md) for the full chain, production-key requirements, and the
boundary between image and package verification.

## Discover and download an image

For a configured APM registry, use its local name from `apm registry list`:

```sh
aos image list --registry andyl --channel stable
aos image download --registry andyl --channel stable \
  --architecture x86_64 --target qemu-kvm --output aos-server.qcow2
```

These commands verify signed Git metadata and download through that registry's
cache chain without a Hub. See [Registry configuration](registries.md) to add a
registry and pin its maintainer-provided trust key.

Alternatively, open the registry's **Images** page at
`https://HUB/REGISTRY/-/images`, or select Hub discovery explicitly. In Hub mode,
`REGISTRY` is the organization/registry slug rather than a local APM name:

```sh
aos image list \
  --hub https://HUB \
  --registry REGISTRY \
  --channel stable

aos image download \
  --hub https://HUB \
  --registry REGISTRY \
  --channel stable \
  --architecture x86_64 \
  --target qemu-kvm \
  --output aos-server.qcow2
```

[Discover and download system images](cli.md#discover-and-download-system-images)
covers resuming a transfer, exact releases, private-registry tokens, and JSON
output. To boot a downloaded raw or QCOW2 image locally without modifying the
verified artifact, see
[Run a downloaded image locally](cli.md#run-a-downloaded-image-locally).

## Choose an image format

The same golden system may be published in several disk encodings:

| Format | Typical target |
| --- | --- |
| Zstd-compressed raw GPT disk | Bare metal, custom image pipelines, QEMU |
| QCOW2 | QEMU/KVM, OpenStack, Proxmox |
| VMDK | VMware and vSphere |
| Dynamic VHD | Hyper-V and VHD-based conversion pipelines |

Use the format published for the target. Raw images are delivered as
`aos-<system>.img.zst`; fixed partition headroom and the empty inactive slot
therefore add almost no transfer cost. The CLI verifies the compressed object's
signed size and SHA-256. Publication also verifies that decompression produces
the exact `virtualSizeBytes` and `logicalDiskSha256` recorded in
`image-delivery.json`. The provider's `image-info.json` separately records the
root, disk layout, and boot artifacts; disk-format conversion preserves that
contract. Retain both documents with the deployment record. UEFI
firmware is required; do not pass a separate kernel or initrd.

## Size the target

Each golden image declares maximum sizes for its root, verity tree, initrd,
UKI, ESP, runtime closure, and image transfer through `aos.image.budgets`.
The root, verity, and ESP maxima are storage-format contracts: they determine
the capacities of the A/B GPT partitions and encrypted ZFS zvols rather than
following the size of one particular build. The per-image `image-budget` Nix
check fails when an artifact, transfer, or runtime closure crosses its declared
maximum.

The target must also provide trailing unallocated space for first-boot state:

- `swap`: 2 GiB by default;
- `/var`: 4 GiB minimum and grows to consume remaining space.

Allow more than 6 GiB beyond the image itself: the fixed provisioning marker
and partition alignment need space in addition to the 2 GiB swap and 4 GiB
`/var` minimum. The fleet tests use 16 GiB disks.

> [!WARNING]
> A measured-boot image started in UEFI Setup Mode uses a temporary plaintext
> `/var` so keys can be enrolled. The first boot with Secure Boot enforcing
> replaces it with TPM-sealed storage and erases everything written there.
> Complete enrollment and that first enforcing boot before applying host
> configuration, installing packages, or staging image updates.

If a raw file is enlarged before boot, relocate its backup GPT header after
resizing:

```sh
zstd -d /path/to/downloaded-aos.img.zst -o aos-server.img
chmod u+w aos-server.img
truncate -s 16G aos-server.img

sgdisk -e aos-server.img
```

For a cloud or hypervisor, expand the virtual disk and relocate its backup GPT
before first boot. Merely increasing the hypervisor-visible size is
insufficient. Prepare the raw image before conversion or import, or use
platform tooling that performs both operations while preserving the image's
GPT and EFI System Partition.

## Write a raw disk

Writing the raw image replaces the target disk's partition table and data.
Resolve and inspect the exact persistent device path before proceeding; use a
`/dev/disk/by-id/...` path rather than a kernel-assigned name such as `/dev/sda`.

```sh
ls -l /dev/disk/by-id
lsblk -o NAME,SIZE,MODEL,SERIAL,MOUNTPOINTS
```

After the operator has confirmed the target, decompress directly into the
imaging tool so the uncompressed disk need not occupy staging storage. Then
relocate the GPT backup header on the target before first boot:

```sh
zstd -dc aos-server.img.zst | \
  sudo dd of=/dev/disk/by-id/REPLACE_WITH_TARGET bs=16M oflag=direct status=progress
sudo sync
sudo sgdisk -e /dev/disk/by-id/REPLACE_WITH_TARGET
```

No AOS command performs this write on a running workstation. Use the
deployment system's normal image-import or disk-imaging workflow, with its
audit and confirmation controls, or boot the installer media described next.

## Install from a USB stick

Installer media installs a release onto a bare-metal machine without another
operating system. It boots a signed installer UKI, evaluates the `host.nix` on
the stick exactly as the installed system's first boot will, and writes the
release image only when that `host.nix` names the target disk.

The media is a raw GPT image with three partitions:

| Partition | Contents |
| --- | --- |
| `aos-installer-esp` | The signed installer UKI as the removable-media boot loader |
| `aos-payload` | The compressed release image, its metadata, and a manifest signed with the release's Secure Boot db key |
| `aos-meta`, filesystem label `AOS-META` | FAT32, holding the operator's `host.nix` and optional `host.nix.sig` |

The installer partition is not labeled `ESP` and the stick carries no root
partitions, so it never collides with the installed disk.

Build the media from a locally signed Secure Boot system. Pass the `host.nix`
to bake it in, or leave it out and copy `host.nix` onto the FAT `AOS-META`
partition from any workstation after writing the stick. Inside the
development shell, `aos-dev list images installer` lists the systems that can
build media, and `aos-dev build image my-server:installer` accepts the same
`--arg hostConfiguration` flag:

```sh
nix-build -A systems.my-server.installerMedia --arg hostConfiguration ./host.nix
sudo dd if=result/aos-aos-installer.img \
  of=/dev/disk/by-id/REPLACE_WITH_USB_STICK bs=16M oflag=direct status=progress
```

Installation is unattended and must be enabled in `host.nix`. Name the whole
disk to erase by its stable identity; it becomes the root disk, so storage
partitions on it omit their `device`:

```nix
{
  aos.provisioning.install = {
    mode = "unattended";
    targetDevice = "/dev/disk/by-id/nvme-Samsung_SSD_990_PRO_2TB_S7KHNJ0X000000";
  };

  aos.provisioning.storage.partitions.var.sizeMin = "64G";
}
```

Boot the machine from the stick. The installer:

1. authorizes and evaluates `host.nix` under the image's trust policy, and
   stops unless installation is enabled;
2. verifies the payload manifest against the image's db certificates and
   every payload file against the manifest;
3. requires the target to be a present, whole, non-removable, unused disk that
   is not the stick, carries no AOS partitions, and fits the image plus the
   bounded first-boot partitions, and requires every other disk named by
   `aos.provisioning.storage` to be present;
4. announces the release and target, then counts down for ten seconds; power
   off during the countdown to abort;
5. writes the image, verifies it by reading it back, and relocates the
   backup GPT header to the end of the disk; and
6. adds a first-priority firmware boot entry for the installed disk, sets
   `BootNext`, and reboots.

Leave the stick attached through that reboot. The installed system's first
boot reads the same `host.nix` from `AOS-META`, provisions storage, and
activates the rest of the configuration. Remove the stick after first boot
reaches `multi-user.target`; later boots restore the last evaluated input.
If the stick stays attached, every boot reads its `host.nix` again, so edits
on the stick become configuration changes under `platform` trust. Use
`signed` trust for media that may be handled by others.

Any failure stops before the disk is written, or reports that the disk may
hold a partial image, and never reboots. The installer refuses a disk that
already carries AOS partitions; wipe it explicitly to reinstall.

## Install redundant ext4 storage

Redundancy for persistent state does not need a different image. Write the
raw image to the boot disk as above, give every additional disk a blank GUID
partition table, and declare the topology in `host.nix`:

```sh
for disk in /dev/disk/by-id/REPLACE_WITH_DISK_2 /dev/disk/by-id/REPLACE_WITH_DISK_3; do
  sudo sgdisk --clear "$disk"
done
```

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
        device = "/dev/disk/by-id/REPLACE_WITH_DISK_2";
        sizeMin = "64G";
        sizeMax = "64G";
      };
      data-a = {
        device = "/dev/disk/by-id/REPLACE_WITH_DISK_2";
        sizeMin = "100G";
        grow = true;
      };
      data-b = {
        device = "/dev/disk/by-id/REPLACE_WITH_DISK_3";
        sizeMin = "100G";
        grow = true;
      };
    };
    arrays = {
      var = {
        level = "raid1";
        members = [ "var" "var-mirror" ];
      };
      data = {
        level = "raid1";
        members = [ "data-a" "data-b" ];
        # Measured-boot images only.
        encryption = "tpm2";
      };
    };
  };

  aos.filesystems.volumes.data.mountPoint = "/srv/data";
}
```

The first boot carves every partition, creates the arrays, and commits the
provenance marker only once they exist. Later boots assemble the arrays from
their superblocks before `/var` is mounted, and start a mirror degraded when a
member is missing. The immutable A/B image slots and the EFI System Partition
remain on the boot disk; this layout protects state, not the boot path. The
[`host.nix` guide](host-nix.md#mirror-the-system-state) documents the levels,
naming rules, encryption policy, and mount units.

## Install redundant encrypted ZFS storage

The encrypted-ZFS bare-metal layout is selected in the image definition and
installed with its own installer; the procedure is in
[Install redundant encrypted ZFS storage](../../maintainers/system-images.md#install-redundant-encrypted-zfs-storage).
[Run ZFS storage](storage-zfs.md) covers operating the pool.

## Supply first-boot metadata

AOS accepts a literal `host.nix` through one of these transports:

- an AOS metadata drive with filesystem label `AOS-META`;
- a NoCloud drive with filesystem label `cidata`;
- an OpenStack config drive with filesystem label `config-2`;
- the QEMU `fw_cfg` blob `opt/org.andyl/host-nix`; or
- native user-data on AWS, GCP, Azure, DigitalOcean, and OpenStack.

[Choose a delivery channel](host-nix.md#choose-a-delivery-channel) lists the
exact file and signature location for each transport and shows how to build an
`AOS-META` ISO or pass the QEMU blob. An AOS metadata ISO is more portable
across QEMU and physical installation tests than `fw_cfg`; attach it as a
CD-ROM for the first boot.

NoCloud user-data is not cloud-config. A JSON provisioning object is also not
accepted. The payload must evaluate as a Nix module.

Other clouds, bare metal, Hyper-V, VMware, and VirtualBox use image defaults
unless an offline metadata or config drive is attached. AOS does not infer an
unrecorded provider metadata protocol.

The [configuration guide](configuration.md) explains runtime activation; the
complete metadata lifecycle and storage recipe reference is in
[Understand and operate `host.nix`](host-nix.md).

## Trust policy

The default `platform` policy treats access to the platform's metadata channel
as configuration authority. Deployments that do not trust that transport can
build an image with `aos.config.evalAtBoot.trust = "signed"` and one or more
`aos.apm.configKeys` trust anchors; the detached signature then travels next
to `host.nix`. [Choose the trust
policy](host-nix.md#choose-the-trust-policy) covers key format, signing, and
failure behavior.

Signed mode requires a transport that carries a detached signature: AOS
metadata media, NoCloud, OpenStack config drive, QEMU `fw_cfg`, or an AWS
pointer with `sig_url`. Native GCP, Azure, DigitalOcean, and OpenStack metadata
do not currently carry one; use an offline config drive for signed provisioning
on those platforms.

## Verify first boot

After the system reaches `multi-user.target`:

```sh
systemctl is-system-running
systemctl --failed
findmnt /
findmnt /var
cat /etc/os-release
cat /var/lib/aos-provisioning/audit.json
cat /var/lib/profiles/image/state.json
cat /var/lib/profiles/system/state.json
apm config status
```

`systemctl is-system-running` prints `running` when no unit has failed and
`degraded` when at least one has; `systemctl --failed` then lists them.
`audit.json` is the durable provisioning record.

If first boot stops before the target, inspect the units and state in
[Troubleshoot an AOS host](troubleshooting.md).

## Installation limits

- The stock disk carries `root-a` and `root-b`; durable image updates stage the
  inactive slot and its UKI, then rely on sd-boot boot counting to accept or
  fall back from the candidate.
- Secure Boot plus dm-verity images also carry signed, uncounted recovery A and
  B entries. The image build exposes the matching fixed-layout removable-media
  payload as `system.build.recoveryBundle`; retain it with the deployed release
  if offline inactive-slot restoration is part of the recovery plan.
- General `host.nix` settings are activated as numbered configuration
  generations after the first-boot storage phase. Keep an image-baked or
  out-of-band recovery path when moving network and access policy to runtime.
- Secure-boot and measured-boot variants in this repository use test keys.
  They are validation fixtures, not production enrollment artifacts.
- MD arrays declared in `host.nix` protect persistent state only; the image
  slots and EFI System Partition are not mirrored, and the recovery console
  does not yet open a mirrored `/var`.
- Limits that apply when defining an image, such as initrd firmware, NVIDIA
  support, the ZFS installer topology, and installer-media signing, are in
  [Image definition limits](../../maintainers/system-images.md#image-definition-limits).
- `apm image download PACKAGE --system --format raw --output FILE` downloads an image
  published in a system registry. It does not write a disk or provision a
  machine.
