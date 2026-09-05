# Install an AOS image

AOS is installed from a signed UEFI disk image published by an AOS Hub
registry. There is no `aos install` command that writes a disk: installation
means downloading a verified image, importing it into a hypervisor, or writing
it with the target platform's normal imaging tool.

Before enrollment or first boot, read [Use Secure Boot and verify package
trust](secure-boot.md) for the full chain, production-key requirements, and the
boundary between image and package verification.

## Discover and download an image

Open the registry's **Images** page at `https://HUB/REGISTRY/-/images`, or use
the CLI. Select a target when possible; the Hub resolves it to a compatible
disk encoding and an authenticated binary-cache identity:

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

`download` resumes the image NAR from the registry's CDN cache, verifies its
signed NAR identity, extracts the single regular-file output, and verifies the
signed disk byte size and SHA-256 before placing the final file. Omit
`--output` to use the useful filename from signed release metadata. Use
`--no-resume` to restart a partial transfer. Existing final files are never
overwritten.

Public registries need no credentials. For a private registry, set
`AOS_TOKEN` or pass `--token`; use HTTPS whenever a bearer token is present:

```sh
AOS_TOKEN=REPLACE_WITH_TOKEN aos image list \
  --hub https://HUB \
  --registry PRIVATE_REGISTRY \
  --channel stable
```

To boot a downloaded raw or QCOW2 image locally without modifying the verified
artifact, install the opt-in `pkgs.aos-vm` host package and use its packaged
QEMU workflow:

```sh
nix-build -A pkgs.aos-vm -o result-aos-vm
./result-aos-vm/bin/aos vm run ./aos-server.qcow2 \
  --host-config ./host.nix \
  --disk-size-gib 16 \
  --ssh-port 2222
```

The command prepares a persistent writable disk and UEFI variable store, fixes
the enlarged disk's backup GPT, and reports the exact launch configuration
before starting QEMU. Use `--dry-run` to inspect the plan. The default chooses
KVM when accessible and warns before falling back to TCG emulation; use
`--accel kvm` when the absence of hardware acceleration should be an error.

Use `aos --json image list` or `aos --json image show` for automation. The
record includes the store and NAR identity, ordered cache URLs, format, target
compatibility, media type, compression, exact size, SHA-256, release-signature
and boot verification states, the associated integrity-bound
`image-info.json`, and,
for Secure Boot plus dm-verity images, paired recovery UKI and authenticated
recovery-bundle metadata.

## Choose an image format

The same golden system may be published in several disk encodings:

| Format | Typical target |
| --- | --- | --- |
| Zstd-compressed raw GPT disk | Bare metal, custom image pipelines, QEMU |
| QCOW2 | QEMU/KVM, OpenStack, Proxmox |
| VMDK | VMware and vSphere |
| Dynamic VHD | Hyper-V and VHD-based conversion pipelines |

Use the format published for the target. Raw images are delivered as
`aos-<system>.img.zst`; fixed partition headroom and the empty inactive slot
therefore add almost no transfer cost. The CLI verifies the compressed object's
signed size and SHA-256. Publication also verifies that decompression produces
the exact `virtualSizeBytes` and `logicalDiskSha256` recorded in
`image-info.json`. Retain that metadata with the deployment record. UEFI
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

The repository intentionally does not wrap this destructive step in an AOS
command. Use the deployment system's normal image-import or disk-imaging
workflow, with its audit and confirmation controls.

## Install redundant encrypted ZFS storage

The reusable `aos.profiles.bareMetalZfs` profile provides a different
bare-metal layout. Every selected disk receives an independently bootable ESP
sized from the golden image's artifact contract and a ZFS member. Adjacent
members form mirrors, and the mirrors are striped by the pool, so two disks
produce a mirror and four or more disks produce RAID10-style storage. The
encrypted pool contains mutable datasets and contract-sized zvols for both
immutable EROFS roots and both dm-verity hash trees. There is no LUKS layer
below ZFS.

Create a deployment system module from the production server baseline, enable
dm-verity and measured boot, enable the profile, list one ESP identity per
target disk, and supply deployment-owned Secure Boot and PCR-policy keys. Do
not import the checked-in Secure Boot or measured-boot system fixtures: those
also select test-only packages and keys. For example:

```nix
{
  imports = [./systems/server.nix];

  aos.security.verity.enable = true;

  aos.profiles.bareMetalZfs = {
    enable = true;
    espDevices = [
      "/dev/disk/by-partlabel/aos-esp-1"
      "/dev/disk/by-partlabel/aos-esp-2"
      "/dev/disk/by-partlabel/aos-esp-3"
      "/dev/disk/by-partlabel/aos-esp-4"
    ];
    nvidiaOpen = true;
    serverManagement = true;
  };

  # These values must be Nix path values from a private deployment input or
  # an isolated signing builder, not untracked absolute-path strings.
  aos.boot.secureBoot = {
    enable = true;
    dbKey = toString ./private-signing/db.key;
    dbCert = toString ./private-signing/db.crt;
    enrollAuthDir = toString ./public-enrollment;
    measuredBoot = {
      enable = true;
      pcrPrivateKey = toString ./private-signing/pcr.key;
      pcrPublicKey = toString ./public-signing/pcr.pem;
    };
  };
}
```

The private deployment input must be available to a controlled build sandbox;
these are Nix path values so their contents are copied into that builder's
store. Use a signing builder whose store, logs, and substituter outputs are not
shared, then destroy its private-key-bearing store paths after the build. This
repository does not yet provide an offline-signing protocol or key-custody
service. Never commit or publish the private input. The repository's
measured-boot systems are test fixtures with public keys; do not install them
on a real machine.

Build the module's `system.build.installBundle` output on x86 Linux. Run the
bundle's `bin/aos-install-zfs` from a trusted AOS recovery environment that has the exact ZFS
kernel module loaded, the deployment Secure Boot keys enrolled, Secure Boot
enforcing, and a working TPM2. The command is intentionally destructive and
accepts only stable whole-disk identities with no existing partition table:

```sh
/path/to/install-bundle/bin/aos-install-zfs \
  --confirm ERASE-AND-INSTALL \
  --recovery-key-output /recovery-media/zfs-recovery.key \
  --disk /dev/disk/by-id/REPLACE_WITH_DISK_1 \
  --disk /dev/disk/by-id/REPLACE_WITH_DISK_2 \
  --disk /dev/disk/by-id/REPLACE_WITH_DISK_3 \
  --disk /dev/disk/by-id/REPLACE_WITH_DISK_4
```

The number of `--disk` arguments must equal the configured ESP count and must
be even. Before the first destructive write, the installer rejects duplicate,
mounted, partitioned, or kernel-name-only disks; an existing or relative
recovery output; a topology mismatch; and a non-enforcing Secure Boot state.
It creates native AES-256-GCM encryption, verifies the root payloads fit their
zvol capacities, seals the pool key to the configured PCR policy, copies the
sealed credential and boot artifacts to every ESP, and exports the pool.

Move the recovery key off the installation environment before rebooting. Test
both unattended TPM unlock and recovery-key import, then test booting through
each firmware-visible ESP and surviving one failed mirror member before
placing data on the system.

Kernel lockdown is a separate opt-in policy. If enabled, the deployment must
also sign both the ZFS and NVIDIA external modules with a key trusted by the
kernel; the bare-metal profile does not generate or retain that private key.

## Supply first-boot metadata

AOS accepts a literal `host.nix` through the following transports:

| Platform | Transport and payload |
| --- | --- |
| AOS metadata drive | Filesystem label `aos-metadata`, with `/host.nix`; optional `/host.nix.sig` and `/facts.json` |
| NoCloud | Filesystem label `cidata`; `/user-data` contains literal Nix, with optional `/user-data.sig` |
| OpenStack config drive | Filesystem label `config-2`; `openstack/latest/user_data` contains literal Nix |
| QEMU | `fw_cfg` blob `opt/org.andyl/host-nix`, with optional `opt/org.andyl/host-nix.sig` |
| AWS | Native user-data, as literal Nix or a content-pinned pointer document |
| GCP, Azure, DigitalOcean, OpenStack | Native user-data as literal Nix |

NoCloud user-data is not cloud-config. A JSON provisioning object is also not
accepted. The payload must evaluate as a Nix module.

For QEMU, the direct channel is:

```sh
-fw_cfg name=opt/org.andyl/host-nix,file=host.nix
```

An AOS metadata ISO is more portable across QEMU and physical installation
tests:

```sh
mkdir -p metadata
cp host.nix metadata/host.nix
xorriso -as mkisofs \
  -V aos-metadata \
  -o metadata.iso \
  metadata
```

Attach `metadata.iso` as a CD-ROM for the first boot. The
[configuration guide](configuration.md) explains runtime activation;
the complete metadata lifecycle and storage recipe reference is in
[Understand and operate `host.nix`](host-nix.md).

The native network metadata agents support AWS IMDSv2, GCP, Azure,
DigitalOcean, and OpenStack. Other clouds, bare metal, Hyper-V, VMware, and
VirtualBox use image defaults unless an offline metadata or config drive is
attached. AOS does not infer an unrecorded provider metadata protocol.

## Trust policy

The default `platform` policy treats access to the platform's metadata channel
as configuration authority. Deployments that do not trust that transport can
build an image with `aos.config.evalAtBoot.trust = "signed"` and one or more
`aos.apm.configKeys` trust anchors. When a `host.nix` is supplied in signed
mode, a missing key, missing signature, or invalid signature rejects that
input. With no operator input, AOS provisions the image's fallback storage
defaults.

Trust anchors belong in the image definition. The detached signature travels
next to `host.nix` as described above.

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
cat /run/aos/activation.json
```

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
- The ZFS installer supports mirrored pairs striped into RAID10-style pools.
  RAID0-only topology is intentionally not exposed because it cannot satisfy
  the redundant-storage contract.
- The initrd carries a focused firmware subset for supported pre-root server
  storage and network adapters, not the general runtime bundle. Image
  definitions for other hardware must add the required firmware package to
  `aos.boot.initrd.firmwarePackages`; runtime firmware remains available after
  the immutable root is mounted.
- NVIDIA support in this repository stops at open kernel modules and matching
  GSP firmware. CUDA, OpenGL, Vulkan, management utilities, and other matching
  proprietary userspace components must be supplied separately.
- `apm install PACKAGE --system --image raw --output FILE` downloads an image
  published in a system registry. It does not write a disk or provision a
  machine.
