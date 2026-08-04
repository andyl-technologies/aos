# Install an AOS image

AOS produces complete UEFI disk images. There is no `aos install` command that
writes a disk: deployment means importing a virtual-disk image or writing the
raw image with tooling appropriate to the target platform.

## Choose an image format

Every discovered file under `systems/*.nix` becomes a system variant and four
flake outputs:

| Output suffix | Format | Typical target |
| --- | --- | --- |
| `image-raw` | Raw GPT disk | Bare metal, custom image pipelines, QEMU |
| `image-qcow2` | QCOW2 | QEMU/KVM, OpenStack, Proxmox |
| `image-vmdk` | VMDK | VMware and vSphere |
| `image-vhd` | Dynamic VHD | Hyper-V and VHD-based conversion pipelines |

For the stock server variant:

```sh
nix build .#server-image-raw
nix build .#server-image-qcow2
```

The raw result contains `aos-aos.img` and `image-info.json`. Converted results
contain the corresponding `aos-aos.qcow2`, `.vmdk`, or `.vhd` file.

The current bootable image workflow is supported on `x86_64-linux`. The short
flake commands above assume an `x86_64-linux` caller. From another system with
an x86 Linux remote builder, select the package set explicitly:

```sh
nix build .#packages.x86_64-linux.server-image-qcow2
```

UEFI firmware is required to boot the image; do not pass a separate kernel or
initrd.

## Size the target

The build output is sized tightly around the EFI System Partition and
immutable `root-a`. The target must provide trailing unallocated space for
first-boot state:

- `swap`: 2 GiB by default;
- `/var`: 4 GiB minimum and grows to consume remaining space.

Allow more than 6 GiB beyond the image itself: the fixed provisioning marker
and partition alignment need space in addition to the 2 GiB swap and 4 GiB
`/var` minimum. The fleet tests use 16 GiB disks.
If a raw file is enlarged before boot, relocate its backup GPT header after
resizing:

```sh
cp result/aos-aos.img aos-server.img
chmod u+w aos-server.img
truncate -s 16G aos-server.img

nix-build -A pkgs.gptfdisk -o result-aos-gptfdisk
./result-aos-gptfdisk/sbin/sgdisk -e aos-server.img
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

After the operator has confirmed the target, a typical imaging tool can copy
`result/aos-aos.img` to that device and flush it. Relocate the GPT backup header
on the target before first boot:

```sh
sudo ./result-aos-gptfdisk/sbin/sgdisk -e /dev/disk/by-id/REPLACE_WITH_TARGET
```

The repository intentionally does not wrap this destructive step in an AOS
command. Use the deployment system's normal image-import or disk-imaging
workflow, with its audit and confirmation controls.

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
nix-build -A pkgs.libisoburn -o result-aos-libisoburn
mkdir -p metadata
cp host.nix metadata/host.nix
./result-aos-libisoburn/bin/xorriso -as mkisofs \
  -V aos-metadata \
  -o metadata.iso \
  metadata
```

Attach `metadata.iso` as a CD-ROM for the first boot. The
[configuration guide](configuration.md) documents build-time customization;
the complete metadata lifecycle and storage recipe reference is in
[Understand and operate `host.nix`](host-nix.md).

The image detects Hetzner, Vultr, Scaleway, and Oracle Cloud, but their native
metadata fetchers are not implemented. Those platforms fail closed rather than
discarding supplied control-plane data. Bare metal, Hyper-V, VMware, and
VirtualBox use image defaults unless an offline metadata drive is attached.

## Trust policy

The default `platform` policy treats access to the platform's metadata channel
as configuration authority. Deployments that do not trust that transport can
build an image with `aos.config.evalAtBoot.trust = "signed"` and one or more
`aos.apm.configKeys` trust anchors. In signed mode, a missing key, missing
signature, or invalid signature prevents first-boot provisioning.

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
```

If first boot stops before the target, inspect the units and state in
[Troubleshoot an AOS host](troubleshooting.md).

## Installation limits

- The stock image does not create a `root-b` partition.
- General `host.nix` settings are evaluated but not activated as a live system
  generation. Bake access, networking, users, and services into the image.
- Secure-boot and measured-boot variants in this repository use test keys.
  They are validation fixtures, not production enrollment artifacts.
- `apm install PACKAGE --system --image raw --output FILE` downloads an image
  published in a system registry. It does not write a disk or provision a
  machine.
