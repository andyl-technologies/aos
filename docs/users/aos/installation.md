# Install an AOS image

AOS is installed from one golden x86-64 UEFI disk image. There is no `aos
install` command that writes a disk: installation means importing the image
into a hypervisor or writing it with the target platform's normal imaging
tool.

AOS is currently an early preview and the public system image is not published
yet. AOS Hub will provide the image catalog and downloads; it does not expose
that surface today. Do not treat a source build as the normal installation
path. Maintainers and release integrators can use the
[source-build guide](../../maintainers/) until public image distribution is
available.

## Choose an image format

The same golden system may be published in several disk encodings:

| Format | Typical target |
| --- | --- | --- |
| Raw GPT disk | Bare metal, custom image pipelines, QEMU |
| QCOW2 | QEMU/KVM, OpenStack, Proxmox |
| VMDK | VMware and vSphere |
| Dynamic VHD | Hyper-V and VHD-based conversion pipelines |

Use the format published for the target. Verify the release checksum or
signature and retain its `image-info.json` with the deployment record. UEFI
firmware is required; do not pass a separate kernel or initrd.

## Size the target

The build output is sized tightly around the EFI System Partition and
immutable `root-a`/`root-b` slots. The target must provide trailing unallocated
space for first-boot state:

- `swap`: 2 GiB by default;
- `/var`: 4 GiB minimum and grows to consume remaining space.

Allow more than 6 GiB beyond the image itself: the fixed provisioning marker
and partition alignment need space in addition to the 2 GiB swap and 4 GiB
`/var` minimum. The fleet tests use 16 GiB disks.
If a raw file is enlarged before boot, relocate its backup GPT header after
resizing:

```sh
cp /path/to/downloaded-aos.img aos-server.img
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

After the operator has confirmed the target, a typical imaging tool can copy
the downloaded raw image to that device and flush it. Relocate the GPT backup header
on the target before first boot:

```sh
sudo sgdisk -e /dev/disk/by-id/REPLACE_WITH_TARGET
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
- General `host.nix` settings are activated as numbered configuration
  generations after the first-boot storage phase. Keep an image-baked or
  out-of-band recovery path when moving network and access policy to runtime.
- Secure-boot and measured-boot variants in this repository use test keys.
  They are validation fixtures, not production enrollment artifacts.
- `apm install PACKAGE --system --image raw --output FILE` downloads an image
  published in a system registry. It does not write a disk or provision a
  machine.
