# Deploy AOS in production

A production deployment promotes the published AOS golden image through boot,
application, and recovery gates before importing or writing it to a target.

This guide describes the common workflow. Platform-specific image import,
network, and disk-writing commands remain the responsibility of the deployment
system because they can replace infrastructure and data.

## Pin the release artifact

Download the image format published for the target and verify its release
checksum or signature. Record the release, image checksum, and
`image-info.json`; do not identify an image only by a mutable object-storage
name.

The public golden image is not yet distributed during the current early
preview. AOS Hub is the planned image catalog and download path. Release
integrators producing the image today should use the
[maintainer guide](../../maintainers/) and hand the resulting immutable
artifact to this deployment workflow.

## Size the target before first boot

The target needs trailing unallocated space for swap, `/var`, the provisioning
marker, and partition alignment. The stock policy needs more than 6 GiB beyond
the built image; fleet tests use a 16 GiB disk.

When enlarging a raw image, relocate its backup GPT header before first boot:

```sh
cp /path/to/downloaded-aos.img acme-server.img
chmod u+w acme-server.img
truncate -s 16G acme-server.img

sgdisk -e acme-server.img
```

Increasing only the virtual disk's visible size is not sufficient when the
backup GPT header remains at the old end. Prepare the raw image before
conversion or use platform tooling that both expands the disk and repairs GPT.

## Supply first-boot policy

Use a literal Nix module as `host.nix`. Storage provisioning is the currently
supported runtime surface:

```nix
{
  aos.provisioning.storage.partitions.var.sizeMin = "8G";
}
```

Choose a transport supported by the target: an `aos-metadata` drive, NoCloud
`cidata`, OpenStack config drive, QEMU `fw_cfg`, or a supported native cloud
user-data channel. Use signed trust only with a transport that also carries the
detached signature.

Networking, users, access, services, and packages required to reach the host
must currently be included in the golden image by its release integrator.
General runtime `host.nix` activation is not complete.

## Gate the image in a VM

Before importing an image, boot the exact artifact under UEFI with a writable
copy, the intended metadata, and a representative network. Maintainers can use
the [source-build tutorial](../../maintainers/source-build-quickstart.md) to
qualify the image-production path; deployment gates must test the published
artifact itself.

The gate should verify:

- UEFI boot reaches `multi-user.target`;
- the expected root and `/var` filesystems are mounted;
- storage provisioning records the accepted plan;
- the intended SSH identity can connect;
- DNS, time, registry TLS, and package synchronization work;
- required services and application health checks pass;
- a reboot returns to the same healthy state.

Do not modify the guest image to make the test pass. Feed it the same external
metadata and network conditions the deployment will use.

## Import a virtual image

Use the format native to the platform:

| Output | Typical targets |
| --- | --- |
| `image-qcow2` | QEMU/KVM, OpenStack, Proxmox |
| `image-vmdk` | VMware and vSphere |
| `image-vhd` | Hyper-V and VHD conversion pipelines |
| `image-raw` | Bare metal and custom conversion pipelines |

The dynamic VHD output is a disk format, not a guarantee that every cloud's
image-import requirements are satisfied. Provider import policy may require
additional conversion, account permissions, firmware selection, or image
metadata.

The native metadata fetchers for Hetzner, Vultr, Scaleway, and Oracle Cloud are
not implemented. Use an offline metadata drive on those platforms. Signed
provisioning on GCP, Azure, DigitalOcean, and native OpenStack metadata also
requires an offline transport that carries a detached signature.

## Write bare-metal media

Resolve the target by a persistent `/dev/disk/by-id/...` path, verify its model,
serial, size, and mount state, then use the organization's audited imaging
tool. Writing the raw image replaces the partition table and data.

AOS intentionally has no `aos install` command that performs this destructive
copy. After writing, relocate the target disk's backup GPT header before first
boot. The [installation guide](installation.md) contains the read-only target
inspection and GPT repair commands.

For fleets, prefer out-of-band imaging or PXE infrastructure that records the
machine identity, image digest, result, and operator or automation identity.

## Promote through rings

Treat the image and its initial package/registry policy as one release input.
A practical promotion sequence is:

1. disposable VM boot;
2. hardware or hypervisor qualification;
3. one recoverable canary host;
4. a small production ring;
5. bounded fleet rings;
6. general availability.

At every ring, compare the observed image, provisioning audit, package
generation, service health, and application signals with the deployment
record. Stop on unexplained drift.

Reimage hosts when a release changes the kernel or UKI. The current APM system
upgrade path is production-safe only for userspace releases whose boot
artifacts remain unchanged.
