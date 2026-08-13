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

The integrity-bound `image-info.json` records the image's declared artifact
budgets and exact GPT layout. Use that layout as the immutable-storage contract
rather than deriving slot sizes from the current compressed payload. The target
also needs trailing unallocated space for swap, `/var`, the provisioning marker,
and partition alignment. The stock policy needs more than 6 GiB beyond the built
image; fleet tests use a 16 GiB disk.

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

Use a literal Nix module as `host.nix`. Storage is projected and committed in
the initrd; general machine policy is evaluated and activated in stage 2:

```nix
{
  aos.provisioning.storage.partitions.var.sizeMin = "8G";
}
```

Choose a transport supported by the target: an `aos-metadata` drive, NoCloud
`cidata`, OpenStack config drive, QEMU `fw_cfg`, or a supported native cloud
user-data channel. Use signed trust only with a transport that also carries the
detached signature.

Stage 2 resolves authenticated package configuration, materializes an EROFS
`/etc` lower, and commits a numbered configuration generation atomically. Keep
an image-baked or out-of-band recovery identity while qualifying runtime
network and access changes.

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

Native user-data and facts are supported on AWS, GCP, Azure, DigitalOcean, and
OpenStack. Use an offline metadata drive for other platforms. Signed
provisioning on GCP, Azure, DigitalOcean, and native OpenStack metadata requires
an offline transport that carries a detached signature.

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

Exercise both durable A/B image rollback and configuration rollback before a
ring advances. A changed image is written to the inactive root slot with its
UKI; sd-boot boot counting falls back automatically when the candidate cannot
reach the configuration-commit gate. A successful boot re-evaluates the host
configuration against the new image ABI before blessing it.
