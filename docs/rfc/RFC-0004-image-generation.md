# RFC-0004: Golden Image Generation Pipeline

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS golden images are produced by GNU Guix's image generation infrastructure from declarative operating-system definitions. This RFC specifies the image build pipeline, role-based image variants, image signing with minisign, image manifests, content-addressed store path management, and reproducibility verification.

## Motivation

Server fleet management requires consistent, verifiable, and reproducible system images. Traditional approaches (installing from package repositories, configuring with Ansible) produce non-deterministic results that vary based on timing, mirror state, and configuration drift. ANDYL OS eliminates this by producing sealed golden images from declarative definitions, where every byte in the image is a deterministic function of the input definitions. Image signing and manifests enable end-to-end verification from build to deployment.

## Design

### 1. Build Foundation: `guix system image`

ANDYL OS images are produced by `guix system image`, which takes an operating-system declaration in Guile Scheme and produces a bootable disk image. The build proceeds in four stages:

1. **Dependency resolution:** Guix resolves the full transitive closure of packages and services declared in the operating-system definition.
2. **Derivation computation:** Each package becomes a derivation (content-addressed build recipe). Identical inputs always produce the same `/gnu/store/hash-name` output path.
3. **Build execution:** The Guix daemon builds or substitutes all derivations, producing store paths in `/gnu/store`.
4. **Image assembly:** The store closure is packed into a disk image with the specified partition layout, boot loader configuration, and system profile symlinks.

```bash
# Build the base image
guix system image --image-type=disk-image \
  --image-size=8G \
  --no-substitutes \
  andyl-os/images/base.scm

# Build a role-specific image
guix system image --image-type=disk-image \
  --image-size=16G \
  --no-substitutes \
  andyl-os/images/k8s-worker.scm
```

### 2. Operating-System Declaration

Each image starts from a Guile Scheme operating-system declaration:

```scheme
;; andyl-os/images/base.scm
(use-modules (gnu)
             (gnu system)
             (gnu image)
             (gnu system image)
             (andyl-os packages)
             (andyl-os services))

(define andyl-os-base-image-type
  (image
   (format 'disk-image)
   (operating-system andyl-os-base)
   (partitions
    (list
     (partition
      (size (* 512 (expt 2 20)))   ;; 512 MiB ESP
      (label "ESP")
      (file-system "vfat")
      (flags '(esp))
      (initializer (gexp (initialize-efi-partition #$output))))
     (partition
      (size 'guess)                ;; fill remaining
      (label "ANDYL-ROOT")
      (file-system "ext4")
      (flags '(boot))
      (initializer
       (gexp (initialize-root-partition #$output
              #:references-graphs '("closure")))))))))
```

### 3. Disk Image Format and Partition Layout

The output is a raw disk image with a GPT partition table. The golden
image uses **ext4 for the root filesystem**. ext4 is the simplest and
most portable choice for the immutable root: it works everywhere (bare
metal, VMs, cloud) with no special kernel modules at imaging time.

ZFS is not part of the golden image itself. ZFS pools and datasets for
mutable runtime state (`/var`, container data, logs) are created by
Ignition on first boot, using remaining unpartitioned disk space. See
RFC-0006 for Ignition-driven ZFS provisioning details.

```
+--------------------------------------------------+
| GPT Header                                       |
+--------------------------------------------------+
| Partition 1: ESP (EFI System Partition)          |
|   - FAT32, 512 MiB - 1 GiB                      |
|   - systemd-boot EFI binary                     |
|   - Boot loader entries (one per generation)     |
|   - UKI or kernel + initrd                       |
+--------------------------------------------------+
| Partition 2: Root filesystem (ANDYL-ROOT)        |
|   - ext4, sized to fit store closure             |
|   - /gnu/store (read-only at runtime)            |
|   - Generation symlinks                          |
|   - Immutable -- mounted read-only at runtime    |
+--------------------------------------------------+
| Remaining disk space: unpartitioned              |
|   - Left free for Ignition to create ZFS pool(s) |
|   - ZFS datasets for /var, data, logs, etc.      |
+--------------------------------------------------+
```

**Key design decision:** The golden image partition is ext4 (immutable,
read-only at runtime). All mutable state lives on ZFS datasets created
by Ignition after the image is written to disk. This separation keeps
the golden image simple and portable while giving runtime data the
benefits of ZFS (checksumming, compression, snapshots).

**ESP sizing:** With a retention policy of 5 generations, we need space for 5 kernels (~12 MiB each) and 5 initrds (~30-80 MiB each): approximately 460 MiB. A 1 GiB ESP provides comfortable headroom.

### 4. Content-Addressed Store Paths

Every artifact in the image lives under `/gnu/store` and is named by its content hash:

```
/gnu/store/abc123...-linux-6.12.1
/gnu/store/def456...-containerd-1.7.24
/gnu/store/xyz789...-andyl-os-system
```

The hash is computed from all build inputs (source, build script, dependencies recursively, environment variables, build system type). This provides:

- **Deduplication:** Identical content is stored once regardless of how many packages or generations reference it.
- **Deterministic builds:** Same inputs produce the same store path hash.
- **Safe concurrent deployment:** New store paths can be added while the old generation runs.
- **Efficient diff computation:** Comparing two generations reduces to comparing two sets of store path hashes.

The final system profile is a single store path containing a directory tree of symlinks:

```
/gnu/store/xyz789...-andyl-os-system/
  bin/                  -> symlinks to all package binaries
  etc/                  -> system configuration templates
  lib/
    modules/            -> kernel modules
    firmware/            -> device firmware
    systemd/system/      -> systemd unit files
  boot/
    vmlinuz             -> kernel image
    initrd              -> initial ramdisk
  manifest              -> JSON manifest of all paths
```

### 5. Role-Based Image Variants

Each server role extends the base operating-system declaration with role-specific packages and services:

```
andyl-os-base (common to all roles)
  |
  +-- andyl-os-k8s-worker
  |     Adds: containerd, kubelet, CNI plugins, runc, crictl
  |     Services: kubelet.service, containerd.service
  |
  +-- andyl-os-k8s-control-plane
  |     Adds: etcd, kube-apiserver, kube-scheduler, kube-controller-manager
  |     Services: etcd.service, kube-apiserver.service, ...
  |
  +-- andyl-os-database
  |     Adds: postgresql, pgbouncer, wal-g
  |     Services: postgresql.service, pgbouncer.service
  |
  +-- andyl-os-edge
        Adds: envoy, haproxy, certbot, coredns
        Services: envoy.service, certbot.timer
```

```scheme
;; andyl-os/images/k8s-worker.scm
(define andyl-os-k8s-worker
  (operating-system
   (inherit andyl-os-base)
   (host-name "k8s-worker")       ;; overridden by Ignition
   (packages
    (append
     (list containerd runc kubectl kubelet cni-plugins
           crictl nerdctl iptables-nft ethtool socat conntrack-tools)
     (operating-system-packages andyl-os-base)))
   (services
    (append
     (list (service kubelet-service-type kubelet-config)
           (service containerd-service-type containerd-config))
     (operating-system-user-services andyl-os-base)))))
```

**Base image contents (common to all roles):**

- systemd (init, journald, networkd, resolved, timesyncd)
- systemd-boot (boot loader)
- Linux kernel (ANDYL OS kernel config)
- GNU coreutils, bash, grep, sed, findutils
- openssh-server
- chrony (NTP)
- node_exporter (Prometheus metrics)
- andyl-os-agent (update/health-check daemon)
- ca-certificates
- Ignition (first-boot configuration)

### 6. Image Signing with minisign

Every image is signed with an Ed25519 key before distribution. The signature covers the full disk image.

```bash
# Generate signing keypair (done once, stored in HSM or secrets manager)
minisign -G -s andyl-os-sign.key -p andyl-os-sign.pub

# Sign the image
minisign -Sm andyl-os-base-gen42.img -s andyl-os-sign.key
# Produces: andyl-os-base-gen42.img.minisig

# Verify the image
minisign -Vm andyl-os-base-gen42.img -p andyl-os-sign.pub
```

**Why minisign over GPG:**
- Simpler trust model (single key, no web of trust)
- Smaller signatures (~200 bytes)
- Faster verification
- No key management complexity (no keyrings, no trust databases)

The public key is baked into every ANDYL OS image at `/etc/andyl-os/update-signing-key.pub` so that update NAR archives can be verified without external infrastructure.

### 7. Image Manifest

Each image ships with a manifest file listing every store path, its hash, and its size. The manifest itself is signed.

```json
{
  "version": 1,
  "image_id": "andyl-os-base-gen42",
  "build_timestamp": "2026-01-15T14:30:00Z",
  "guix_commit": "a1b2c3d4e5f6...",
  "andyl_channel_commit": "f6e5d4c3b2a1...",
  "system_profile": "/gnu/store/xyz789...-andyl-os-system",
  "role": "k8s-worker",
  "kernel_version": "6.12.10",
  "store_paths": [
    {
      "path": "/gnu/store/abc123...-linux-6.12.10",
      "nar_hash": "sha256:deadbeef...",
      "nar_size": 134217728,
      "references": [
        "/gnu/store/mod111...-linux-module-a",
        "/gnu/store/mod222...-linux-module-b"
      ]
    },
    {
      "path": "/gnu/store/def456...-containerd-1.7.24",
      "nar_hash": "sha256:cafebabe...",
      "nar_size": 52428800,
      "references": [
        "/gnu/store/runc99...-runc-1.2.3"
      ]
    }
  ],
  "total_store_size": 2147483648,
  "total_paths": 847,
  "signature": "base64-encoded-minisign-signature"
}
```

The manifest enables:
- **Diff computation:** Comparing two generations is a set difference on store path hashes.
- **Integrity verification:** Verify that all store paths arrived intact after transport.
- **Inventory tracking:** Know exactly what is deployed on every machine.
- **Update optimization:** Download only new store paths (those not in the current manifest).

### 8. Reproducibility Verification

Because Guix builds are functionally pure, we can verify reproducibility:

```bash
# Build the same image on two independent machines
machine-a$ guix system image ... > image-a.img
machine-b$ guix system image ... > image-b.img

# Compare store path hashes (not raw image bytes, since UUIDs differ)
machine-a$ guix system describe --format=json ... > manifest-a.json
machine-b$ guix system describe --format=json ... > manifest-b.json

diff manifest-a.json manifest-b.json
# Should be empty if builds are reproducible
```

**CI reproducibility check on every release build:**

1. Build the image twice on different builders.
2. Extract the store closure from each.
3. Compare the set of `(path, nar-hash)` tuples.
4. Fail the release if any divergence is found.

```bash
# Build and compare (via justfile)
just check-reproducibility k8s-worker
```

Individual packages can also be checked:

```bash
guix build --no-substitutes --check andyl-zlib
# If the build is reproducible, this succeeds silently
# If not, it shows which output files differ

guix challenge andyl-zlib
# Compares local build against known-good builds
```

### 9. Image Build Pipeline in CI

```
Channel Commit
    |
    v
CI: Lint package definitions
    |
    v
CI: Build packages (guix build, incremental via store cache)
    |
    v
CI: Push to binary cache (guix publish)
    |
    v
CI: Build images (guix system image, matrix over roles)
    |
    v
CI: Record image hash (sha256sum)
    |
    v
CI: Sign image (minisign)
    |
    v
CI: Generate manifest (JSON with all store paths)
    |
    v
CI: Integration test (boot in QEMU, run health checks)
    |
    v
CI: Publish to artifact storage (S3/CDN)
```

### 10. Image Size Estimates

| Component | Approximate Size |
|-----------|-----------------|
| Base OS (systemd, coreutils, networking) | ~500 MB |
| Kernel + modules + firmware | ~150 MB |
| K8s worker additions (containerd, kubelet, CNI) | ~200 MB |
| Control plane additions (etcd, API server) | ~300 MB |
| Database additions (PostgreSQL) | ~150 MB |
| Total base image (compressed qcow2) | ~800 MB - 1.2 GB |
| Total k8s-worker image (compressed qcow2) | ~1.0 - 1.5 GB |

The golden image root partition (ext4) is not compressed at the filesystem
level. ZFS compression (zstd-3) applies to runtime mutable data on the
ZFS `datapool` datasets (`/var`, container data, logs), typically achieving
1.5-2x compression on those workloads.

## Alternatives Considered

**Container images (OCI) as the deployment unit:** Rejected because container images do not boot directly on bare metal. ANDYL OS needs to manage the full boot path including kernel, initrd, and firmware. Container images are appropriate for workloads running ON ANDYL OS, not for the OS itself.

**A/B partition scheme (like ChromeOS/Android):** Considered but rejected in favor of the Guix generational model. A/B partitions waste 50% of disk space and limit rollback to a single previous version. Guix generations can keep N previous versions with shared store paths.

**Raw image deployment without manifests:** Rejected because manifests enable efficient delta updates (NAR-based diffs) and integrity verification without downloading the full image.

**GPG for image signing:** Rejected in favor of minisign for its simpler trust model and smaller signatures.

## Security Considerations

- **Image signing** with Ed25519 (minisign) ensures only authorized build infrastructure can produce deployable images.
- **Manifest signing** allows verification of individual store paths without re-hashing the entire image.
- **Content-addressed store paths** make it impossible to substitute a tampered package without changing the hash, which would break all references.
- **Reproducibility verification** detects non-determinism that could indicate supply chain compromise.
- **The signing private key** must be stored in an HSM or secrets manager. Only CI infrastructure should have access. Key rotation requires re-signing all cached artifacts and distributing the new public key.

## Compatibility

- **Guix build infrastructure:** Images are produced by `guix system image`, which requires a running `guix-daemon` on the build machine.
- **QEMU:** Images can be tested in QEMU with virtio drivers. The `qcow2` format is used for testing; raw images are used for production deployment.
- **Cloud providers:** Images can be converted to provider-specific formats (AMI for AWS, raw for GCP, VHD for Azure) using `qemu-img convert`.
- **Bare metal:** Raw images can be written to disk with `dd` or deployed via PXE netboot.

## Open Questions

1. **NAR format vs. custom archive:** Should we use Guix's NAR format directly for update transport, or define a simpler custom format?
2. **Delta updates:** Beyond store-path-level diffs, should we support binary delta compression (e.g., casync, zchunk) for large store paths that changed slightly?
3. **Image format standardization:** Should we standardize on raw, qcow2, or UKI as the primary image format?
4. **Multi-architecture images:** When we add aarch64 support, should we build separate images or a fat image?

## References

- GNU Guix System Images: https://guix.gnu.org/manual/en/html_node/System-Images.html
- minisign: https://jedisct1.github.io/minisign/
- NAR Archive Format: https://nixos.org/guides/nix-pills/nix-store-paths.html
- QEMU Disk Image Formats: https://www.qemu.org/docs/master/system/images.html
- Content-Addressable Storage: https://en.wikipedia.org/wiki/Content-addressable_storage
