# RFC-0004: Golden Image Generation Pipeline

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS golden images are produced by the `images/builder.nix` derivation from evaluated system configurations. This RFC specifies the image build pipeline, role-based image variants, image signing with minisign, image manifests, content-addressed store path management, and reproducibility verification. All images are built natively using `nix-build` -- no Docker is involved.

## Motivation

Server fleet management requires consistent, verifiable, and reproducible system images. Traditional approaches (installing from package repositories, configuring with Ansible) produce non-deterministic results that vary based on timing, mirror state, and configuration drift. ANDYL OS eliminates this by producing sealed golden images from declarative definitions, where every byte in the image is a deterministic function of the input definitions. Image signing and manifests enable end-to-end verification from build to deployment.

## Design

### 1. Build Foundation: `images/builder.nix`

ANDYL OS images are produced by the `buildAndylImage` derivation defined in `images/builder.nix`. The build proceeds as follows:

1. **Module evaluation:** `lib.evalModules` evaluates the system configuration for the selected variant (e.g., `systems/server.nix`), producing a complete system attrset.
2. **Closure computation:** The transitive store closure of the system toplevel is computed via `nix-store --query --requisites`.
3. **Image assembly:** The store closure is packed into a raw disk image with GPT partitions, systemd-boot on ESP, and the full Nix store on ext4 root.

```bash
# Build a system image
aos system image server

# Which wraps:
nix-build default.nix -A images.server -o output/aos-server.raw
```

### 2. System Configuration

Each image starts from a system variant defined in `systems/`. Variants compose modules:

```nix
# systems/server.nix
{ config, pkgs, lib, ... }:
{
  imports = [
    ./base.nix
    ../modules/security/selinux.nix
    ../modules/security/hardening.nix
    ../modules/security/firewall.nix
    ../modules/security/ssh.nix
    ../modules/security/audit.nix
    ../modules/services/update.nix
    ../modules/services/gc.nix
    ../modules/services/chrony.nix
  ];

  aos.system.variant = "server";
  aos.security.selinux.enable = true;
  # ...
}
```

### 3. Disk Image Format and Partition Layout

The output is a raw disk image with a GPT partition table. The image uses **ext4 for the root filesystem** -- simple and portable across bare metal, VMs, and cloud environments.

ZFS is not part of the golden image. ZFS pools and datasets for mutable runtime state (`/var`, container data, logs) are created by Ignition on first boot using remaining unpartitioned disk space. See RFC-0006.

```
+--------------------------------------------------+
| GPT Header                                       |
+--------------------------------------------------+
| Partition 1: ESP (EFI System Partition)          |
|   - FAT32, 1 GiB                                 |
|   - systemd-boot EFI binary                     |
|   - Boot loader entries (one per generation)     |
|   - Kernel + initrd                               |
+--------------------------------------------------+
| Partition 2: Root filesystem (aos-root)           |
|   - ext4, sized per variant                       |
|   - /nix/store (read-only at runtime)             |
|   - System symlinks                               |
|   - Immutable -- mounted read-only at runtime    |
+--------------------------------------------------+
| Remaining disk space: unpartitioned              |
|   - Left free for Ignition to create ZFS pool(s) |
|   - ZFS datasets for /var, data, logs, etc.      |
+--------------------------------------------------+
```

The image builder (`images/builder.nix`) creates this layout:

```nix
# From images/builder.nix — partition creation
sfdisk image.raw <<PTABLE
label: gpt
size=${espSize}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="ESP"
size=${rootSize}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="Root"
PTABLE
```

**ESP sizing:** With a retention policy of 5 generations, 1 GiB ESP provides comfortable headroom for kernels and initrds.

### 4. Content-Addressed Store Paths

Every artifact in the image lives under `/nix/store` and is named by its content hash:

```
/nix/store/abc123...-linux-6.12.11
/nix/store/def456...-containerd-1.7.24
/nix/store/xyz789...-aos-system
```

The hash is computed from all build inputs. This provides:

- **Deduplication:** Identical content is stored once regardless of how many packages or generations reference it.
- **Deterministic builds:** Same inputs produce the same store path hash.
- **Safe concurrent deployment:** New store paths can be added while the old generation runs.
- **Efficient diff computation:** Comparing two generations reduces to comparing two sets of store path hashes.

### 5. Role-Based Image Variants

Each server role extends the base system with role-specific modules. Variants are defined in `systems/` and their images in `images/`:

```
systems/base.nix                  Minimal bootable system
  |
  +-- systems/server.nix          + SSH, firewall, chrony, SELinux enforcing
  |     |
  |     +-- systems/k8s-worker.nix        + containerd, kubelet, CNI
  |     |     |
  |     |     +-- systems/k8s-control-plane.nix  + kubeadm, control plane firewall
```

Image variants set partition sizes via `images/<variant>.nix`:
- Base/server: 16 GiB total (1 GiB ESP + 8 GiB root + 7 GiB ZFS)
- K8s variants: 32 GiB total (1 GiB ESP + 12 GiB root + 19 GiB ZFS)

**Base image contents (common to all roles):**

- systemd (init, journald, networkd, tmpfiles, sysusers)
- systemd-boot (boot loader)
- Linux kernel with AOS config fragments
- GNU coreutils, bash, grep, sed, findutils
- openssh-server
- chrony (NTP)
- node_exporter (Prometheus metrics)
- aos-update (update/health-check agent)
- ca-certificates
- Ignition (first-boot configuration)

### 6. Image Signing with minisign

Every image is signed with an Ed25519 key before distribution. Signing is implemented as a Nix derivation in `deploy/sign.nix`.

```bash
# Generate signing keypair (done once)
minisign -G -s aos-sign.key -p aos-sign.pub

# Sign via the deploy/sign.nix derivation
nix-build -A signedBundle --arg signingKey ./aos-sign.key
```

**Why minisign over GPG:**
- Simpler trust model (single key, no web of trust)
- Smaller signatures (~200 bytes)
- Faster verification
- No key management complexity

The public key is baked into every ANDYL OS image at `/etc/aos/update-signing-key.pub`.

### 7. Image Manifest

The image builder writes metadata alongside the image:

```json
{
  "name": "server",
  "variant": "server",
  "version": "0.3.1",
  "diskSize": "16G",
  "espSize": "1G",
  "rootSize": "8G",
  "format": "raw",
  "partitionTable": "gpt",
  "partitions": [
    { "number": 1, "label": "ESP",  "type": "esp",  "filesystem": "fat32", "size": "1G" },
    { "number": 2, "label": "Root", "type": "linux", "filesystem": "ext4",  "size": "8G" }
  ]
}
```

The manifest enables diff computation, integrity verification, inventory tracking, and update optimization.

### 8. Reproducibility Verification

Because Nix builds are functionally pure, reproducibility can be verified:

```bash
# Build the same image on two independent machines
machine-a$ nix-build default.nix -A images.server
machine-b$ nix-build default.nix -A images.server

# Compare store path hashes
diff <(nix-store --query --requisites result-a | sort) \
     <(nix-store --query --requisites result-b | sort)
# Should be empty if builds are reproducible
```

### 9. Image Size Estimates

| Component | Approximate Size |
|-----------|-----------------|
| Base OS (systemd, coreutils, networking) | ~500 MB |
| Kernel + modules + firmware | ~150 MB |
| K8s worker additions (containerd, kubelet, CNI) | ~200 MB |
| Control plane additions (kubeadm) | ~100 MB |
| Total base image (raw) | ~800 MB - 1.2 GB |
| Total k8s-worker image (raw) | ~1.0 - 1.5 GB |

The golden image root partition (ext4) is not compressed at the filesystem level. ZFS compression (zstd-3) applies to runtime mutable data.

## Alternatives Considered

**Container images (OCI) as the deployment unit:** Rejected because container images do not boot directly on bare metal. ANDYL OS manages the full boot path including kernel, initrd, and firmware.

**A/B partition scheme (like ChromeOS/Android):** Rejected in favor of the generational model. A/B partitions waste 50% of disk space and limit rollback to a single previous version.

**Docker-based image building:** Rejected. The Nix sandbox provides equivalent build isolation natively. The image builder runs as a standard Nix derivation with `requiredSystemFeatures = ["kvm"]` for loop device access.

## Security Considerations

- **Image signing** with Ed25519 (minisign) ensures only authorized build infrastructure can produce deployable images.
- **Content-addressed store paths** make it impossible to substitute a tampered package without changing the hash.
- **Reproducibility verification** detects non-determinism that could indicate supply chain compromise.
- **The signing private key** must be stored in an HSM or secrets manager.

## Compatibility

- **Nix build infrastructure:** Images are produced by `nix-build default.nix -A images.<variant>`, requiring KVM-capable build machines.
- **QEMU:** Images can be tested in QEMU with virtio drivers via `aos test vm`.
- **Cloud providers:** Raw images can be converted to provider-specific formats (AMI, VHD) using `qemu-img convert`.
- **Bare metal:** Raw images can be written to disk with `dd` or deployed via PXE netboot.

## Open Questions

1. **Delta updates:** Beyond store-path-level diffs, should we support binary delta compression (e.g., casync, zchunk)?
2. **Image format standardization:** Should we standardize on raw or qcow2 as the primary image format?

## References

- minisign: https://jedisct1.github.io/minisign/
- NAR Archive Format: https://nixos.org/guides/nix-pills/nix-store-paths.html
- QEMU Disk Image Formats: https://www.qemu.org/docs/master/system/images.html
- Content-Addressable Storage: https://en.wikipedia.org/wiki/Content-addressable_storage
