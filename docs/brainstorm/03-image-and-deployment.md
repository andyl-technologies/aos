# 03 - Image Generation, Deployment, and Rollback

## Overview

This document covers the full lifecycle of an ANDYL OS machine: how golden
images are built from Guix, how they are deployed to bare metal or VMs, how
updates are delivered as content-addressed diffs, how generations provide
atomic rollback, how garbage collection reclaims disk space, how CoreOS
Ignition configures machines on first boot, and how Kubernetes workloads run
on the immutable base.

---

## 1. Golden Image Generation Pipeline

### 1.1 Build Foundation: `guix system image`

ANDYL OS images are produced by GNU Guix's image generation infrastructure.
The entry point is `guix system image`, which takes an operating-system
declaration and produces a bootable disk image.

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
      (size (* 512 (expt 2 20)))   ;; 512 MiB
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

The build proceeds in these stages:

1. **Dependency resolution** -- Guix resolves the full transitive closure of
   packages and services declared in the operating-system definition.
2. **Derivation computation** -- Each package is represented as a derivation
   (a build recipe). Derivations are content-addressed: identical inputs
   always produce the same `/gnu/store/hash-name` output path.
3. **Build execution** -- The Guix daemon (running on the build machine only)
   builds or substitutes all derivations. This produces a set of store paths
   in `/gnu/store`.
4. **Image assembly** -- The store closure is packed into a disk image with
   the specified partition layout, boot loader configuration, and system
   profile symlinks.

Build command:

```bash
# Build the base image
guix system image --image-type=disk-image \
  --image-size=8G \
  andyl-os/images/base.scm

# Build a role-specific image
guix system image --image-type=disk-image \
  --image-size=16G \
  andyl-os/images/k8s-worker.scm
```

### 1.2 Disk Image Format and Partition Layout

The golden image is a raw disk image with a GPT partition table and an
**ext4 root filesystem**. ext4 is used for the golden image because it is
simple, portable, and works everywhere (bare metal, VMs, cloud). ZFS is
not part of the golden image itself -- ZFS pools and datasets are created
at first boot by Ignition (see Section 6).

```
+--------------------------------------------------+
| GPT Header                                       |
+--------------------------------------------------+
| Partition 1: ESP (EFI System Partition)          |
|   - FAT32, 512 MiB                              |
|   - systemd-boot EFI binary                     |
|   - Boot loader entries (one per generation)     |
|   - Kernel + initrd                              |
+--------------------------------------------------+
| Partition 2: Root filesystem (ANDYL-ROOT)        |
|   - ext4, sized to fit the store closure         |
|   - /gnu/store (read-only bind mount at runtime) |
|   - Generation symlinks                          |
|   - Immutable -- mounted read-only at runtime    |
+--------------------------------------------------+
| Remaining disk space: unpartitioned              |
|   - Left free for Ignition to create ZFS pool(s) |
|   - ZFS datasets for /var, data, logs, etc.     |
+--------------------------------------------------+
```

**Key architectural decision:** The golden image partition is ext4
(immutable, read-only at runtime). ZFS is used for all mutable state at
runtime, but ZFS pool/partition setup happens **after** the golden image
is written to disk, driven by Ignition on first boot. See Section 4 for
the runtime partition layout and Section 6 for Ignition-driven ZFS setup.

### 1.3 Content-Addressed Store Paths

Every artifact in the image lives under `/gnu/store` and is named by its
content hash:

```
/gnu/store/abc123...-linux-6.12.1
/gnu/store/def456...-containerd-1.7.24
/gnu/store/ghi789...-andyl-os-system
```

The final system profile is a single store path
(`/gnu/store/hash-andyl-os-system`) containing a directory tree of symlinks
that reference all the other store paths. This profile path is what
generation symlinks point to.

Content addressing provides:

- **Deduplication** -- Identical content is stored once regardless of how
  many packages or generations reference it.
- **Deterministic builds** -- Same inputs produce same store path hash.
- **Safe concurrent deployment** -- New store paths can be added while the
  old generation runs. No in-place mutation.
- **Efficient diff computation** -- Comparing two generations reduces to
  comparing two sets of store path hashes.

### 1.4 Role-Based Image Variants

Each server role gets its own operating-system declaration that extends the
base. The key difference is the set of packages and services included.

```
andyl-os-base (common to all roles)
  |
  +-- andyl-os-k8s-worker
  |     Adds: containerd, kubelet, CNI plugins, runc
  |     Services: kubelet.service, containerd.service
  |
  +-- andyl-os-k8s-control-plane
  |     Adds: everything in k8s-worker + etcd, kube-apiserver,
  |           kube-scheduler, kube-controller-manager
  |     Services: etcd.service, kube-apiserver.service, ...
  |
  +-- andyl-os-database
  |     Adds: postgresql, pgbouncer, pg_basebackup, wal-g
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
   (host-name "k8s-worker")  ;; overridden by Ignition
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

**Base image contents** (common to all roles):

- systemd (init, journald, networkd, resolved, timesyncd)
- systemd-boot (boot loader)
- Linux kernel (with ANDYL OS kernel config -- see 02-kernel.md)
- GNU coreutils, bash, grep, sed, findutils
- openssh-server
- chrony (NTP)
- node_exporter (Prometheus metrics)
- andyl-os-agent (custom update/health-check daemon)
- ca-certificates
- Ignition (first-boot configuration)

### 1.5 Image Signing

Every image is signed with the project's Ed25519 private key before
distribution. The signature covers the full disk image.

```bash
# Generate signing keypair (done once, stored in hardware security module)
openssl genpkey -algorithm Ed25519 -out andyl-os-sign.key
openssl pkey -in andyl-os-sign.key -pubout -out andyl-os-sign.pub

# Sign the image
minisign -Sm andyl-os-base-gen42.img -s andyl-os-sign.key
# Produces: andyl-os-base-gen42.img.minisig

# Alternatively, using signify (OpenBSD-style):
signify -S -s andyl-os-sign.sec -m andyl-os-base-gen42.img \
  -x andyl-os-base-gen42.img.sig
```

We prefer `minisign` or `signify` over GPG for image signing because:
- Simpler trust model (single key, no web of trust)
- Smaller signatures
- Faster verification
- No key management complexity

The public key is baked into every ANDYL OS image so that update NAR
archives can be verified without external infrastructure.

### 1.6 Image Manifest

Each image ships with a manifest file listing every store path, its hash,
and its size. The manifest itself is signed.

```json
{
  "version": 1,
  "image_id": "andyl-os-base-gen42",
  "build_timestamp": "2026-01-15T14:30:00Z",
  "guix_commit": "a1b2c3d4e5f6...",
  "system_profile": "/gnu/store/xyz789...-andyl-os-system",
  "store_paths": [
    {
      "path": "/gnu/store/abc123...-linux-6.12.1",
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
- Efficient diff computation between generations (set difference on store
  path hashes)
- Verification that all store paths arrived intact after transport
- Inventory tracking of what is deployed where

### 1.7 Reproducibility Verification

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

For CI, we run a reproducibility check on every release build:
1. Build the image twice on different builders
2. Extract the store closure from each
3. Compare the set of `(path, nar-hash)` tuples
4. Fail the release if any divergence is found

---

## 2. Generational Deployment Model

### 2.1 Core Concepts

The generational model is the heart of ANDYL OS deployment. It provides
atomic upgrades, instant rollback, and concurrent version coexistence.

**Key terms:**

- **Store path**: An immutable, content-addressed directory under
  `/gnu/store`. Example: `/gnu/store/abc123...-bash-5.2`.
- **System profile**: A store path containing a directory tree that
  references all packages, services, and configuration for a complete
  system. Example: `/gnu/store/xyz789...-andyl-os-system`.
- **Generation**: A numbered symlink that points to a system profile.
  Example: `/var/guix/profiles/system-42` -> `/gnu/store/xyz789...-andyl-os-system`.
- **Current generation**: The generation currently booted and running.
  Indicated by `/var/guix/profiles/system` -> `system-42`.

### 2.2 Filesystem Layout

The runtime filesystem combines the ext4 golden image partition (read-only)
with ZFS datasets (created by Ignition on first boot) for all mutable state:

```
/
├── gnu/
│   └── store/                          # Content-addressed store (READ-ONLY at runtime)
│       ├── abc123...-bash-5.2/         # On ext4 root partition (immutable)
│       ├── def456...-linux-6.12.1/
│       ├── ghi789...-andyl-os-system/  # Generation 41 system profile
│       ├── xyz789...-andyl-os-system/  # Generation 42 system profile
│       └── ...                         # (thousands of store paths)
│
├── var/                                 # ZFS: datapool/var (writable, created by Ignition)
│   ├── guix/
│   │   └── profiles/
│   │       ├── system -> system-42      # Current generation (symlink)
│   │       ├── system-41 -> /gnu/store/ghi789...-andyl-os-system
│   │       ├── system-42 -> /gnu/store/xyz789...-andyl-os-system
│   │       └── ...
│   ├── lib/                             # ZFS: datapool/var/lib (persistent state)
│   └── log/                             # ZFS: datapool/var/log (persistent logs)
│
├── run/                                 # tmpfs, ephemeral
├── etc/                                 # Overlay: lower=profile/etc, upper=/var/etc-overlay
├── boot/
│   └── efi/                             # ESP mount point
│       └── loader/
│           ├── loader.conf
│           └── entries/
│               ├── andyl-os-41.conf
│               └── andyl-os-42.conf
└── ...
```

**Storage split:** The ext4 root partition holds the immutable store and
generation profiles. ZFS datasets (created by Ignition on first boot)
hold all mutable state: `/var`, logs, container data, databases, etc.

### 2.3 System Profile Structure

A system profile store path contains:

```
/gnu/store/xyz789...-andyl-os-system/
├── bin/                        # Symlinks to all package binaries
│   ├── bash -> /gnu/store/abc123...-bash-5.2/bin/bash
│   ├── systemctl -> /gnu/store/stu555...-systemd-255/bin/systemctl
│   └── ...
├── etc/
│   ├── systemd/system/         # Service unit files
│   ├── sysctl.d/               # Kernel parameters
│   └── ...
├── lib/
│   ├── modules/                # Kernel modules
│   └── firmware/               # Device firmware
├── share/
│   └── systemd/
│       └── bootctl/            # Boot loader entries
├── boot/
│   ├── vmlinuz -> /gnu/store/def456...-linux-6.12.1/bzImage
│   └── initrd -> /gnu/store/jkl012...-initrd/initrd.cpio.zst
└── manifest                    # JSON manifest of all paths in this profile
```

### 2.4 Generation Metadata

Each generation has associated metadata stored alongside the symlink:

```
/var/guix/profiles/
├── system-42                          # Symlink to profile
├── system-42.meta                     # Metadata file
```

```json
// system-42.meta
{
  "generation": 42,
  "profile": "/gnu/store/xyz789...-andyl-os-system",
  "timestamp": "2026-01-15T14:30:00Z",
  "guix_commit": "a1b2c3d4e5f6...",
  "andyl_os_version": "0.3.1",
  "role": "k8s-worker",
  "changelog": "Updated containerd 1.7.23 -> 1.7.24, kernel 6.12.0 -> 6.12.1",
  "manifest_hash": "sha256:aabbccdd...",
  "previous_generation": 41
}
```

### 2.5 No Guix Daemon at Runtime

This is a critical design decision. The Guix daemon (`guix-daemon`) is
**only** used at build time on the CI/build infrastructure. Deployed ANDYL
OS machines:

- Do **not** run `guix-daemon`
- Do **not** have `guix` CLI tools installed (except optionally for debugging)
- Have a **read-only** `/gnu/store` (bind-mounted read-only or on a
  read-only filesystem)
- Receive updates as pre-built NAR archives, not as derivations to build

This eliminates:
- Build-time dependencies on deployed machines (no compilers, no build tools)
- The attack surface of a build daemon
- Resource consumption from local builds
- Non-determinism from building on heterogeneous hardware

The update agent (`andyl-os-agent`) handles receiving, verifying, and
installing updates without needing the Guix daemon.

### 2.6 Boot Entry Per Generation

Each generation gets a systemd-boot loader entry:

```ini
# /boot/efi/loader/entries/andyl-os-42.conf
title   ANDYL OS Generation 42 (0.3.1)
linux   /andyl-os/xyz789...-vmlinuz
initrd  /andyl-os/xyz789...-initrd.cpio.zst
options root=LABEL=ANDYL-ROOT rw systemd.machine_id=abcdef1234 \
        init=/gnu/store/xyz789...-andyl-os-system/boot/init \
        andyl.generation=42
```

```ini
# /boot/efi/loader/loader.conf
default andyl-os-42.conf
timeout 3
editor  no
console-mode max
```

The `default` entry is updated atomically when a new generation is
deployed. The `editor no` line prevents boot-time editing of kernel
parameters (security hardening).

---

## 3. Update Mechanism

### 3.1 Update Flow Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   Build Server  │     │   Update Server  │     │   Target Machine    │
│                 │     │   (HTTPS/CDN)    │     │   (ANDYL OS)        │
│ guix system ... │────>│                  │     │                     │
│ compute diff    │     │ Signed NAR       │────>│ andyl-os-agent      │
│ create NAR      │     │ archives         │     │   1. verify sig     │
│ sign NAR        │     │                  │     │   2. unpack store   │
│                 │     │ Manifests        │────>│   3. new generation │
└─────────────────┘     └──────────────────┘     │   4. boot entry     │
                                                 │   5. reboot         │
                                                 │   6. health check   │
                                                 └─────────────────────┘
```

### 3.2 NAR Archive Generation

NAR (Nix ARchive) is a deterministic archive format used by both Nix and
Guix. A NAR archive captures a single store path (a directory tree) in a
byte-for-byte reproducible way, independent of filesystem metadata like
timestamps or permissions (those are normalized).

**Diff computation:**

```bash
# On the build server:

# 1. Get the manifest of the currently deployed generation
current_manifest=$(curl -s https://target/api/v1/manifest)

# 2. Build the new generation
new_profile=$(guix system build andyl-os/systems/k8s-worker.scm)

# 3. Compute the store closure of the new profile
new_closure=$(guix gc --references --recursive $new_profile)

# 4. Compute the store closure of the current profile
current_closure=$(cat current_manifest | jq -r '.store_paths[].path')

# 5. Diff: new paths = new_closure - current_closure
new_paths=$(comm -23 \
  <(echo "$new_closure" | sort) \
  <(echo "$current_closure" | sort))

# 6. Export only new paths as NAR archives
for path in $new_paths; do
  guix archive --export $path > nars/$(basename $path).nar
done

# 7. Compress
zstd --ultra -22 nars/*.nar

# 8. Create update bundle
tar cf update-gen42.tar \
  nars/*.nar.zst \
  manifest-42.json \
  boot/vmlinuz \
  boot/initrd.cpio.zst
```

**What's included in the update bundle:**

- NAR archives for every store path not already present on the target
- New kernel image and initrd (if changed)
- New generation manifest (JSON)
- Boot loader entry file
- Digital signature covering all of the above

**What's excluded:**

- Store paths already present on the target (the diff)
- Mutable state under `/var`
- Machine-specific configuration (handled by Ignition)

### 3.3 Transport Mechanism

We use a **pull-based HTTPS** model:

```
Target Machine                          Update Server
     |                                       |
     |--- GET /api/v1/updates/latest ------->|
     |<-- 200 { "generation": 42,            |
     |         "manifest_url": "...",        |
     |         "bundle_url": "...",          |
     |         "signature_url": "..." }      |
     |                                       |
     |--- GET /updates/gen42/manifest.json ->|
     |<-- manifest.json                      |
     |                                       |
     |  (agent computes diff locally)        |
     |                                       |
     |--- GET /updates/gen42/bundle.tar ---->|
     |<-- streaming download                 |
     |                                       |
     |  (verify, unpack, register, reboot)   |
```

**Why pull-based:**

- Machines behind NAT/firewalls can still update
- No inbound ports required on target machines
- Update server is a simple HTTPS file server (or CDN)
- Machines can poll on their own schedule or be triggered via a
  lightweight notification (MQTT, webhook)
- Natural rate limiting (machines pull when ready)

**Alternative: push-based for urgent patches:**

For critical security updates, we support a push trigger via SSH:

```bash
# From control plane, trigger immediate update on a fleet
for host in $(andyl-fleet list --role=k8s-worker); do
  ssh root@$host andyl-os-agent update --now &
done
wait
```

The push only triggers the pull; the actual update content still comes from
the HTTPS update server.

### 3.4 Signature Verification on the Target

The `andyl-os-agent` verifies every update before installation:

```bash
# Embedded in the agent, pseudocode:
verify_update() {
    bundle=$1
    sig=$2
    pubkey=/etc/andyl-os/update-signing-key.pub

    # 1. Verify bundle signature
    minisign -Vm "$bundle" -p "$pubkey" -x "$sig" || {
        log "ERROR: signature verification failed"
        return 1
    }

    # 2. Extract manifest
    manifest=$(tar xf "$bundle" --to-stdout manifest-*.json)

    # 3. Verify each NAR hash matches manifest
    for nar in $(tar tf "$bundle" | grep '\.nar\.zst$'); do
        expected_hash=$(echo "$manifest" | jq -r \
          ".store_paths[] | select(.path == \"$(nar_to_path $nar)\") | .nar_hash")
        actual_hash=$(tar xf "$bundle" --to-stdout "$nar" | \
          zstd -d | sha256sum | cut -d' ' -f1)
        if [ "$actual_hash" != "$expected_hash" ]; then
            log "ERROR: hash mismatch for $nar"
            return 1
        fi
    done

    return 0
}
```

### 3.5 Atomic Store Path Registration

Unpacking new store paths into `/gnu/store` must be atomic to prevent
partial updates from corrupting the store.

**Strategy: unpack to temp, rename into place.**

```bash
# For each NAR archive in the update bundle:
install_nar() {
    nar_file=$1
    target_path=$2   # e.g., /gnu/store/abc123...-bash-5.2

    # 1. Check if path already exists (idempotent)
    if [ -d "$target_path" ]; then
        log "Path already exists, skipping: $target_path"
        return 0
    fi

    # 2. Unpack to temporary location (same filesystem for atomic rename)
    temp_path="/gnu/store/.tmp-$(basename $target_path)-$$"
    mkdir -p "$temp_path"
    guix archive --import < "$nar_file" --target="$temp_path"

    # 3. Atomic rename into final location
    mv "$temp_path" "$target_path"

    # 4. Make read-only
    chmod -R a-w "$target_path"
}
```

The key insight: `mv` (rename) on the same filesystem is atomic in Linux.
By unpacking to a temporary directory on the same partition as `/gnu/store`
and then renaming, we ensure each store path either fully exists or doesn't.

After all store paths are installed, the generation symlink is created:

```bash
# Atomic generation registration
register_generation() {
    gen_num=$1
    profile_path=$2   # /gnu/store/xyz789...-andyl-os-system

    # Create generation symlink atomically
    ln -sf "$profile_path" "/var/guix/profiles/system-${gen_num}.tmp"
    mv -T "/var/guix/profiles/system-${gen_num}.tmp" \
          "/var/guix/profiles/system-${gen_num}"

    # Update "current" symlink
    ln -sf "system-${gen_num}" "/var/guix/profiles/system.tmp"
    mv -T "/var/guix/profiles/system.tmp" "/var/guix/profiles/system"
}
```

### 3.6 Boot Loader Entry Management

After registering the new generation, the agent installs a new boot loader
entry on the ESP:

```bash
install_boot_entry() {
    gen_num=$1
    profile_path=$2

    # Copy kernel and initrd to ESP (with content-addressed names)
    kernel_hash=$(sha256sum "$profile_path/boot/vmlinuz" | cut -c1-16)
    initrd_hash=$(sha256sum "$profile_path/boot/initrd.cpio.zst" | cut -c1-16)

    cp "$profile_path/boot/vmlinuz" \
       "/boot/efi/andyl-os/${kernel_hash}-vmlinuz"
    cp "$profile_path/boot/initrd.cpio.zst" \
       "/boot/efi/andyl-os/${initrd_hash}-initrd.cpio.zst"

    # Write boot loader entry with boot counting
    # The +3 suffix enables systemd-boot boot counting: 3 tries allowed
    cat > "/boot/efi/loader/entries/andyl-os-${gen_num}+3.conf" <<EOF
title   ANDYL OS Generation ${gen_num}
linux   /andyl-os/${kernel_hash}-vmlinuz
initrd  /andyl-os/${initrd_hash}-initrd.cpio.zst
options root=LABEL=ANDYL-ROOT rw init=${profile_path}/boot/init \
        andyl.generation=${gen_num}
EOF

    # Set as default
    bootctl set-default "andyl-os-${gen_num}+3.conf"
}
```

### 3.7 systemd-boot Boot Counting Protocol

systemd-boot implements automatic boot assessment and rollback through the
[Boot Loader Specification](https://systemd.io/BOOT_COUNTING/) boot
counting protocol.

**How it works:**

1. The boot entry filename contains a `+N` suffix: `andyl-os-42+3.conf`
   - `+3` means "3 tries remaining"
2. Each time systemd-boot boots this entry, it renames the file:
   - `andyl-os-42+3.conf` -> `andyl-os-42+2.conf` (2 tries left)
3. If the system boots successfully and the health check passes, a
   systemd service marks the boot as "good":
   ```bash
   # This removes the counter suffix entirely
   systemctl start boot-complete.target
   ```
   The entry becomes: `andyl-os-42.conf` (no counter = verified good)
4. If the counter reaches `+0` and the system still hasn't marked boot as
   good, systemd-boot automatically falls back to the previous entry on
   next boot.

**Boot counting file naming convention:**

```
andyl-os-42+3.conf    # Fresh deploy, 3 tries remaining
andyl-os-42+2.conf    # After 1st failed boot
andyl-os-42+1.conf    # After 2nd failed boot
andyl-os-42+0.conf    # After 3rd failed boot -> fallback on next boot
andyl-os-42.conf      # Verified good (counter removed)
```

**systemd integration:**

```ini
# /etc/systemd/system/andyl-os-health-check.service
[Unit]
Description=ANDYL OS Post-Boot Health Check
After=multi-user.target
# Only run for new generations (boot counting active)
ConditionPathExists=/boot/efi/loader/entries/andyl-os-*+*.conf

[Service]
Type=oneshot
ExecStart=/usr/bin/andyl-os-health-check
# If health check succeeds, signal boot-complete
ExecStartPost=/usr/bin/systemctl start boot-complete.target
# If health check fails, log and let boot counting handle rollback
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

### 3.8 Health Check Service Design

The health check runs after every boot of a new (unverified) generation:

```bash
#!/usr/bin/env bash
# /usr/bin/andyl-os-health-check
set -euo pipefail

CHECKS_PASSED=0
CHECKS_TOTAL=0

check() {
    local name=$1; shift
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    if "$@"; then
        log "PASS: $name"
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        log "FAIL: $name"
    fi
}

# Core system checks
check "systemd running"        systemctl is-system-running --quiet || \
                               [ "$(systemctl is-system-running)" = "degraded" ]
check "networkd online"        networkctl status --no-pager
check "DNS resolution"         getent hosts update.andyl-os.internal
check "NTP synchronized"       timedatectl show -p NTPSynchronized --value | grep -q yes
check "store mount read-only"  mount | grep '/gnu/store' | grep -q 'ro,'
check "journal healthy"        journalctl --verify --quiet 2>/dev/null

# Role-specific checks (detected from Ignition metadata)
ROLE=$(cat /etc/andyl-os/role 2>/dev/null || echo "base")
case "$ROLE" in
    k8s-worker|k8s-control-plane)
        check "containerd running"  systemctl is-active --quiet containerd
        check "kubelet running"     systemctl is-active --quiet kubelet
        check "cni plugins exist"   test -d /opt/cni/bin
        check "kubelet healthz"     curl -sf http://localhost:10248/healthz
        ;;
    database)
        check "postgresql running"  systemctl is-active --quiet postgresql
        check "pg accepting conns"  pg_isready -q
        ;;
    edge)
        check "envoy running"       systemctl is-active --quiet envoy
        check "envoy admin ready"   curl -sf http://localhost:9901/ready
        ;;
esac

# Verdict
if [ "$CHECKS_PASSED" -eq "$CHECKS_TOTAL" ]; then
    log "Health check passed: $CHECKS_PASSED/$CHECKS_TOTAL checks"
    exit 0
else
    log "Health check FAILED: $CHECKS_PASSED/$CHECKS_TOTAL checks"
    exit 1
fi
```

### 3.9 Rollback Procedures

**Automatic rollback** (via boot counting):

1. New generation boots, health check fails
2. System reboots (either via watchdog or manually)
3. systemd-boot decrements the counter
4. After 3 failures, systemd-boot boots the previous generation
5. Previous generation's health check passes (it was already verified)
6. System is stable on the old generation
7. Alert sent to monitoring system

**Manual rollback:**

```bash
# List available generations
andyl-os-agent generations list
# Generation 42 (current, FAILED)
# Generation 41 (verified)
# Generation 40 (verified)

# Roll back to generation 41
andyl-os-agent rollback --to=41

# This does:
# 1. Sets generation 41 as the default boot entry
# 2. Reboots
```

**Emergency rollback** (from boot menu):

1. Reboot the machine
2. systemd-boot menu appears (3-second timeout)
3. Select the desired generation entry
4. System boots into that generation

---

## 4. Partition Layout: ext4 Golden Image + ZFS Runtime Data

### 4.1 Architectural Decision

ANDYL OS uses a **hybrid ext4 + ZFS** partition strategy:

- **The golden image partition is ext4.** Since the root filesystem is
  immutable (read-only at runtime), ext4 is the simplest and most portable
  choice. It works everywhere -- bare metal, VMs, cloud -- with no special
  kernel module requirements at imaging time.
- **ZFS is used for all mutable state at runtime.** ZFS provides
  checksumming, compression, dynamic allocation, and snapshots for `/var`,
  container data, databases, logs, and other mutable data.
- **ZFS setup happens after imaging, driven by Ignition.** When the golden
  image is written to disk, it occupies only a portion of the disk. On
  first boot, Ignition partitions the remaining disk space, creates a ZFS
  pool, and sets up datasets. See Section 6 for Ignition-driven ZFS
  provisioning details.

### 4.2 Golden Image Partition Layout (Written to Disk)

The golden image contains only what is needed to boot:

```
Disk: /dev/sda (or /dev/nvme0n1)
Partition Table: GPT

+---------+-------------------+----------+------------+
| Part #  | Label             | Size     | Filesystem |
+---------+-------------------+----------+------------+
| 1       | ESP               | 1 GiB    | FAT32      |
| 2       | ANDYL-ROOT        | ~8-16 GB | ext4       |
| (free)  | (unpartitioned)   | remainder| (none)     |
+---------+-------------------+----------+------------+
```

The ANDYL-ROOT partition is sized to fit the store closure plus headroom
for future generation updates. The remaining disk space is intentionally
left unpartitioned for Ignition to claim on first boot.

### 4.3 Runtime Partition Layout (After Ignition First Boot)

After Ignition runs on first boot, the full layout becomes:

```
Disk: /dev/sda (or /dev/nvme0n1)
Partition Table: GPT

+---------+-------------------+----------+------------+
| Part #  | Label             | Size     | Filesystem |
+---------+-------------------+----------+------------+
| 1       | ESP               | 1 GiB    | FAT32      |
| 2       | ANDYL-ROOT        | ~8-16 GB | ext4 (ro)  |
| 3       | zpool: datapool   | remainder| ZFS        |
+---------+-------------------+----------+------------+
```

**ZFS dataset layout (created by Ignition):**

```
datapool                              # Data pool on remaining disk space
├── datapool/var                      # /var -- persistent mutable state
│   ├── datapool/var/log              #   /var/log
│   ├── datapool/var/lib              #   /var/lib (databases, containers)
│   │   ├── datapool/var/lib/containerd   # Container images and layers
│   │   └── datapool/var/lib/postgresql   # Database files
│   └── datapool/var/tmp              #   /var/tmp
│   Properties:
│     compression=zstd-3
│     atime=off
│     recordsize=128K
│
├── datapool/etc-overlay              # /etc overlay upper layer
│   Properties:
│     compression=zstd-3
│
└── datapool/swap                     # zvol for swap (optional)
    Properties:
      volsize=8G
      compression=off
```

**Mount points at runtime:**

```
/                ext4: ANDYL-ROOT (read-only)
/gnu/store       Part of ext4 root (read-only)
/boot/efi        Part 1 (ESP)
/var             ZFS: datapool/var (writable)
/var/lib         ZFS: datapool/var/lib (writable, persistent)
/var/log         ZFS: datapool/var/log (writable, persistent)
/etc             overlay: lower=/gnu/store/...-system/etc, upper=datapool/etc-overlay
/tmp             tmpfs
/run             tmpfs
```

### 4.4 Why This Hybrid Approach

**ext4 for the golden image:**
- Simple, well-understood, works everywhere (BIOS, UEFI, VMs, bare metal)
- No special kernel modules needed at imaging/deployment time
- Easy to produce with `guix system image`
- Portable -- can be `dd`'d to any disk, uploaded to any cloud
- The immutable root does not need ZFS features (snapshots, compression)
  because it is read-only

**ZFS for runtime mutable data:**
- **Transparent compression**: zstd-3 typically achieves 1.5-2x on `/var`
  data, effectively doubling available space
- **Checksumming**: Every block is checksummed (SHA-256 by default).
  Silent data corruption is detected and reported
- **Dynamic space allocation**: No fixed partition sizes. Datasets share
  the pool and grow as needed
- **Snapshots**: Pre-upgrade snapshots of `/var` data for rollback safety
- **Per-dataset properties**: Different record sizes and compression for
  containers (large sequential) vs. databases (small random) vs. logs

**Cons of ZFS (still apply for the data partition):**
- **Licensing**: ZFS is CDDL-licensed, not GPL-compatible. Must ship as a
  DKMS module or use OpenZFS packages.
- **Memory usage**: ZFS's ARC cache wants RAM. Minimum 2GB recommended, but
  can be tuned with `zfs_arc_max`.
- **Complexity**: ZFS pool management is another operational surface.
- **initrd size**: ZFS kernel modules must be in the initrd for mounting
  data partitions early in boot.
- **Kubernetes interaction**: Container runtimes (containerd) on ZFS need
  the `zfs` snapshotter, which adds complexity compared to `overlayfs` on
  ext4.

**Fallback: ext4-only layout.** For environments where ZFS is not desired
or not available, Ignition can create traditional ext4 partitions for
`/var` instead. This is a simpler but less capable alternative:

```
+---------+-------------------+----------+------------+
| Part #  | Label             | Size     | Filesystem |
+---------+-------------------+----------+------------+
| 1       | ESP               | 1 GiB    | FAT32      |
| 2       | ANDYL-ROOT        | ~8-16 GB | ext4 (ro)  |
| 3       | ANDYL-VAR         | 80%      | ext4       |
| 4       | ANDYL-SWAP        | remaining| swap       |
+---------+-------------------+----------+------------+
```

### 4.5 ESP Sizing Considerations

The ESP needs to hold:
- systemd-boot EFI binary (~200 KiB)
- Kernel images (~12 MiB each)
- initrd images (~30-80 MiB each, depending on modules)
- Boot loader entries (~1 KiB each)

With a retention policy of 5 generations, we need space for 5 kernels and 5
initrds: approximately `5 * (12 + 80) = 460 MiB`. A 1 GiB ESP provides
comfortable headroom.

---

## 5. Garbage Collection

### 5.1 Overview

Over time, `/gnu/store` accumulates store paths from old generations. The
garbage collector (GC) reclaims disk space by deleting store paths no longer
referenced by any kept generation.

### 5.2 The GC Algorithm

The GC uses a **mark-and-sweep** approach:

```
Phase 1: Determine GC Roots
  roots = {all kept generation symlinks}
        + {store paths referenced by running processes}

Phase 2: Mark (compute reachable set)
  reachable = {}
  worklist = roots
  while worklist is not empty:
    path = worklist.pop()
    if path not in reachable:
      reachable.add(path)
      for ref in references(path):
        worklist.add(ref)

Phase 3: Sweep (delete unreachable paths)
  for path in list_store_paths():
    if path not in reachable:
      delete(path)
```

### 5.3 Computing the Reference Graph

Store paths reference other store paths. These references are discovered by
scanning the content of each store path for strings matching the pattern
`/gnu/store/[a-z0-9]{32}-...`.

Guix records these references at build time in a database. Since we don't
run the Guix daemon at runtime, we ship the reference database as part of
the manifest.

```json
// Reference database (embedded in each generation's manifest)
{
  "/gnu/store/abc123...-bash-5.2": {
    "references": [
      "/gnu/store/glibc1...-glibc-2.39",
      "/gnu/store/ncurse...-ncurses-6.4",
      "/gnu/store/readln...-readline-8.2"
    ]
  },
  "/gnu/store/glibc1...-glibc-2.39": {
    "references": [
      "/gnu/store/linux0...-linux-headers-6.12"
    ]
  }
}
```

The GC agent loads reference data from all kept generations' manifests and
computes the transitive closure.

### 5.4 Detailed GC Implementation

```bash
#!/usr/bin/env bash
# /usr/bin/andyl-os-gc
set -euo pipefail

# Configuration
RETENTION_KEEP=${ANDYL_GC_KEEP:-5}
DRY_RUN=${ANDYL_GC_DRY_RUN:-false}
LOCK_FILE="/var/lock/andyl-os-gc.lock"

# Acquire exclusive lock (prevents races with update agent)
exec 9>"$LOCK_FILE"
flock -n 9 || { echo "GC already running or update in progress"; exit 1; }

# Phase 0: Determine which generations to keep
generations=($(ls -1 /var/guix/profiles/system-* 2>/dev/null | \
  grep -oP 'system-\K\d+' | sort -n))

total=${#generations[@]}
if [ "$total" -le "$RETENTION_KEEP" ]; then
    echo "Only $total generations exist, retention=$RETENTION_KEEP, nothing to GC"
    exit 0
fi

# Keep the most recent N generations
keep_gens=(${generations[@]: -$RETENTION_KEEP})
remove_gens=(${generations[@]:0:$((total - RETENTION_KEEP))})

echo "Keeping generations: ${keep_gens[*]}"
echo "Removing generations: ${remove_gens[*]}"

# Phase 1: Compute GC roots
declare -A roots

# Roots from kept generations
for gen in "${keep_gens[@]}"; do
    profile=$(readlink -f "/var/guix/profiles/system-${gen}")
    roots["$profile"]=1
done

# Roots from running processes (/proc/*/maps scanning)
for maps_file in /proc/[0-9]*/maps; do
    while IFS= read -r line; do
        if [[ "$line" =~ /gnu/store/([a-z0-9]{32}-[^/[:space:]]+) ]]; then
            store_path="/gnu/store/${BASH_REMATCH[1]}"
            roots["$store_path"]=1
        fi
    done < "$maps_file" 2>/dev/null
done

# Also check /proc/*/exe and /proc/*/fd/*
for exe_link in /proc/[0-9]*/exe; do
    target=$(readlink -f "$exe_link" 2>/dev/null) || continue
    if [[ "$target" =~ ^/gnu/store/ ]]; then
        roots["$target"]=1
    fi
done

echo "Found ${#roots[@]} GC root paths"

# Phase 2: Mark (compute transitive closure)
declare -A reachable
declare -a worklist=("${!roots[@]}")

# Load reference database from all kept generations
declare -A ref_db
for gen in "${keep_gens[@]}"; do
    profile=$(readlink -f "/var/guix/profiles/system-${gen}")
    manifest="$profile/manifest"
    if [ -f "$manifest" ]; then
        # Parse manifest and populate ref_db
        while IFS= read -r entry; do
            path=$(echo "$entry" | jq -r '.path')
            refs=$(echo "$entry" | jq -r '.references[]')
            ref_db["$path"]="$refs"
        done < <(jq -c '.store_paths[]' "$manifest")
    fi
done

# BFS to compute reachable set
while [ ${#worklist[@]} -gt 0 ]; do
    path="${worklist[0]}"
    worklist=("${worklist[@]:1}")

    if [ -n "${reachable[$path]+x}" ]; then
        continue
    fi
    reachable["$path"]=1

    # Add references to worklist
    if [ -n "${ref_db[$path]+x}" ]; then
        for ref in ${ref_db[$path]}; do
            if [ -z "${reachable[$ref]+x}" ]; then
                worklist+=("$ref")
            fi
        done
    fi
done

echo "Reachable store paths: ${#reachable[@]}"

# Phase 3: Sweep
bytes_freed=0
paths_deleted=0

for store_path in /gnu/store/*/; do
    store_path="${store_path%/}"
    if [ -z "${reachable[$store_path]+x}" ]; then
        size=$(du -sb "$store_path" 2>/dev/null | cut -f1)
        if [ "$DRY_RUN" = "true" ]; then
            echo "DRY-RUN: would delete $store_path ($size bytes)"
        else
            rm -rf "$store_path"
            echo "Deleted: $store_path ($size bytes)"
        fi
        bytes_freed=$((bytes_freed + size))
        paths_deleted=$((paths_deleted + 1))
    fi
done

# Phase 4: Clean up old generation symlinks and boot entries
for gen in "${remove_gens[@]}"; do
    if [ "$DRY_RUN" = "true" ]; then
        echo "DRY-RUN: would remove generation $gen"
    else
        rm -f "/var/guix/profiles/system-${gen}"
        rm -f "/var/guix/profiles/system-${gen}.meta"
        rm -f "/boot/efi/loader/entries/andyl-os-${gen}.conf"
        rm -f "/boot/efi/loader/entries/andyl-os-${gen}+*.conf"
        echo "Removed generation $gen"
    fi
done

echo "GC complete: deleted $paths_deleted paths, freed $((bytes_freed / 1048576)) MiB"

# Release lock
flock -u 9
```

### 5.5 Retention Policy Configuration

```ini
# /etc/andyl-os/gc.conf
[gc]
# Number of generations to keep
keep_generations = 5

# Minimum age before a generation can be GC'd (safety net)
min_age_hours = 24

# Schedule (systemd timer)
schedule = weekly

# Disk space threshold: trigger GC if free space drops below this
low_space_threshold_percent = 15

# Dry-run mode: log what would be deleted without deleting
dry_run = false

# Maximum time the GC is allowed to run
timeout_minutes = 60
```

```ini
# /etc/systemd/system/andyl-os-gc.timer
[Unit]
Description=ANDYL OS Store Garbage Collection Timer

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# /etc/systemd/system/andyl-os-gc.service
[Unit]
Description=ANDYL OS Store Garbage Collection
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/bin/andyl-os-gc
# Remount store read-write for GC, then back to read-only
ExecStartPre=/bin/mount -o remount,rw /gnu/store
ExecStopPost=/bin/mount -o remount,ro /gnu/store
# Safety limits
TimeoutSec=3600
IOSchedulingClass=idle
Nice=19
```

### 5.6 /proc/*/maps Scanning

This is a safety mechanism to prevent deleting store paths that are
currently memory-mapped by running processes, even if no generation symlink
references them.

Example `/proc/1234/maps` entry:
```
7f8a12000000-7f8a12200000 r-xp 00000000 08:02 12345678 /gnu/store/glibc1...-glibc-2.39/lib/libc.so.6
```

The GC scans:
- `/proc/*/maps` -- memory-mapped files
- `/proc/*/exe` -- the executable itself
- `/proc/*/fd/*` -- open file descriptors

This prevents a class of bugs where:
1. Process A is running from generation 40
2. Generations 40 is GC'd (only keep last 5, current is 45)
3. Process A crashes because its shared libraries are deleted

The `/proc` scan catches this and keeps those store paths alive.

### 5.7 GC Locking

The GC must not run concurrently with updates. Both the GC and the update
agent use a shared lock file (`/var/lock/andyl-os-gc.lock`):

- **GC**: acquires exclusive lock. If update is in progress, GC skips this
  run.
- **Update agent**: acquires shared lock during store path installation.
  If GC is running, update waits (or retries after GC completes).

This prevents the race condition where GC deletes a store path that is
being referenced by a partially-installed new generation.

### 5.8 Disk Space Reclamation

After deleting store paths, the freed space is returned to the ext4 root
filesystem immediately. For mutable data on ZFS datasets, space is returned
to the ZFS pool. No additional compaction step is needed.

For the ESP, old kernel/initrd images from GC'd generations are also
removed.

```bash
# Clean up orphaned kernel/initrd images on ESP
clean_esp() {
    # Find all kernel/initrd hashes referenced by remaining boot entries
    referenced=()
    for entry in /boot/efi/loader/entries/andyl-os-*.conf; do
        referenced+=($(grep -oP '(?<=/andyl-os/)\S+' "$entry"))
    done

    # Delete unreferenced files
    for file in /boot/efi/andyl-os/*; do
        basename=$(basename "$file")
        if ! printf '%s\n' "${referenced[@]}" | grep -q "^${basename}$"; then
            rm -f "$file"
        fi
    done
}
```

---

## 6. CoreOS Ignition Integration

### 6.1 Ignition Overview

[Ignition](https://coreos.github.io/ignition/) is a first-boot provisioning
tool from the Fedora CoreOS project. It runs in the initrd, before the real
root filesystem is mounted, and applies machine-specific configuration
exactly once.

**Ignition is responsible for ZFS pool/dataset creation.** The golden image
ships with an ext4 root partition and unpartitioned free space. On first
boot, Ignition partitions the remaining disk, creates ZFS pool(s), and sets
up datasets for `/var`, data, logs, and other mutable state. This is the
mechanism by which ZFS is "layered on top" of the portable ext4 base image.

**Why Ignition over cloud-init:**

| Feature | Ignition | cloud-init |
|---------|----------|------------|
| Runs when | initrd (before pivot_root) | After boot (multiple stages) |
| Runs how many times | Once (first boot only) | Every boot |
| Config format | JSON (compiled from Butane YAML) | YAML |
| Disk operations | Yes (partitioning, formatting, ZFS pool creation) | Limited |
| Atomicity | All-or-nothing (fails = no boot) | Partial application possible |
| Complexity | Simple, declarative | Complex, imperative stages |
| Suitable for immutable OS | Yes (designed for it) | Not ideal |

**cloud-init fallback:** For environments that do not support Ignition
(some cloud providers, legacy provisioning systems), cloud-init can serve
as a fallback. The same logical operations (partition creation, ZFS setup,
file writes) would be expressed as cloud-init modules and runcmd directives.
However, cloud-init lacks Ignition's all-or-nothing atomicity and runs
after boot rather than in the initrd. When using cloud-init as a fallback,
the ZFS setup should be placed in the `bootcmd` or early `runcmd` stage to
run before services that depend on `/var`:

```yaml
# cloud-init fallback example (simplified)
bootcmd:
  - parted /dev/sda mkpart primary 16GiB 100%
  - zpool create -f -o ashift=12 datapool /dev/sda3
  - zfs create -o mountpoint=/var -o compression=zstd datapool/var
  - zfs create -o mountpoint=/var/lib datapool/var/lib
  - zfs create -o mountpoint=/var/log datapool/var/log
```

### 6.2 Ignition Config Structure

Ignition configs are JSON, but we write them in Butane (YAML) and transpile.
A key responsibility of the Ignition config is **ZFS pool and dataset
creation** on first boot. The config partitions the remaining disk space,
creates a ZFS pool, and sets up datasets before any services start.

```yaml
# butane config: k8s-worker-node-42.bu
variant: fcos
version: "1.5.0"

storage:
  # --- ZFS Pool/Dataset Creation (first-boot partitioning) ---
  # Ignition creates a partition on the remaining disk space for ZFS.
  # Note: Ignition's built-in disk/partition support handles the GPT
  # partition creation. ZFS pool and dataset setup is done via a
  # systemd oneshot unit that runs before other services.
  disks:
    - device: /dev/sda
      wipe_table: false          # preserve existing partitions (ESP + root)
      partitions:
        - label: ANDYL-ZFS
          number: 3
          size_mib: 0            # 0 = fill remaining space
          start_mib: 0           # 0 = start after last existing partition
          type_guid: 6A898CC3-1DD2-11B2-99A6-080020736631  # Solaris /usr (ZFS convention)

  files:
    # Role assignment
    - path: /etc/andyl-os/role
      mode: 0644
      contents:
        inline: k8s-worker

    # Machine identity
    - path: /etc/hostname
      mode: 0644
      contents:
        inline: k8s-worker-42.dc1.andyl.internal

    # Zone/region metadata
    - path: /etc/andyl-os/zone.json
      mode: 0644
      contents:
        inline: |
          {
            "region": "us-east-1",
            "zone": "us-east-1a",
            "datacenter": "dc1",
            "rack": "rack-07",
            "chassis": "blade-3"
          }

    # Update server endpoint
    - path: /etc/andyl-os/update.conf
      mode: 0644
      contents:
        inline: |
          [update]
          server = https://update.andyl-os.internal
          channel = stable
          check_interval = 3600

    # TLS certificates
    - path: /etc/ssl/andyl-os/ca.pem
      mode: 0444
      contents:
        inline: |
          -----BEGIN CERTIFICATE-----
          MIIBkTCB+wIJALTRFs... (CA certificate)
          -----END CERTIFICATE-----

    - path: /etc/ssl/andyl-os/node.pem
      mode: 0400
      contents:
        inline: |
          -----BEGIN CERTIFICATE-----
          MIICpTCCAYkCFH... (node certificate)
          -----END CERTIFICATE-----

    - path: /etc/ssl/andyl-os/node-key.pem
      mode: 0400
      contents:
        inline: |
          -----BEGIN EC PRIVATE KEY-----
          MHQCAQEEIKz... (node private key)
          -----END EC PRIVATE KEY-----

    # kubelet configuration (for k8s roles)
    - path: /var/lib/kubelet/config.yaml
      mode: 0644
      contents:
        inline: |
          apiVersion: kubelet.config.k8s.io/v1beta1
          kind: KubeletConfiguration
          clusterDNS:
            - 10.96.0.10
          clusterDomain: cluster.local
          containerRuntimeEndpoint: unix:///run/containerd/containerd.sock
          staticPodPath: /etc/kubernetes/manifests
          cgroupDriver: systemd
          authentication:
            x509:
              clientCAFile: /etc/ssl/andyl-os/ca.pem

  directories:
    - path: /etc/kubernetes/manifests
      mode: 0755
    - path: /var/lib/containerd
      mode: 0710

passwd:
  users:
    - name: core
      ssh_authorized_keys:
        - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... ops-team-key"
        - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... deploy-bot-key"

systemd:
  units:
    # --- ZFS pool and dataset creation (first boot) ---
    - name: andyl-os-zfs-setup.service
      enabled: true
      contents: |
        [Unit]
        Description=Create ZFS pool and datasets (first boot)
        ConditionPathExists=!/var/lib/andyl-os/zfs-setup-complete
        DefaultDependencies=no
        Before=local-fs.target var.mount
        After=systemd-udevd.service
        Requires=systemd-udevd.service

        [Service]
        Type=oneshot
        RemainAfterExit=yes
        ExecStart=/usr/bin/bash -c '\
          set -euo pipefail; \
          modprobe zfs; \
          zpool create -f \
            -o ashift=12 \
            -o autotrim=on \
            -O compression=zstd-3 \
            -O atime=off \
            -O xattr=sa \
            -O acltype=posixacl \
            -O dnodesize=auto \
            datapool /dev/disk/by-partlabel/ANDYL-ZFS; \
          zfs create -o mountpoint=/var datapool/var; \
          zfs create -o mountpoint=/var/lib datapool/var/lib; \
          zfs create -o mountpoint=/var/log datapool/var/log; \
          zfs create -o mountpoint=/var/tmp datapool/var/tmp; \
          zfs create -o mountpoint=/var/lib/containerd \
            -o recordsize=128K datapool/var/lib/containerd; \
          zfs set quota=2G datapool/var/log; \
          mkdir -p /var/lib/andyl-os; \
          touch /var/lib/andyl-os/zfs-setup-complete'

        [Install]
        WantedBy=local-fs.target

    # Network configuration (static IP)
    - name: 10-eno1.network
      contents: |
        [Match]
        Name=eno1

        [Network]
        Address=10.0.7.42/24
        Gateway=10.0.7.1
        DNS=10.0.0.53
        DNS=10.0.0.54
        Domains=andyl.internal
        NTP=10.0.0.123

        [Link]
        MTUBytes=9000

    # VLAN configuration
    - name: 10-eno1.100.netdev
      contents: |
        [NetDev]
        Name=eno1.100
        Kind=vlan

        [VLAN]
        Id=100

    # Bond configuration (for redundant networking)
    - name: 10-bond0.netdev
      contents: |
        [NetDev]
        Name=bond0
        Kind=bond

        [Bond]
        Mode=802.3ad
        MIIMonitorSec=100ms
        LACPTransmitRate=fast

    # Custom node labels (for k8s scheduling)
    - name: kubelet-node-labels.service
      enabled: true
      contents: |
        [Unit]
        Description=Set Kubernetes Node Labels
        After=kubelet.service
        Requires=kubelet.service

        [Service]
        Type=oneshot
        ExecStart=/usr/bin/kubectl label node ${HOSTNAME} \
          topology.kubernetes.io/region=us-east-1 \
          topology.kubernetes.io/zone=us-east-1a \
          node.andyl.internal/role=worker \
          node.andyl.internal/rack=rack-07 \
          --overwrite
        RemainAfterExit=yes
        Restart=on-failure
        RestartSec=10s

        [Install]
        WantedBy=multi-user.target
```

### 6.3 Transpilation: Butane to Ignition

```bash
# Transpile a single node config
butane --strict k8s-worker-node-42.bu > k8s-worker-node-42.ign

# Validate
ignition-validate k8s-worker-node-42.ign
```

### 6.4 Ignition + Immutable Root Interaction

ANDYL OS has an immutable root filesystem (ext4, read-only at runtime).
Ignition must write configuration without modifying the immutable base.
Because ZFS datasets for `/var` are created by Ignition on first boot
(see Section 6.2), the overlay upper layer and all mutable state live on
ZFS datasets.

**Strategy: Ignition writes to ZFS-backed `/var` and uses overlays/drop-ins.**

```
Immutable base (from /gnu/store/...-system, on ext4 root):
  /etc/systemd/system/kubelet.service     <- from generation profile

Ignition creates ZFS datasets first (via andyl-os-zfs-setup.service):
  datapool/var          -> /var            <- ZFS, writable
  datapool/var/lib      -> /var/lib        <- ZFS, persistent state
  datapool/var/log      -> /var/log        <- ZFS, persistent logs
  datapool/etc-overlay  -> /var/etc-overlay <- ZFS, /etc overlay upper layer

Ignition then writes machine-specific config:
  /etc/systemd/system/kubelet.service.d/  <- drop-in directory (overlay)
    10-node-config.conf                   <- Ignition-generated drop-in

  /var/lib/kubelet/config.yaml            <- mutable, on ZFS
  /etc/andyl-os/role                      <- mutable, on ZFS via overlay
```

The `/etc` directory uses an overlay filesystem. The upper layer
(`/var/etc-overlay`) is a ZFS dataset, providing checksumming and
compression for all machine-specific configuration:

- **Lower layer**: `/gnu/store/...-system/etc` (read-only, from profile,
  on ext4 root)
- **Upper layer**: `/var/etc-overlay` (writable, ZFS: `datapool/etc-overlay`,
  persists across reboots)

Ignition writes to the upper layer, so its changes persist and overlay the
immutable base without modifying it.

```
mount -t overlay overlay -o \
  lowerdir=/gnu/store/xyz789...-andyl-os-system/etc,\
  upperdir=/var/etc-overlay,\
  workdir=/var/etc-work \
  /etc
```

**Ordering dependency:** The `andyl-os-zfs-setup.service` unit must
complete before Ignition writes to `/var` paths. This is enforced by
the unit ordering in Section 6.2 (`Before=local-fs.target var.mount`).
On subsequent boots (when ZFS is already set up), the ZFS pool is
imported normally by `zfs-import-cache.service` and datasets are
mounted before services start.

### 6.5 Ignition Config Delivery

Ignition configs are delivered to machines via one of:

1. **HTTP server** (bare metal): Machine's firmware (UEFI HTTP Boot) or
   iPXE fetches the config from a known URL:
   ```
   https://ignition.andyl-os.internal/config?mac=aa:bb:cc:dd:ee:ff
   ```
   The server looks up the MAC address and returns the machine-specific
   config.

2. **Cloud provider user-data** (VMs): For cloud deployments, the Ignition
   config is passed as instance user-data/metadata.

3. **USB/local disk** (air-gapped): The Ignition config is placed on a
   FAT32 USB drive labeled `ignition` and read by the initrd.

### 6.6 Ignition Config Generation and Templating

For fleet management, we use a templating system to generate per-machine
configs from per-role templates:

```
templates/
├── base.bu.j2              # Common to all roles
├── k8s-worker.bu.j2        # K8s worker additions
├── k8s-control-plane.bu.j2
├── database.bu.j2
└── edge.bu.j2

inventory/
├── hosts.yaml              # Machine inventory
└── secrets.yaml            # Encrypted secrets (sops/age)
```

```yaml
# inventory/hosts.yaml
machines:
  - hostname: k8s-worker-01.dc1
    role: k8s-worker
    mac: "aa:bb:cc:dd:ee:01"
    ip: 10.0.7.1/24
    gateway: 10.0.7.254
    region: us-east-1
    zone: us-east-1a
    rack: rack-01

  - hostname: k8s-worker-02.dc1
    role: k8s-worker
    mac: "aa:bb:cc:dd:ee:02"
    ip: 10.0.7.2/24
    gateway: 10.0.7.254
    region: us-east-1
    zone: us-east-1a
    rack: rack-01

  - hostname: db-primary-01.dc1
    role: database
    mac: "aa:bb:cc:dd:ee:10"
    ip: 10.0.8.1/24
    gateway: 10.0.8.254
    region: us-east-1
    zone: us-east-1a
    rack: rack-03
```

```python
#!/usr/bin/env python3
# tools/generate-ignition-configs.py
"""Generate per-machine Ignition configs from templates and inventory."""

import yaml
import json
import subprocess
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

def generate_configs():
    env = Environment(loader=FileSystemLoader("templates"))
    inventory = yaml.safe_load(Path("inventory/hosts.yaml").read_text())
    secrets = yaml.safe_load(
        subprocess.check_output(["sops", "-d", "inventory/secrets.yaml"])
    )

    output_dir = Path("generated/ignition")
    output_dir.mkdir(parents=True, exist_ok=True)

    for machine in inventory["machines"]:
        # Render base template
        base = env.get_template("base.bu.j2").render(
            machine=machine, secrets=secrets
        )
        # Render role-specific template
        role = env.get_template(f"{machine['role']}.bu.j2").render(
            machine=machine, secrets=secrets
        )
        # Merge (role template inherits/extends base)
        butane_config = merge_butane(base, role)

        # Write Butane YAML
        bu_path = output_dir / f"{machine['hostname']}.bu"
        bu_path.write_text(butane_config)

        # Transpile to Ignition JSON
        ign_path = output_dir / f"{machine['hostname']}.ign"
        result = subprocess.run(
            ["butane", "--strict"],
            input=butane_config.encode(),
            capture_output=True
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Butane failed for {machine['hostname']}: "
                f"{result.stderr.decode()}"
            )
        ign_path.write_bytes(result.stdout)

        print(f"Generated: {ign_path}")

if __name__ == "__main__":
    generate_configs()
```

### 6.7 Config Per-Machine vs. Per-Role

**Per-role** (shared):
- Package set and service definitions (baked into the image)
- Service configurations (kubelet config, containerd config)
- systemd unit files

**Per-machine** (via Ignition):
- Hostname
- IP address and network configuration
- SSH authorized keys
- TLS certificates and keys
- Zone/region/rack metadata
- Node labels and taints

This separation means the golden image is identical for all machines of the
same role. Only the Ignition config varies per machine.

---

## 7. Kubernetes Production Support

### 7.1 Required Packages by Role

**K8s Worker Node:**

| Package | Version | Purpose |
|---------|---------|---------|
| containerd | 1.7.x | Container runtime (CRI) |
| runc | 1.2.x | OCI runtime |
| kubelet | 1.31.x | Node agent |
| kubectl | 1.31.x | CLI tool (debugging) |
| cni-plugins | 1.5.x | Standard CNI plugins |
| crictl | 1.31.x | CRI debugging tool |
| iptables-nft | 1.8.x | Network policy backend |
| ethtool | 6.x | NIC configuration |
| socat | 1.8.x | Port forwarding (kubectl port-forward) |
| conntrack-tools | 1.4.x | Connection tracking |
| ipvsadm | 1.31.x | IPVS-mode kube-proxy |

**K8s Control Plane (adds):**

| Package | Version | Purpose |
|---------|---------|---------|
| kubeadm | 1.31.x | Cluster bootstrap |
| etcd | 3.5.x | Distributed key-value store |
| kube-apiserver | 1.31.x | API server (may run as static pod) |
| kube-scheduler | 1.31.x | Pod scheduler |
| kube-controller-manager | 1.31.x | Controller loops |

### 7.2 Container Runtime Interface (CRI) Setup

containerd is the CRI implementation. Configuration for an immutable OS:

```toml
# /etc/containerd/config.toml (baked into image)
version = 2

[grpc]
  address = "/run/containerd/containerd.sock"

[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    sandbox_image = "registry.k8s.io/pause:3.10"

    [plugins."io.containerd.grpc.v1.cri".containerd]
      # Use overlayfs snapshotter (default for ext4)
      # Use zfs snapshotter if on ZFS partition layout
      snapshotter = "overlayfs"
      default_runtime_name = "runc"

      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
          runtime_type = "io.containerd.runc.v2"
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
            SystemdCgroup = true

    [plugins."io.containerd.grpc.v1.cri".cni]
      bin_dir = "/opt/cni/bin"
      conf_dir = "/etc/cni/net.d"

    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"

  [plugins."io.containerd.internal.v1.opt"]
    path = "/var/lib/containerd/opt"
```

**Key paths for immutable OS:**
- Binary: `/gnu/store/...-containerd/bin/containerd` (read-only)
- State: `/var/lib/containerd` (mutable, persists)
- Socket: `/run/containerd/containerd.sock` (tmpfs, ephemeral)
- Config: `/etc/containerd/config.toml` (from profile, overlayable)

### 7.3 Pluggable CNI Architecture

ANDYL OS uses a **pluggable architecture** for Kubernetes networking. The
base image provides the host-side prerequisites (directory structure, kernel
features, standard reference plugins), but the actual CNI implementation is
deployed at runtime as a DaemonSet. This means the CNI can be swapped
without rebuilding the golden image.

**What the base image provides:**

| Component | Path | Mutability | Purpose |
|-----------|------|-----------|---------|
| Standard CNI reference plugins | `/opt/cni/bin/` | Read-only (from store) | `bridge`, `loopback`, `host-local`, `portmap`, `bandwidth`, etc. |
| CNI config directory | `/etc/cni/net.d/` | Mutable (empty at image time) | CNI DaemonSets write their config here at runtime |
| Kernel features | (compiled in) | Read-only | eBPF, netfilter, conntrack, IPVS, VXLAN, overlay -- see below |

The `/opt/cni/bin/` directory is populated from the Guix store at image
build time with the standard CNI reference plugins (from the `cni-plugins`
package). These provide basic networking primitives. The actual cluster CNI
(Cilium, Calico, Flannel, etc.) installs its own binaries into
`/opt/cni/bin/` and writes its configuration to `/etc/cni/net.d/` when
its DaemonSet starts.

**`/etc/cni/net.d/` is intentionally empty in the golden image.** The CNI
DaemonSet populates it on each node when the pod starts. This is standard
practice for Kubernetes CNI plugins and works naturally with the immutable
OS because `/etc/cni/net.d/` is on the mutable `/etc` overlay.

**Recommended default: Cilium** (eBPF-based, deployed as DaemonSet)

Cilium replaces kube-proxy and iptables-based networking with eBPF programs
loaded directly into the kernel. It is deployed entirely at runtime via
Helm/DaemonSet -- no host-level changes beyond kernel support.

```yaml
# Cilium Helm values for ANDYL OS
cilium:
  kubeProxyReplacement: "true"
  k8sServiceHost: "k8s-api.andyl.internal"
  k8sServicePort: 6443
  bpf:
    masquerade: true
  ipam:
    mode: "kubernetes"
  cni:
    binPath: "/opt/cni/bin"      # Cilium agent installs cilium-cni here
    confPath: "/etc/cni/net.d"   # Cilium writes 05-cilium.conflist here
    exclusive: true              # Remove other CNI configs
  hubble:
    enabled: true
    relay:
      enabled: true
    ui:
      enabled: true
```

Benefits of Cilium on an immutable OS:
- Runs entirely as a DaemonSet (no host package installation needed)
- Replaces kube-proxy (no iptables rules, scales better)
- Network policy enforcement in eBPF (faster, more expressive)
- Built-in observability (Hubble)
- Service mesh capabilities without sidecars

**Alternative: Flannel** (simple overlay, deployed as DaemonSet)

For environments where eBPF is not available or simplicity is preferred,
Flannel provides basic VXLAN overlay networking:

```yaml
# Flannel values for ANDYL OS
flannel:
  backend: "vxlan"
  podCidr: "10.244.0.0/16"
  cni:
    binPath: "/opt/cni/bin"      # Flannel installs flannel-cni here
    confPath: "/etc/cni/net.d"   # Flannel writes 10-flannel.conflist here
```

**Alternative: Calico** (eBPF or iptables dataplane, deployed as DaemonSet)

```yaml
# Calico values for ANDYL OS
calico:
  bpfEnabled: true
  bpfExternalServiceMode: "DSR"
  cni:
    binPath: "/opt/cni/bin"
    confPath: "/etc/cni/net.d"
```

**Extension points table:**

The pluggable architecture extends beyond CNI to other Kubernetes plugins.
The base image provides host paths and kernel prerequisites; the actual
implementations are deployed as DaemonSets at runtime.

| Extension Point | Host Path(s) | Mutable? | Deployed Via | Notes |
|----------------|-------------|----------|-------------|-------|
| **CNI plugins** | `/opt/cni/bin/`, `/etc/cni/net.d/` | bin: RO base + writable; net.d: mutable | DaemonSet (Cilium/Calico/Flannel) | Config dir empty at image time |
| **CSI drivers** | `/var/lib/kubelet/plugins/`, `/var/lib/kubelet/plugins_registry/` | Mutable (on ZFS `/var`) | DaemonSet (per storage provider) | Node plugin registers via kubelet plugin dir |
| **Device plugins** | `/var/lib/kubelet/device-plugins/` | Mutable (on ZFS `/var`) | DaemonSet (GPU, FPGA, SR-IOV, etc.) | Registers devices via kubelet gRPC socket |
| **kube-proxy replacement** | N/A (kernel eBPF) | N/A | DaemonSet (Cilium) or standalone DaemonSet | Cilium replaces kube-proxy entirely |
| **Log forwarding** | `/var/log/pods/`, `/var/log/containers/` | Mutable (on ZFS `/var`) | DaemonSet (Fluent Bit, Vector, etc.) | Reads pod logs from host path |

**Required kernel features for CNI** (reference 02-kernel.md):
- `CONFIG_BPF=y`
- `CONFIG_BPF_SYSCALL=y`
- `CONFIG_BPF_JIT=y`
- `CONFIG_CGROUP_BPF=y`
- `CONFIG_NET_CLS_BPF=y`
- `CONFIG_NET_ACT_BPF=y`
- `CONFIG_BPF_EVENTS=y`
- `CONFIG_VXLAN=y` (for Flannel/Calico VXLAN backend)
- `CONFIG_IP_VS=y` (for IPVS-mode kube-proxy, if not using Cilium)
- `CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y`
- `CONFIG_OVERLAY_FS=y` (for containerd)

### 7.4 Kubelet Configuration for Immutable OS

The kubelet on an immutable OS needs special consideration:

```yaml
# /var/lib/kubelet/config.yaml (written by Ignition, mutable on /var)
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration

# Cluster identity
clusterDNS:
  - 10.96.0.10
clusterDomain: cluster.local

# Runtime
containerRuntimeEndpoint: "unix:///run/containerd/containerd.sock"
cgroupDriver: systemd

# Paths (must all be on mutable partitions)
staticPodPath: /etc/kubernetes/manifests
containerLogMaxSize: "50Mi"
containerLogMaxFiles: 5

# Authentication
authentication:
  x509:
    clientCAFile: /etc/ssl/andyl-os/ca.pem
  webhook:
    enabled: true

# Authorization
authorization:
  mode: Webhook

# Resource management
systemReserved:
  cpu: "500m"
  memory: "512Mi"
  ephemeral-storage: "1Gi"
kubeReserved:
  cpu: "500m"
  memory: "512Mi"
  ephemeral-storage: "1Gi"
evictionHard:
  memory.available: "256Mi"
  nodefs.available: "10%"
  imagefs.available: "15%"

# Immutable OS specific
protectKernelDefaults: true
readOnlyPort: 0
```

```ini
# /etc/systemd/system/kubelet.service
[Unit]
Description=Kubernetes Kubelet
Documentation=https://kubernetes.io/docs/
After=containerd.service
Requires=containerd.service

[Service]
ExecStart=/gnu/store/...-kubelet/bin/kubelet \
  --config=/var/lib/kubelet/config.yaml \
  --kubeconfig=/var/lib/kubelet/kubeconfig \
  --bootstrap-kubeconfig=/var/lib/kubelet/bootstrap-kubeconfig \
  --cert-dir=/var/lib/kubelet/pki \
  --root-dir=/var/lib/kubelet \
  --node-labels=node.andyl.internal/os=andyl-os \
  --register-with-taints="" \
  --v=2

Restart=always
RestartSec=10
StartLimitInterval=0
KillMode=process
CPUAccounting=true
MemoryAccounting=true

[Install]
WantedBy=multi-user.target
```

**Mutable paths kubelet needs (all on /var):**
- `/var/lib/kubelet` -- kubelet state, pods, plugins
- `/var/lib/containerd` -- container images, snapshots
- `/var/log/pods` -- pod logs
- `/var/log/containers` -- container log symlinks
- `/run/containerd` -- containerd socket (tmpfs)
- `/etc/kubernetes/manifests` -- static pod manifests (overlay on /etc)

### 7.5 etcd Considerations (Control Plane)

If running etcd on ANDYL OS control plane nodes (rather than external etcd):

```yaml
# etcd static pod manifest or systemd service
# Key consideration: etcd data directory MUST be on mutable /var

etcd:
  data-dir: /var/lib/etcd
  wal-dir: /var/lib/etcd/wal    # Separate WAL for performance

  # Disk performance
  # etcd is latency-sensitive; ensure /var is on fast storage (NVMe)
  quota-backend-bytes: 8589934592  # 8 GiB
  auto-compaction-mode: periodic
  auto-compaction-retention: "8"

  # Snapshot retention
  snapshot-count: 10000
  max-snapshots: 5
  max-wals: 5
```

**etcd upgrade strategy with generational deployment:**

1. etcd must be upgraded one minor version at a time
2. Rolling upgrade: update one control plane node at a time
3. Verify etcd cluster health between each node update
4. Keep previous generation available for instant rollback
5. etcd data directory (`/var/lib/etcd`) persists across generations

### 7.6 Node Labels and Taints via Ignition

Ignition sets node labels and taints via a systemd oneshot unit that runs
after kubelet starts (shown in Section 6.2 above). Common labels:

```
topology.kubernetes.io/region=us-east-1
topology.kubernetes.io/zone=us-east-1a
node.andyl.internal/role=worker
node.andyl.internal/rack=rack-07
node.andyl.internal/os-generation=42
node.kubernetes.io/instance-type=bare-metal-xlarge
```

Taints for control plane nodes:

```
node-role.kubernetes.io/control-plane:NoSchedule
```

### 7.7 Pod Security Standards

ANDYL OS enforces Pod Security Standards at the cluster level:

```yaml
# Namespace-level enforcement via labels
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

The `restricted` profile requires:
- Containers run as non-root
- No privilege escalation
- Seccomp profile set
- No host namespaces or host paths
- Read-only root filesystem in containers

This aligns with ANDYL OS's immutable philosophy.

### 7.8 Required Kernel Features for Kubernetes

Reference to the kernel configuration document (02-kernel.md). Key features:

```
# Namespaces (container isolation)
CONFIG_NAMESPACES=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_CGROUP_NS=y

# cgroups v2 (resource management)
CONFIG_CGROUPS=y
CONFIG_CGROUP_V2=y
CONFIG_MEMCG=y
CONFIG_CPUSET=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_BPF=y

# Networking
CONFIG_BRIDGE=y
CONFIG_VXLAN=y
CONFIG_IP_VS=y
CONFIG_IP_VS_RR=y
CONFIG_IP_VS_WRR=y
CONFIG_IP_VS_SH=y
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y
CONFIG_NF_CONNTRACK=y
CONFIG_NETFILTER_XT_MATCH_COMMENT=y

# eBPF (Cilium)
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_HAVE_EBPF_JIT=y
CONFIG_BPF_EVENTS=y
CONFIG_CGROUP_BPF=y

# Overlay filesystem (containerd)
CONFIG_OVERLAY_FS=y

# Seccomp (pod security)
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
```

### 7.9 Considerations for Running Kubernetes on ZFS

With the ext4 + ZFS hybrid layout (Section 4), container runtime data
lives on ZFS datasets under `datapool/var/lib/containerd`:

1. **containerd snapshotter**: Must use the `zfs` snapshotter instead of
   `overlayfs`. This means containerd manages container filesystem layers
   as ZFS clones.
   ```toml
   [plugins."io.containerd.grpc.v1.cri".containerd]
     snapshotter = "zfs"
   ```

2. **Performance**: ZFS snapshotter creates a ZFS dataset per container
   layer. With many pods, this can create thousands of datasets. Monitor
   `zfs list` output and dataset creation/deletion latency.

3. **Container image storage**: Container images stored on ZFS benefit from
   transparent compression, reducing disk usage for image layers.

4. **etcd on ZFS**: Set `recordsize=4k` for the etcd dataset to match
   etcd's write pattern (small, frequent writes):
   ```bash
   zfs create -o recordsize=4K -o logbias=throughput datapool/var/lib/etcd
   ```

5. **Copy-on-write overhead**: ZFS CoW means random writes cause
   fragmentation over time. For write-heavy workloads (databases, etcd),
   consider `sync=disabled` for non-critical data or a dedicated zvol with
   ext4.

---

## Appendix A: Complete Update Sequence Diagram

```
Time    Build Server              Update Server         Target Machine
─────   ────────────              ─────────────         ──────────────
 t0     guix system build
        (produces new profile)
 t1     compute diff vs. current
        deployed manifest
 t2     export NAR archives
        for new store paths
 t3     compress with zstd
 t4     sign bundle with
        minisign
 t5     upload to update ──────> receives bundle
        server                   serves via HTTPS
 t6                                                    andyl-os-agent
                                                       polls for update
 t7                              <─── GET /latest ──── discovers gen 42
 t8                              <─── GET /manifest ── downloads manifest
 t9                                                    computes local diff
t10                              <─── GET /bundle ──── downloads NAR bundle
t11                                                    verifies signature
t12                                                    verifies NAR hashes
t13                                                    remounts /gnu/store rw
t14                                                    unpacks store paths
t15                                                    remounts /gnu/store ro
t16                                                    creates gen-42 symlink
t17                                                    installs boot entry
                                                       (with +3 boot count)
t18                                                    reboots
t19                                                    systemd-boot loads
                                                       gen-42+3 → gen-42+2
t20                                                    kernel + initrd boot
t21                                                    systemd starts
t22                                                    health check runs
t23                                                    all checks pass
t24                                                    boot-complete.target
                                                       reached
t25                                                    entry renamed:
                                                       gen-42+2 → gen-42
                                                       (verified good)
```

## Appendix B: Failure Scenarios and Recovery

### B.1 Update Download Failure

- **Cause**: Network interruption during bundle download
- **Effect**: Incomplete bundle on disk
- **Recovery**: Agent retries with HTTP range requests (resume download).
  No store paths have been modified.

### B.2 Signature Verification Failure

- **Cause**: Corrupted bundle or signing key mismatch
- **Effect**: Agent rejects the update
- **Recovery**: Alert sent to monitoring. Operator investigates. No
  changes applied.

### B.3 Store Path Unpacking Failure

- **Cause**: Disk full, I/O error
- **Effect**: Some store paths installed, some not
- **Recovery**: Agent rolls back by deleting partially-installed paths
  (they are not yet referenced by any generation). The temp-then-rename
  strategy means partial store paths don't exist (each path is atomic).

### B.4 Health Check Failure (Post-Boot)

- **Cause**: Application-level failure in the new generation
- **Effect**: Boot counting decrements. After 3 failures, automatic
  rollback.
- **Recovery**: Previous generation boots and is stable. Alert sent.
  Operator debugs the new generation on a test machine.

### B.5 ESP Corruption

- **Cause**: Power loss during ESP write
- **Effect**: Unbootable system
- **Recovery**: Boot from USB rescue image. Reinstall systemd-boot and
  boot entries from `/var/guix/profiles` symlinks. This is scriptable:
  ```bash
  # From rescue USB:
  mount /dev/sda1 /mnt/esp
  bootctl install --esp-path=/mnt/esp
  # Regenerate boot entries from existing generations
  andyl-os-agent regenerate-boot-entries --esp=/mnt/esp
  ```

---

## Open Questions

1. **NAR format vs. custom archive**: Should we use Guix's NAR format
   directly, or define our own simpler archive format? NAR has the
   advantage of being well-tested, but it carries Guix/Nix compatibility
   baggage we may not need.

2. **Delta updates**: Beyond store-path-level diffs, should we support
   binary delta compression (e.g., `casync`, `zchunk`) for large store
   paths that changed slightly (e.g., kernel rebuild)?

3. **Multi-machine coordination**: How do we orchestrate fleet-wide
   updates? Rolling update strategy? Canary deployments? This is likely
   a separate document (fleet management).

4. **Secure boot chain**: Should we sign the kernel and initrd for UEFI
   Secure Boot? This adds complexity but hardens the boot chain. If yes,
   we need to manage Secure Boot keys and sign kernels as part of the
   image build.

5. **Store deduplication across machines**: If many machines share the
   same role, they have identical stores. Can we use this for more
   efficient distribution (e.g., BitTorrent-style peer distribution)?

6. **ZFS native encryption**: If using ZFS, should we enable native
   encryption for `/var` (containing secrets, database state)? Key
   management becomes a concern.

7. **Ignition re-provisioning**: Ignition runs once. What if we need to
   change machine-specific config (e.g., IP change, certificate rotation)
   after first boot? Do we need a secondary config management layer?
