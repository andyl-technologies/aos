# 3. Golden Image Composition

## 3.1 Module Composition

```nix
# systems/golden.nix
{ config, pkgs, lib, ... }:
{
  imports = [
    # Base
    ../modules/base/build.nix
    ../modules/base/system.nix
    ../modules/base/boot.nix
    ../modules/base/filesystems.nix
    ../modules/base/networking.nix
    ../modules/base/users.nix
    ../modules/base/journald.nix
    ../modules/base/kernel.nix
    ../modules/base/swap.nix
    ../modules/base/repart.nix
    ../modules/base/generations.nix

    # Cloud-init (new module, replaces Ignition for service config)
    ../modules/services/cloud-init.nix

    # Security (always present and active)
    ../modules/security/selinux.nix
    ../modules/security/audit.nix
    ../modules/security/hardening.nix
    ../modules/security/firewall.nix
    ../modules/security/ssh.nix
    ../modules/security/fail2ban.nix
    ../modules/security/encryption.nix
    ../modules/security/verity.nix

    # Services (packages present, services masked by default)
    ../modules/services/ignition.nix
    ../modules/services/chrony.nix

    # Kubernetes via k3s (packages present, services masked by default)
    ../modules/kubernetes/containerd.nix
    ../modules/kubernetes/k3s.nix

    # Image builder
    ../modules/image/default.nix
  ];

  aos.system.variant = "golden";

  # Base services: always active in the golden image
  aos.security.selinux.enable = true;
  aos.security.selinux.mode = "enforcing";
  aos.security.audit.enable = true;
  aos.security.hardening.enable = true;
  aos.firewall.enable = true;
  aos.services.ssh.enable = true;
  aos.services.chrony.enable = true;

  # Everything else defaults to enable = false.
  # Cloud-init activates services at boot.

  # Force all packages into the Nix store closure
  environment.systemPackages = with pkgs; [
    # Kubernetes (k3s)
    k3s containerd runc cni-plugins
    # Security + base
    openssh nftables chrony fail2ban cryptsetup
    # Cloud provisioning
    cloud-init
  ];

  # Disk sizing — minimal image
  aos.image.diskSize = "16G";
  aos.image.rootSize = "8G";
}
```

## 3.2 Estimated Image Size

```
Component                    Nix Store Size (approx)
---------------------------------------------------
Bootstrap tools              ~300 MB
Linux kernel + modules       ~150 MB
systemd + core utils         ~120 MB
OpenSSH + security stack     ~80 MB
k3s (single binary)          ~72 MB
containerd + runc            ~60 MB
ZFS tools + kernel module    ~60 MB
Chrony + cloud-init          ~30 MB
CNI plugins                  ~20 MB
Shared libraries             ~150 MB
---------------------------------------------------
TOTAL (raw ext4)             ~1.0 GB
TOTAL (zstd -19 compressed)  ~350 MB
```

Compared to the previous five-image approach (~6 GB total compressed), the
single minimal golden image at ~350 MB is a significant reduction. Removing
alloy, node-exporter, nginx, vault-agent, sssd, and the full kubelet/kubeadm
stack eliminates ~800 MB of binaries from the image.

## 3.3 Partition Layout

```
+-----+--------+------+----------+------------------------------------+
| #   | Label  | Type | Size     | Purpose                            |
+-----+--------+------+----------+------------------------------------+
| 1   | ESP    | EFI  | 1 GB     | systemd-boot, per-generation UKIs  |
| 2   | store  | ext4 | 16 GB    | /var/lib/store (all generations)   |
| 3+  | data   | ZFS  | remainder| ZFS pool (aos-pool) for /var state |
+-----+--------+------+----------+------------------------------------+
```

The store partition holds the content-addressed Nix store containing all
system generations. Each generation is a complete system closure identified
by its derivation hash. Generations share common store paths (kernel,
libraries, etc.) via content-addressing, so adding a new generation only
consumes space for changed paths.

The ESP holds one signed UKI per retained generation (~15 MB each). With
a default retention of 5 generations, this uses ~75 MB of the 1 GB ESP.

For distribution, only ESP + store (with one generation) are shipped
(~1.5 GB raw, ~500 MB compressed). The data partition is created on first
boot by `systemd-repart`.

**Generation profile structure** (within the store partition):

```
/var/lib/profiles/
  system           -> system-42-link          (current generation)
  system-42-link   -> /var/lib/store/<hash>-aos-system  (latest)
  system-41-link   -> /var/lib/store/<hash>-aos-system  (previous)
  system-40-link   -> /var/lib/store/<hash>-aos-system  (older)
```

Each generation's store path contains:
- `bin/switch-to-configuration` — activation/switch script
- `etc/` — /etc file tree for this generation
- `sw/` — system software symlink tree
- `systemd/` — systemd unit files
- `kernel`, `initrd` — kernel image and initial ramdisk
- `boot.json` — machine-readable boot specification
- `aos-version` — generation metadata (hash, build time, version contract)

## 3.4 Service Activation Model

All AOS modules gate their `systemd.services` with `lib.mkIf cfg.enable`.
In the golden image, optional `enable` flags are `false`, so no unit files
are generated for those services. The binaries exist in `/nix/store/` and
are on `PATH`, but nothing references them.

The golden image additionally ships pre-rendered unit templates at
`/etc/aos/unit-templates/`:

```
/etc/aos/unit-templates/
  containerd.service
  containerd-config.toml
  k3s-server.service
  k3s-agent.service
  k3s-modules-load.service
  90-k3s-networking.conf
  k3s-modules.conf
  nftables-k8s-worker.conf
  nftables-k8s-control-plane.conf
```

These are generated at image build time by a derivation that evaluates each
module with `enable = true` and captures the rendered outputs with correct
Nix store paths. Cloud-init copies the appropriate templates into
`/etc/systemd/system/` at boot time.
