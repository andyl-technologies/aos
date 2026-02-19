# 2. Architecture Overview

## Current State

```
systems/base.nix             -> base.img
systems/server.nix           -> server.img
systems/seed.nix             -> seed.img
systems/k8s-worker.nix       -> k8s-worker.img
systems/k8s-control-plane.nix -> k8s-control-plane.img
```

Each variant is a Nix expression that imports a subset of modules with
specific `enable` flags set to `true`. The image builder evaluates the
variant, copies the resulting Nix store closure into an ext4 root partition,
and produces a GPT disk image.

## Proposed State

```
systems/golden.nix -> golden.img (single minimal image)
                        |
                        +-- cloud-init userdata (role=server)
                        +-- cloud-init userdata (role=k8s-worker)
                        +-- cloud-init userdata (role=k8s-control-plane)
                        +-- (no userdata -> base: SSH + DHCP only)
```

A single `systems/golden.nix` imports the base, security, cloud-init, and
k3s modules, and includes only the minimal package set. Optional services
are disabled by default. Cloud-init reads a `role` from the instance's
userdata and activates the appropriate services by copying pre-rendered unit
templates into the overlay `/etc/systemd/system/`.

## Boot Sequence

```
Firmware (UEFI Secure Boot)
  -> systemd-boot (signed, ESP)
    -> Generation selection (latest, pinned, or rollback from boot menu)
      -> Unified Kernel Image for selected generation (signed)
        -> dm-verity root verification (roothash embedded in UKI)
          -> systemd initrd:
              - systemd-repart (create store + data partitions if missing)
              - Ignition (first boot: ZFS pool + datasets)
              - switch-root to verified ro root
        -> systemd PID 1:
            - SELinux policy load (before sysinit.target)
            - sysctl hardening (80-aos-hardening.conf)
            - nftables firewall (default-deny, SSH only)
            - auditd
            - ZFS import + mount (/var)
            - overlay /etc mount (tmpfs upper)
            - systemd-networkd (DHCP by default)
        -> cloud-init-local.service:
            - Read local datasource (NoCloud, ConfigDrive)
            - Set hostname
        -> cloud-init.service (after network-online):
            - Read network datasource (EC2 IMDS, GCE, Azure)
            - Determine role from userdata
            - Copy unit templates to /etc/systemd/system/
            - Write role-specific configs
            - Generate firewall rules
            - daemon-reload
        -> cloud-init-config.service:
            - Enable and start activated services
        -> cloud-init-final.service:
            - Run user scripts, k3s server/agent start
            - Install Cilium (first control plane only)
            - Write boot-finished marker
        -> multi-user.target

Live generation switch (without full reboot):
  -> aos system switch --now <gen-hash>
    -> Mount new generation root at /run/nextroot/
    -> systemctl soft-reboot
      -> SIGTERM/SIGKILL all userspace
      -> switch_root to /run/nextroot/
      -> systemd re-executes PID 1 from new root
      -> Fresh boot transaction (all services restart)
      -> cloud-init re-applies role config
      -> multi-user.target
```

Each generation is identified by the hash of its `system.build.toplevel`
derivation. Multiple generations coexist in the store partition. The ESP
holds one signed UKI per retained generation (e.g., `aos-<hash>.efi`).
systemd-boot presents all available generations in its menu.
