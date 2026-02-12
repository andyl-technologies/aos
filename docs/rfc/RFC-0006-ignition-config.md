# RFC-0006: First-Boot Configuration with CoreOS Ignition

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS uses CoreOS Ignition (not cloud-init) for one-shot, first-boot machine configuration. Ignition runs in the initrd before the real root is mounted, applying machine-specific configuration atomically. Configuration is authored in Butane YAML and transpiled to Ignition JSON. The Ignition module (`modules/services/ignition.nix`) configures ZFS pool and dataset creation on first boot.

## Motivation

Immutable operating systems require a mechanism to apply machine-specific configuration (hostname, IP address, SSH keys, certificates) without modifying the golden image. cloud-init is the traditional choice but is designed for mutable systems: it runs every boot, applies configuration in multiple stages across the boot process, and can leave the system in a partially-configured state if interrupted.

Ignition is purpose-built for immutable operating systems. It runs once in the initrd (before pivot_root), applies all configuration atomically (all-or-nothing: failure prevents boot), and never runs again on subsequent boots. This aligns with ANDYL OS's philosophy of treating the OS as a sealed artifact with machine-specific configuration layered on top.

## Design

### 1. Why Ignition Over cloud-init

| Feature | Ignition | cloud-init |
|---------|----------|------------|
| Runs when | initrd (before pivot_root) | After boot (multiple stages) |
| Runs how many times | Once (first boot only) | Every boot |
| Config format | JSON (compiled from Butane YAML) | YAML |
| Disk operations | Yes (partitioning, formatting, ZFS pool creation) | Limited |
| Atomicity | All-or-nothing (failure = no boot) | Partial application possible |
| Complexity | Simple, declarative | Complex, imperative stages |
| Suitable for immutable OS | Yes (designed for Fedora CoreOS/Flatcar) | Not ideal |

### 2. Butane YAML to Ignition JSON Transpilation

Ignition configs are JSON, but we author them in Butane (YAML) for readability and transpile:

```bash
# Transpile a single node config
butane --strict k8s-worker-node-42.bu > k8s-worker-node-42.ign

# Validate the output
ignition-validate k8s-worker-node-42.ign
```

**Example Butane config for a Kubernetes worker node:**

```yaml
# butane config: k8s-worker-node-42.bu
variant: fcos
version: "1.5.0"

storage:
  files:
    # Role assignment
    - path: /etc/aos/role
      mode: 0644
      contents:
        inline: k8s-worker

    # Machine identity
    - path: /etc/hostname
      mode: 0644
      contents:
        inline: k8s-worker-42.dc1.andyl.internal

    # Zone/region metadata
    - path: /etc/aos/zone.json
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
    - path: /etc/aos/update.conf
      mode: 0644
      contents:
        inline: |
          [update]
          server = https://update.aos.internal
          channel = stable
          check_interval = 3600

    # TLS certificates
    - path: /etc/ssl/aos/ca.pem
      mode: 0444
      contents:
        inline: |
          -----BEGIN CERTIFICATE-----
          MIIBkTCB+wIJALTRFs... (CA certificate)
          -----END CERTIFICATE-----

    - path: /etc/ssl/aos/node.pem
      mode: 0400
      contents:
        inline: |
          -----BEGIN CERTIFICATE-----
          MIICpTCCAYkCFH... (node certificate)
          -----END CERTIFICATE-----

    - path: /etc/ssl/aos/node-key.pem
      mode: 0400
      contents:
        inline: |
          -----BEGIN EC PRIVATE KEY-----
          MHQCAQEEIKz... (node private key)
          -----END EC PRIVATE KEY-----

    # kubelet configuration
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
              clientCAFile: /etc/ssl/aos/ca.pem

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
    # Static network configuration
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

    # Bond configuration (redundant networking)
    - name: 10-bond0.netdev
      contents: |
        [NetDev]
        Name=bond0
        Kind=bond

        [Bond]
        Mode=802.3ad
        MIIMonitorSec=100ms
        LACPTransmitRate=fast

    # Kubernetes node labels service
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

### 3. ZFS Pool and Dataset Creation (First Boot)

A key Ignition responsibility is **creating the ZFS pool and datasets**
that hold all mutable runtime state. The golden image ships with an ext4
root partition and unpartitioned free space. On first boot, Ignition
partitions the remaining disk, and systemd oneshot units create the ZFS
pool and datasets before other services start.

The Ignition module (`modules/services/ignition.nix`) provides typed options for ZFS configuration:

```nix
# From modules/services/ignition.nix — key options
aos.services.ignition = {
  enable = true;
  configSource = "/dev/disk/by-label/ignition";
  createZfsPool = true;
  poolName = "aos-pool";
  poolDisks = [];  # e.g., [ "/dev/vdb" ]
  datasets = {
    "var"               = { mountpoint = "/var"; compression = "zstd-3"; atime = "off"; };
    "var/log"           = { mountpoint = "/var/log"; compression = "zstd-3"; logbias = "throughput"; };
    "var/lib"           = { mountpoint = "/var/lib"; compression = "zstd-3"; };
    "var/lib/containerd" = { mountpoint = "/var/lib/containerd"; recordsize = "128K"; };
    "var/lib/etcd"      = { mountpoint = "/var/lib/etcd"; recordsize = "4K"; sync = "always"; };
  };
};
```

**ZFS pool creation systemd unit (generated by the module):**

```nix
# From modules/services/ignition.nix — pool creation service
systemd.services."ignition-zfs-pool" = {
  description = "Ignition: Create ZFS Pool";
  wantedBy = [ "initrd.target" ];
  before = [ "ignition-zfs-datasets.service" ];
  after = [ "ignition-apply.service" "systemd-udevd.service" ];
  serviceConfig = {
    Type = "oneshot";
    RemainAfterExit = true;
    ExecCondition = "/usr/bin/sh -c '! /usr/sbin/zpool list ${cfg.poolName} 2>/dev/null'";
    ExecStart = "/usr/sbin/zpool create -f -o ashift=12 -O compression=zstd-3 "
              + "-O acltype=posixacl -O xattr=sa -O dnodesize=auto "
              + "-O normalization=formD -O relatime=on "
              + "-O canmount=off -O mountpoint=none "
              + "${cfg.poolName} ${poolDisks}";
  };
};
```

**ZFS dataset creation (generated dynamically from the `datasets` option):**

The module builds dataset creation commands from the typed `datasets` attrset:

```nix
# From modules/services/ignition.nix — dataset command generation
datasetCmds = lib.mapAttrsToList (name: props:
  let
    propFlags = builtins.concatStringsSep " " (
      lib.mapAttrsToList (k: v: "-o ${k}=${v}") props
    );
  in "/usr/sbin/zfs create ${propFlags} ${cfg.poolName}/${name}"
) cfg.datasets;
```

**ZFS dataset layout created by Ignition:**

```
aos-pool                              # ZFS pool on remaining disk space
  aos-pool/var                        # /var (persistent mutable state)
    aos-pool/var/lib                  # /var/lib (databases, containers)
      aos-pool/var/lib/containerd     # Container images and layers (recordsize=128K)
      aos-pool/var/lib/etcd           # etcd data (recordsize=4K, sync=always)
    aos-pool/var/log                  # /var/log (logs, logbias=throughput)
    aos-pool/var/tmp                  # /var/tmp
```

### 4. Per-Machine vs. Per-Role Configuration Split

**Per-role (baked into the golden image via Nix modules):**
- Package set and service definitions (`systems/*.nix`, `modules/*.nix`)
- Service configurations (containerd config, kubelet base config)
- systemd unit files
- Kernel and initrd
- Base `/etc` contents

**Per-machine (delivered via Ignition):**
- Hostname
- IP address and network configuration (static IPs, VLANs, bonds)
- SSH authorized keys
- TLS certificates and private keys
- Zone/region/rack/chassis metadata
- Node labels and taints (Kubernetes)
- Update channel and server endpoint

This separation means the golden image is identical for all machines of the same role. Only the Ignition config varies per machine.

### 5. Interaction with Immutable Root (/etc Overlay)

ANDYL OS has an immutable ext4 root filesystem (read-only at runtime).
Ignition must write configuration without modifying the immutable base.
All writable state lives on ZFS datasets created during first boot
(see Section 3).

**Strategy: Ignition writes to ZFS-backed `/var` and the /etc overlay upper layer.**

The `/etc` directory uses an OverlayFS:
- **Lower layer:** `/nix/store/...-aos-system/etc` (read-only, from the system profile, on ext4 root)
- **Upper layer:** `/var/etc-overlay` (writable, ZFS: `aos-pool/etc-overlay`, persists across reboots)

Ignition runs in the initrd before the overlay is mounted. It writes files to what will become the upper layer, seeding it with machine-specific configuration. The upper layer lives on a ZFS dataset, providing checksumming and compression for all machine-specific configuration.

```
Immutable base (from /nix/store/...-aos-system, on ext4 root):
  /etc/systemd/system/kubelet.service           <- from generation profile

Ignition writes (to upper layer, on ZFS aos-pool/etc-overlay):
  /etc/systemd/system/kubelet.service.d/        <- drop-in directory
    10-node-config.conf                         <- Ignition-generated drop-in
  /etc/hostname                                 <- machine-specific
  /etc/aos/role                                 <- role assignment
  /etc/ssl/aos/                                 <- TLS certificates

Ignition writes (to /var, on ZFS aos-pool/var):
  /var/lib/kubelet/config.yaml                  <- kubelet config
  /var/lib/kubelet/bootstrap-kubeconfig         <- bootstrap credentials
```

The resulting merged `/etc` on the running system contains the base configuration from the image plus the machine-specific overrides from Ignition.

### 6. Ignition Config Delivery

Ignition configs are delivered to machines via one of these mechanisms:

**1. HTTP server (bare metal):**

The machine's firmware or iPXE fetches the config from a known URL, keyed by MAC address:

```
https://ignition.aos.internal/config?mac=aa:bb:cc:dd:ee:ff
```

The server looks up the MAC address in the machine inventory and returns the machine-specific Ignition JSON.

**2. Cloud provider user-data (VMs):**

For cloud deployments, the Ignition config is passed as instance user-data/metadata:

```bash
# AWS
aws ec2 run-instances \
  --user-data file://k8s-worker-42.ign \
  --image-id ami-andyl-os ...

# GCP
gcloud compute instances create k8s-worker-42 \
  --metadata-from-file user-data=k8s-worker-42.ign ...
```

**3. USB/local disk (air-gapped):**

The Ignition config is placed on a FAT32 USB drive labeled `ignition`. The initrd reads the config from the USB device. The config source is configurable via `aos.services.ignition.configSource`.

**4. QEMU fw_cfg (testing):**

For QEMU-based integration testing, the config is passed via the fw_cfg mechanism:

```bash
qemu-system-x86_64 \
  -fw_cfg name=opt/com.coreos/config,file=ignition.json \
  ...
```

### 7. Ignition Execution Timeline

```
UEFI firmware boots
  -> systemd-boot loads kernel + initrd
    -> Linux kernel starts
      -> systemd in initrd (PID 1)
        -> udevd enumerates devices
        -> Ignition fetches config (HTTP, user-data, USB, or fw_cfg)
        -> Ignition applies config:
           1. Creates partitions (ANDYL-ZFS on remaining disk space)
           2. Writes files to /sysroot/var/etc-overlay/
           3. Writes files to /sysroot/var/lib/
           4. Creates users/groups
           5. Enables/disables systemd units
        -> Ignition marks first-boot complete (/sysroot/boot/ignition.complete)
        -> switch-root to /sysroot (ext4 root, read-only)
          -> systemd on real root (PID 1)
            -> ignition-zfs-pool.service runs (first boot only):
               - Creates ZFS pool on ANDYL-ZFS partition
               - Pool properties: ashift=12, compression=zstd-3, acltype=posixacl
            -> ignition-zfs-datasets.service runs (first boot only):
               - Creates datasets from aos.services.ignition.datasets
               - Each dataset gets specified properties (mountpoint, recordsize, etc.)
            -> ZFS datasets mounted (/var, /var/lib, /var/log)
            -> /etc overlay mounted (lower=profile/etc, upper=aos-pool/etc-overlay)
            -> Services start with machine-specific configuration
```

Ignition runs exactly once. On subsequent boots, it detects the first-boot
flag (`/boot/ignition.complete`) and skips. ZFS pools are imported normally by
`zfs-import-cache.service` on all subsequent boots.

### 8. Post-First-Boot Configuration Changes

Ignition runs once. For configuration changes after first boot:

**Certificate rotation:** A systemd timer periodically fetches new certificates from a CA and writes them to `/etc/ssl/aos/`. This uses the writable `/etc` overlay.

**IP address changes:** Modify the networkd configuration files in `/etc/systemd/network/` (writable via overlay) and restart `systemd-networkd`.

**SSH key rotation:** Update `/home/core/.ssh/authorized_keys` or use a centralized SSH CA.

**For bulk reconfiguration,** re-provisioning is preferred: deploy the machine with a new Ignition config by clearing the first-boot flag and rebooting, or by deploying a fresh image.

## Alternatives Considered

**cloud-init:** Rejected because it runs every boot, applies configuration in multiple stages (some after services start), and can leave the system partially configured on interruption. cloud-init's complexity (modules, stages, datasources) is unnecessary for our use case.

**Ansible/Puppet/Chef:** Rejected because configuration management tools assume a mutable base system. They would conflict with the immutable root filesystem and introduce non-determinism.

**Custom first-boot script:** Rejected because Ignition's all-or-nothing semantics and its execution in the initrd (before real root mount) provide stronger guarantees. A custom script running after boot could leave the system in an inconsistent state.

**systemd firstboot:** `systemd-firstboot` handles a subset of first-boot configuration (locale, timezone, hostname) but lacks the comprehensive file/service/user management that Ignition provides.

## Security Considerations

- **Ignition configs contain secrets** (TLS private keys, bootstrap tokens). They must be delivered over secure channels (HTTPS, encrypted user-data).
- **The Ignition HTTP server** must authenticate requests (e.g., by MAC address or machine certificate) to prevent unauthorized config retrieval.
- **Ignition runs in the initrd** with full root privileges. The config must be validated (`butane --strict`, `ignition-validate`) before deployment.
- **Ignition configs should not be stored unencrypted** in version control if they contain secrets.

## Compatibility

- **Fedora CoreOS / Flatcar:** Ignition is the native first-boot tool for these distributions. ANDYL OS adopts the same Ignition binary and config format.
- **Cloud providers:** Ignition configs are delivered as instance user-data, which is supported by AWS, GCP, Azure, and most cloud providers.
- **Bare metal:** Ignition configs are delivered via HTTP (iPXE/UEFI HTTP Boot) or USB drive.
- **QEMU:** Ignition configs are delivered via the fw_cfg mechanism for testing.
- **Butane:** Butane YAML is the human-writable format. The Ignition JSON format is machine-generated and should not be hand-edited.

## Open Questions

1. **Ignition re-provisioning:** Ignition runs once. What if we need to change machine-specific config (e.g., IP change, certificate rotation) after first boot? Do we need a secondary config management layer, or is a "re-provision by reflashing" approach acceptable?
2. **Ignition config size limits:** Cloud provider user-data has size limits (e.g., 16 KiB on AWS). For large configs, should we use a URL reference to an HTTP-served config?

## References

- CoreOS Ignition: https://coreos.github.io/ignition/
- Butane Config Transpiler: https://coreos.github.io/butane/
- Ignition Configuration Specification: https://coreos.github.io/ignition/configuration-v3_4/
- Fedora CoreOS Documentation: https://docs.fedoraproject.org/en-US/fedora-coreos/
