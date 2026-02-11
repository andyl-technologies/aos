# RFC-0006: First-Boot Configuration with CoreOS Ignition

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS uses CoreOS Ignition (not cloud-init) for one-shot, first-boot machine configuration. Ignition runs in the initrd before the real root is mounted, applying machine-specific configuration atomically. Configuration is authored in Butane YAML and transpiled to Ignition JSON. A fleet templating system generates per-machine configs from per-role templates and a machine inventory, with secrets managed via sops/age encryption.

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

**cloud-init fallback:** For environments that do not support Ignition
(some cloud providers, legacy provisioning systems), cloud-init can serve
as a fallback. The same logical operations (partition creation, ZFS setup,
file writes) are expressed as cloud-init modules and `runcmd` directives.
However, cloud-init lacks Ignition's all-or-nothing atomicity and runs
after boot rather than in the initrd. When using cloud-init as a fallback,
the ZFS setup should be placed in `bootcmd` to run before services that
depend on `/var`:

```yaml
# cloud-init fallback example (simplified)
bootcmd:
  - parted /dev/sda mkpart primary 16GiB 100%
  - zpool create -f -o ashift=12 -O compression=zstd-3 datapool /dev/sda3
  - zfs create -o mountpoint=/var datapool/var
  - zfs create -o mountpoint=/var/lib datapool/var/lib
  - zfs create -o mountpoint=/var/log datapool/var/log
```

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
partitions the remaining disk, and a systemd oneshot unit creates the ZFS
pool and datasets before other services start.

**Ignition disk config (partitions the remaining space for ZFS):**

```yaml
storage:
  disks:
    - device: /dev/sda
      wipe_table: false          # preserve existing partitions (ESP + root)
      partitions:
        - label: ANDYL-ZFS
          number: 3
          size_mib: 0            # 0 = fill remaining space
          start_mib: 0           # 0 = start after last existing partition
          type_guid: 6A898CC3-1DD2-11B2-99A6-080020736631  # Solaris /usr (ZFS convention)
```

**ZFS setup systemd unit (enabled by Ignition, runs once on first boot):**

```ini
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
  zfs create datapool/etc-overlay; \
  zfs set quota=2G datapool/var/log; \
  mkdir -p /var/lib/andyl-os; \
  touch /var/lib/andyl-os/zfs-setup-complete'

[Install]
WantedBy=local-fs.target
```

The `ConditionPathExists` guard ensures this unit runs only on first boot.
On subsequent boots, `zfs-import-cache.service` imports the pool normally.

**ZFS dataset layout created by Ignition:**

```
datapool                              # ZFS pool on remaining disk space
  datapool/var                        # /var (persistent mutable state)
    datapool/var/lib                  # /var/lib (databases, containers)
      datapool/var/lib/containerd     # Container images and layers
    datapool/var/log                  # /var/log (logs, quota=2G)
    datapool/var/tmp                  # /var/tmp
  datapool/etc-overlay                # /etc overlay upper layer
```

### 4. Per-Machine vs. Per-Role Configuration Split

**Per-role (baked into the golden image):**
- Package set and service definitions
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
- **Lower layer:** `/gnu/store/...-system/etc` (read-only, from the system profile, on ext4 root)
- **Upper layer:** `/var/etc-overlay` (writable, ZFS: `datapool/etc-overlay`, persists across reboots)

Ignition runs in the initrd before the overlay is mounted. It writes files to what will become the upper layer, seeding it with machine-specific configuration. The upper layer lives on a ZFS dataset, providing checksumming and compression for all machine-specific configuration.

```
Immutable base (from /gnu/store/...-system, on ext4 root):
  /etc/systemd/system/kubelet.service           <- from generation profile

Ignition writes (to upper layer, on ZFS datapool/etc-overlay):
  /etc/systemd/system/kubelet.service.d/        <- drop-in directory
    10-node-config.conf                         <- Ignition-generated drop-in
  /etc/hostname                                 <- machine-specific
  /etc/andyl-os/role                            <- role assignment
  /etc/ssl/andyl-os/                            <- TLS certificates

Ignition writes (to /var, on ZFS datapool/var):
  /var/lib/kubelet/config.yaml                  <- kubelet config
  /var/lib/kubelet/bootstrap-kubeconfig         <- bootstrap credentials
```

The resulting merged `/etc` on the running system contains the base configuration from the image plus the machine-specific overrides from Ignition.

### 6. Ignition Config Delivery

Ignition configs are delivered to machines via one of three mechanisms:

**1. HTTP server (bare metal):**

The machine's firmware or iPXE fetches the config from a known URL, keyed by MAC address:

```
https://ignition.andyl-os.internal/config?mac=aa:bb:cc:dd:ee:ff
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

The Ignition config is placed on a FAT32 USB drive labeled `ignition`. The initrd reads the config from the USB device.

**4. QEMU fw_cfg (testing):**

For QEMU-based integration testing, the config is passed via the fw_cfg mechanism:

```bash
qemu-system-x86_64 \
  -fw_cfg name=opt/com.coreos/config,file=ignition.json \
  ...
```

### 7. Fleet Templating System

For fleet management, per-machine configs are generated from per-role templates and a machine inventory.

**Template structure:**

```
templates/
  base.bu.j2              Common to all roles (SSH keys, update config, CA cert)
  k8s-worker.bu.j2        K8s worker additions (kubelet config, node labels)
  k8s-control-plane.bu.j2
  database.bu.j2
  edge.bu.j2

inventory/
  hosts.yaml              Machine inventory (hostnames, IPs, MACs, metadata)
  secrets.yaml            Encrypted secrets (sops/age)
```

**Machine inventory:**

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

**Secrets management:**

Secrets (TLS private keys, bootstrap tokens) are stored encrypted with sops/age:

```yaml
# inventory/secrets.yaml (encrypted with sops)
ssh_authorized_keys:
  - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... ops-team"
k8s_bootstrap_token: "abcdef.0123456789abcdef"
tls:
  ca_cert: |
    -----BEGIN CERTIFICATE-----
    ...
  nodes:
    k8s-worker-01.dc1:
      cert: |
        -----BEGIN CERTIFICATE-----
        ...
      key: |
        -----BEGIN EC PRIVATE KEY-----
        ...
```

**Generation script:**

```python
#!/usr/bin/env python3
# tools/generate-ignition-configs.py

import yaml, json, subprocess
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
        # Render base + role-specific templates
        base = env.get_template("base.bu.j2").render(
            machine=machine, secrets=secrets
        )
        role = env.get_template(f"{machine['role']}.bu.j2").render(
            machine=machine, secrets=secrets
        )
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
            raise RuntimeError(f"Butane failed for {machine['hostname']}")
        ign_path.write_bytes(result.stdout)
```

**justfile integration:**

```makefile
# Generate all Ignition configs from templates + inventory
generate-ignition:
    python3 tools/generate-ignition-configs.py

# Generate config for a single machine
generate-ignition-single HOSTNAME:
    python3 tools/generate-ignition-configs.py --host={{HOSTNAME}}

# Validate all generated Ignition configs
validate-ignition:
    for f in generated/ignition/*.ign; do
        ignition-validate "$f" || exit 1
    done
```

### 8. Ignition Execution Timeline

```
UEFI firmware boots
  -> systemd-boot loads UKI
    -> Linux kernel starts
      -> systemd in initrd (PID 1)
        -> udevd enumerates devices
        -> Ignition fetches config (HTTP, user-data, USB, or fw_cfg)
        -> Ignition applies config:
           1. Creates partitions (ANDYL-ZFS on remaining disk space)
           2. Writes files to /sysroot/var/etc-overlay/
           3. Writes files to /sysroot/var/lib/
           4. Creates users/groups
           5. Enables/disables systemd units (including andyl-os-zfs-setup.service)
        -> Ignition marks first-boot complete (writes flag file)
        -> switch-root to /sysroot (ext4 root, read-only)
          -> systemd on real root (PID 1)
            -> andyl-os-zfs-setup.service runs (first boot only):
               - Creates ZFS pool on ANDYL-ZFS partition
               - Creates datasets: datapool/var, datapool/var/lib,
                 datapool/var/log, datapool/etc-overlay, etc.
               - Writes completion marker
            -> ZFS datasets mounted (/var, /var/lib, /var/log)
            -> /etc overlay mounted (lower=profile/etc, upper=datapool/etc-overlay)
            -> Services start with machine-specific configuration
```

Ignition runs exactly once. On subsequent boots, it detects the first-boot
flag and skips. ZFS pools are imported normally by `zfs-import-cache.service`
on all subsequent boots.

### 9. Post-First-Boot Configuration Changes

Ignition runs once. For configuration changes after first boot:

**Certificate rotation:** A systemd timer periodically fetches new certificates from a CA and writes them to `/etc/ssl/andyl-os/`. This uses the writable `/etc` overlay.

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
- **sops/age encryption** protects secrets at rest in the inventory repository. Only the CI/CD pipeline and the Ignition config generation tool have decryption keys.
- **Ignition runs in the initrd** with full root privileges. The config must be validated (`butane --strict`, `ignition-validate`) before deployment.
- **Ignition configs should not be stored unencrypted** in version control if they contain secrets. Use sops or similar encryption.

## Compatibility

- **Fedora CoreOS / Flatcar:** Ignition is the native first-boot tool for these distributions. ANDYL OS adopts the same Ignition binary and config format.
- **Cloud providers:** Ignition configs are delivered as instance user-data, which is supported by AWS, GCP, Azure, and most cloud providers.
- **Bare metal:** Ignition configs are delivered via HTTP (iPXE/UEFI HTTP Boot) or USB drive.
- **QEMU:** Ignition configs are delivered via the fw_cfg mechanism for testing.
- **Butane:** Butane YAML is the human-writable format. The Ignition JSON format is machine-generated and should not be hand-edited.

## Open Questions

1. **Ignition re-provisioning:** Ignition runs once. What if we need to change machine-specific config (e.g., IP change, certificate rotation) after first boot? Do we need a secondary config management layer, or is a "re-provision by reflashing" approach acceptable?
2. **Config validation in CI:** Should we add a CI step that validates all generated Ignition configs against the current image (checking that referenced paths exist)?
3. **Secret rotation automation:** Should certificate and key rotation be handled by a dedicated agent, or by periodically re-running Ignition?
4. **Ignition config size limits:** Cloud provider user-data has size limits (e.g., 16 KiB on AWS). For large configs, should we use a URL reference to an HTTP-served config?

## References

- CoreOS Ignition: https://coreos.github.io/ignition/
- Butane Config Transpiler: https://coreos.github.io/butane/
- Ignition Configuration Specification: https://coreos.github.io/ignition/configuration-v3_4/
- sops (Secrets OPerationS): https://github.com/getsops/sops
- age encryption: https://github.com/FiloSottile/age
- Fedora CoreOS Documentation: https://docs.fedoraproject.org/en-US/fedora-coreos/
