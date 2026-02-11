# Phase 6: CoreOS Ignition Integration

**Phase Number:** 6

## Objective

Integrate CoreOS Ignition as the first-boot provisioning system. Create Butane template infrastructure for fleet-wide configuration generation, implement per-machine config delivery, and verify Ignition works correctly with the immutable root and `/etc` overlay architecture.

## Prerequisites

- Phase 4 complete: Base image boots with systemd, ext4 read-only root, `/etc` overlay
- Phase 5 in progress or complete: update agent infrastructure (Ignition writes update config)
- Understanding of Ignition specification v3.4.0
- Understanding of Butane YAML format and transpilation
- ZFS kernel modules available (included in initrd or loadable at boot)

## Deliverables

- `channel/andyl/packages/ignition.scm` -- Ignition binary package for Guix
- `channel/andyl/packages/butane.scm` -- Butane transpiler package
- Ignition systemd units integrated into the initrd
- ZFS pool and dataset creation via `andyl-os-zfs-setup.service` (first-boot oneshot)
- `templates/base.bu.j2` -- Base Butane template (common to all roles, includes ZFS partitioning)
- `templates/k8s-worker.bu.j2` -- K8s worker role template
- `templates/k8s-control-plane.bu.j2` -- K8s control plane role template
- `templates/database.bu.j2` -- Database role template
- `templates/edge.bu.j2` -- Edge/gateway role template
- `inventory/hosts.yaml` -- Machine inventory format
- `inventory/secrets.yaml` -- Encrypted secrets template (sops/age)
- `tools/generate-ignition-configs.py` -- Config generation script
- Ignition config delivery mechanism (HTTP server for bare metal, user-data for cloud)
- cloud-init fallback configuration for environments without Ignition support
- Verified first-boot provisioning in QEMU (including ZFS dataset creation)

## Detailed Task Checklist

### 6.1 Ignition Package

- [ ] Create `channel/andyl/packages/ignition.scm`
- [ ] Define `andyl-ignition` package
- [ ] Source: Ignition GitHub release (coreos/ignition)
- [ ] Build with Go build system (or download pre-built binary and wrap)
- [ ] Install `ignition` binary and dracut module
- [ ] Build and verify: `ignition --version`

### 6.2 Butane Package

- [ ] Create `channel/andyl/packages/butane.scm`
- [ ] Define `andyl-butane` package
- [ ] Source: Butane GitHub release (coreos/butane)
- [ ] Build or wrap the Go binary
- [ ] Install `butane` CLI tool
- [ ] Build and verify: `butane --version`

### 6.3 Ignition in initrd

- [ ] Add Ignition dracut module to the initrd build:
  - [ ] Include `ignition` binary in initrd
  - [ ] Include Ignition systemd units for initrd:
    - [ ] `ignition-disks.service`
    - [ ] `ignition-mount.service`
    - [ ] `ignition-files.service`
    - [ ] `ignition-fetch.service`
    - [ ] `ignition-complete.service`
  - [ ] Order Ignition before `initrd-switch-root.target`
- [ ] Configure Ignition to read config from:
  - [ ] QEMU fw_cfg: `opt/com.coreos/config` (for testing)
  - [ ] Cloud provider metadata (user-data endpoint)
  - [ ] USB drive labeled `ignition`
  - [ ] HTTP endpoint (for bare-metal provisioning)
- [ ] Add first-boot detection: Ignition runs only if `/boot/ignition/first-boot` marker exists (or equivalent)
- [ ] Rebuild initrd with Ignition support
- [ ] Verify Ignition modules are present in initrd

### 6.4 ZFS Pool and Dataset Setup (First Boot)

- [ ] Create `andyl-os-zfs-setup.service` systemd unit (enabled by Ignition):
  - [ ] `ConditionPathExists=!/var/lib/andyl-os/zfs-setup-complete` (runs only on first boot)
  - [ ] `Before=local-fs.target var.mount`, `After=systemd-udevd.service`
  - [ ] Load ZFS kernel module: `modprobe zfs`
  - [ ] Create ZFS pool on the ANDYL-ZFS partition:
    ```
    zpool create -f -o ashift=12 -o autotrim=on \
      -O compression=zstd-3 -O atime=off -O xattr=sa \
      -O acltype=posixacl -O dnodesize=auto \
      datapool /dev/disk/by-partlabel/ANDYL-ZFS
    ```
  - [ ] Create core datasets:
    - [ ] `datapool/var` (mountpoint=/var)
    - [ ] `datapool/var/lib` (mountpoint=/var/lib)
    - [ ] `datapool/var/log` (mountpoint=/var/log, quota=2G)
    - [ ] `datapool/var/tmp` (mountpoint=/var/tmp)
    - [ ] `datapool/etc-overlay` (for /etc overlay upper layer)
  - [ ] Create role-specific datasets:
    - [ ] `datapool/var/lib/containerd` (recordsize=128K, for container images)
    - [ ] `datapool/var/lib/postgresql` (recordsize=8K, for database roles)
    - [ ] `datapool/var/lib/etcd` (recordsize=4K, for control plane roles)
  - [ ] Write completion marker: `touch /var/lib/andyl-os/zfs-setup-complete`
- [ ] Add Ignition disk config to base Butane template:
  - [ ] Partition remaining disk space as partition 3, label ANDYL-ZFS
  - [ ] Use `wipe_table: false` to preserve existing ESP + root partitions
- [ ] Verify ZFS pool imports correctly on subsequent boots via `zfs-import-cache.service`
- [ ] Test ZFS dataset creation with different disk sizes (small VM, large bare metal)

### 6.4a cloud-init Fallback

- [ ] Create cloud-init fallback config for environments without Ignition support:
  - [ ] `bootcmd` stage: partition remaining disk, create ZFS pool and datasets
  - [ ] `write_files`: machine-specific config files (hostname, role, certs)
  - [ ] `runcmd`: post-boot setup (node labels, service configuration)
- [ ] Document limitations vs. Ignition:
  - [ ] No all-or-nothing atomicity
  - [ ] Runs after boot, not in initrd
  - [ ] ZFS setup in `bootcmd` may race with services depending on `/var`
- [ ] Test cloud-init fallback in a cloud VM environment

### 6.5 Ignition + /etc Overlay Interaction

- [ ] Ensure Ignition writes to the `/etc` overlay upper directory:
  - [ ] Ignition runs in initrd before switch-root
  - [ ] At this point, the overlay is not yet mounted
  - [ ] Ignition writes directly to `/sysroot/var/etc-overlay/` (the upper dir)
  - [ ] After switch-root, systemd mounts the overlay, merging Ignition changes with base /etc
  - [ ] The upper layer (`/var/etc-overlay`) lives on ZFS dataset `datapool/etc-overlay`
- [ ] Verify ordering: ZFS setup must complete before overlay mount:
  - [ ] `andyl-os-zfs-setup.service` creates `datapool/etc-overlay` dataset
  - [ ] The `/etc` overlay mount unit depends on ZFS dataset availability
- [ ] Alternative: Ignition writes to `/sysroot/etc/` which becomes the lower or upper layer depending on timing
- [ ] Test both approaches; select the one that works reliably
- [ ] Verify files written by Ignition appear correctly in the merged `/etc` after boot
- [ ] Verify /etc overlay persists correctly across reboots (ZFS dataset survives reboot)

### 6.6 Base Butane Template

- [ ] Create `templates/` directory
- [ ] Write `templates/base.bu.j2` with Jinja2 templating:
  - [ ] Ignition spec version: `1.5.0`
  - [ ] Storage files:
    - [ ] `/etc/hostname` -- from `{{ machine.hostname }}`
    - [ ] `/etc/andyl-os/role` -- from `{{ machine.role }}`
    - [ ] `/etc/andyl-os/zone.json` -- region, zone, datacenter, rack metadata
    - [ ] `/etc/andyl-os/update.conf` -- update server endpoint and channel
    - [ ] `/etc/ssl/andyl-os/ca.pem` -- CA certificate
    - [ ] `/etc/ssl/andyl-os/node.pem` -- node TLS certificate
    - [ ] `/etc/ssl/andyl-os/node-key.pem` -- node TLS private key (mode 0400)
  - [ ] Passwd:
    - [ ] `core` user with SSH authorized keys from `{{ secrets.ssh_keys }}`
  - [ ] systemd units:
    - [ ] Network configuration (static IP or DHCP based on machine config)

### 6.7 Role-Specific Templates

- [ ] Write `templates/k8s-worker.bu.j2`:
  - [ ] `/var/lib/kubelet/config.yaml` -- kubelet configuration
  - [ ] `/var/lib/kubelet/bootstrap-kubeconfig` -- bootstrap token for cluster join
  - [ ] `/etc/containerd/config.toml` drop-in (if needed)
  - [ ] `kubelet-node-labels.service` -- systemd unit to set k8s node labels
  - [ ] Create `/etc/kubernetes/manifests/` directory
  - [ ] Create `/var/lib/containerd/` directory with mode 0710
- [ ] Write `templates/k8s-control-plane.bu.j2`:
  - [ ] Everything from k8s-worker plus:
  - [ ] etcd configuration
  - [ ] kube-apiserver static pod manifest (or systemd unit)
  - [ ] Control plane certificates
- [ ] Write `templates/database.bu.j2`:
  - [ ] PostgreSQL configuration (`/var/lib/postgresql/`)
  - [ ] pgbouncer configuration
  - [ ] Database-specific TLS certificates
- [ ] Write `templates/edge.bu.j2`:
  - [ ] Envoy/HAProxy configuration
  - [ ] TLS certificates for external endpoints
  - [ ] certbot timer configuration

### 6.8 Network Configuration Templates

- [ ] Static IP template:
  - [ ] `10-<interface>.network` systemd-networkd unit with Address, Gateway, DNS, NTP
  - [ ] Support for jumbo frames (MTUBytes=9000)
- [ ] DHCP template:
  - [ ] Match on `Type=ether`, `Name=en* eth*`
  - [ ] DHCP=yes, IPv6AcceptRA=yes
- [ ] VLAN template:
  - [ ] `.netdev` file for VLAN interface
  - [ ] `.network` file for VLAN network config
- [ ] Bond template:
  - [ ] `.netdev` file for bond interface (802.3ad)
  - [ ] `.network` files for member interfaces
- [ ] Select template based on machine inventory configuration

### 6.9 Machine Inventory

- [ ] Create `inventory/hosts.yaml` format:
  ```yaml
  machines:
    - hostname: <fqdn>
      role: <k8s-worker|k8s-control-plane|database|edge>
      mac: "<mac-address>"
      ip: <ip>/<cidr>
      gateway: <ip>
      dns: [<ip>, ...]
      ntp: [<ip>, ...]
      region: <string>
      zone: <string>
      datacenter: <string>
      rack: <string>
  ```
- [ ] Create sample inventory with 3+ machines per role
- [ ] Create `inventory/secrets.yaml` template (encrypted with sops/age):
  - [ ] SSH authorized keys
  - [ ] TLS CA certificate and key
  - [ ] Per-machine TLS certificates (or certificate generation script)
  - [ ] Kubernetes bootstrap tokens

### 6.10 Config Generation Script

- [ ] Create `tools/generate-ignition-configs.py`:
  - [ ] Load Jinja2 templates from `templates/`
  - [ ] Load machine inventory from `inventory/hosts.yaml`
  - [ ] Decrypt secrets using sops: `sops -d inventory/secrets.yaml`
  - [ ] For each machine:
    - [ ] Render base template with machine and secrets context
    - [ ] Render role-specific template
    - [ ] Merge templates (role extends base)
    - [ ] Write Butane YAML to `generated/ignition/<hostname>.bu`
    - [ ] Transpile to Ignition JSON: `butane --strict < input.bu > output.ign`
    - [ ] Validate with `ignition-validate`
  - [ ] Generate summary report: machines processed, any errors
- [ ] Add error handling: clear error messages for missing fields, invalid YAML, transpilation failures
- [ ] Test with the sample inventory

### 6.11 Config Delivery Mechanisms

- [ ] QEMU (development/testing):
  - [ ] Pass config via fw_cfg: `-fw_cfg name=opt/com.coreos/config,file=<path>.ign`
  - [ ] Verify Ignition reads from fw_cfg in initrd
- [ ] Bare metal (production):
  - [ ] Set up HTTP config server at a known URL
  - [ ] Server looks up MAC address and returns machine-specific config:
    ```
    GET /config?mac=aa:bb:cc:dd:ee:ff -> <hostname>.ign
    ```
  - [ ] Configure Ignition to fetch from this URL (via kernel cmdline or initrd config)
- [ ] Cloud (VMs):
  - [ ] Pass Ignition config as instance user-data
  - [ ] Configure Ignition provider for each cloud:
    - [ ] AWS: IMDSv2 user-data endpoint
    - [ ] GCP: metadata server
    - [ ] Azure: custom-data
- [ ] Air-gapped (USB):
  - [ ] Place config on FAT32 USB drive labeled `ignition`
  - [ ] Ignition reads from the mounted USB drive

### 6.12 Certificate Generation Tooling

- [ ] Create `tools/generate-certs.sh` or integrate with cert-manager:
  - [ ] Generate project CA (Ed25519 or ECDSA P-256)
  - [ ] Generate per-machine node certificates signed by the CA
  - [ ] Store certificates in `inventory/secrets.yaml` (encrypted)
  - [ ] Support certificate rotation workflow
- [ ] Document certificate lifecycle and rotation procedure

### 6.13 Integration Testing

- [ ] Create test Ignition configs for each role
- [ ] Boot base image in QEMU with Ignition config via fw_cfg
- [ ] Verify first-boot behavior:
  - [ ] ext4 root partition mounted read-only
  - [ ] ANDYL-ZFS partition created on remaining disk space
  - [ ] ZFS pool `datapool` created successfully
  - [ ] ZFS datasets created: `datapool/var`, `datapool/var/lib`, `datapool/var/log`, `datapool/etc-overlay`
  - [ ] `/var` is mounted from ZFS dataset (verify with `mount | grep datapool`)
  - [ ] `/etc/hostname` set correctly
  - [ ] `/etc/andyl-os/role` set correctly
  - [ ] SSH access works with authorized key
  - [ ] Network configuration applied (static IP or DHCP)
  - [ ] TLS certificates installed at correct paths with correct permissions
  - [ ] Role-specific files created
  - [ ] systemd units from Ignition are enabled and started
  - [ ] ZFS setup completion marker exists: `/var/lib/andyl-os/zfs-setup-complete`
- [ ] Verify second-boot behavior:
  - [ ] Ignition does NOT run again (first-boot only)
  - [ ] `andyl-os-zfs-setup.service` does NOT run again (completion marker exists)
  - [ ] ZFS pool imported normally via `zfs-import-cache.service`
  - [ ] All first-boot configuration persists (on ZFS datasets)
- [ ] Test with deliberately invalid config:
  - [ ] Verify Ignition fails cleanly (all-or-nothing)
  - [ ] Verify the machine does not boot to an inconsistent state

### 6.14 justfile Targets

- [ ] Add `ignition-generate` target: generates all Ignition configs from inventory
- [ ] Add `ignition-validate` target: validates all generated configs
- [ ] Add `ignition-serve port` target: starts HTTP config server for bare-metal provisioning
- [ ] Add `certs-generate` target: generates TLS certificates

## Acceptance Criteria

1. Ignition runs during first boot in initrd and applies all configuration
2. ZFS pool and datasets are created on first boot via `andyl-os-zfs-setup.service`
3. Machine hostname, role, network config, SSH keys, and TLS certificates are correctly applied
4. Ignition writes persist through the `/etc` overlay mechanism (upper layer on ZFS)
5. Ignition runs only once (first-boot marker consumed)
6. ZFS setup runs only once (completion marker prevents re-execution)
7. Config generation script produces valid Ignition JSON for all machines in inventory
8. Each role template produces a valid, complete configuration (including ZFS partition config)
9. Config delivery works via QEMU fw_cfg (development) and HTTP server (production)
10. Invalid Ignition configs fail cleanly without partially configuring the machine
11. Second boot does not re-run Ignition; ZFS pool imports normally; all changes persist
12. cloud-init fallback produces equivalent results to Ignition for environments that require it

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Ignition + /etc overlay interaction is fragile | High | Files not visible after boot | Test both write strategies (upper dir vs. sysroot); pick the working one |
| Ignition dracut module incompatible with our custom initrd | Medium | Ignition doesn't run | Study Ignition's dracut module requirements; may need custom dracut module |
| Secrets leak in generated configs | Medium | Security breach | Use sops/age encryption; generate configs in memory where possible; restrict access |
| Certificate rotation requires re-running Ignition (but it's first-boot only) | High | Can't rotate certs | Plan secondary config management for post-first-boot changes (systemd drop-ins, etc.) |
| Butane/Ignition version incompatibility | Low | Transpilation errors | Pin Butane and Ignition versions; test with specific Ignition spec version |
| Cloud provider metadata endpoint format differences | Medium | Ignition can't fetch config on some clouds | Test each cloud provider; use provider-specific Ignition platform IDs |
| ZFS pool creation fails on first boot (disk layout mismatch) | Medium | No writable /var, system unusable | Test with multiple disk sizes/types; use by-partlabel for stable device naming |
| ZFS kernel module not available in initrd/early boot | Medium | ZFS setup service fails | Ensure ZFS modules are in initrd; test module loading in andyl-os-zfs-setup.service |
| cloud-init ZFS setup races with services needing /var | Medium | Services fail on first boot | Use bootcmd stage; add systemd ordering dependencies; document limitations |

## Estimated Complexity

**L (Large)**

Ignition integration touches the initrd, the boot flow, the `/etc` overlay, and fleet management tooling. The Butane templating system with Jinja2 adds a code-generation layer. Testing requires QEMU with multiple config variants. The interaction between Ignition's write timing and the overlay filesystem is the most technically challenging aspect.
