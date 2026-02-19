# 4. Cloud-Init Integration

## 4.1 Systemd Units

Four systemd services, defined in a new `modules/services/cloud-init.nix`:

```ini
# cloud-init-local.service
# Before networking. Reads local datasources (NoCloud, ConfigDrive).
[Unit]
Description=AOS Cloud-Init (Local)
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target systemd-networkd.service
ConditionPathExists=!/var/lib/cloud/instance/boot-finished

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/cloud-init init --local
TimeoutStartSec=120
```

```ini
# cloud-init.service
# After networking. Fetches metadata from IMDS, applies role config.
[Unit]
Description=AOS Cloud-Init (Network)
After=network-online.target cloud-init-local.service
Wants=network-online.target
ConditionPathExists=!/var/lib/cloud/instance/boot-finished

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/cloud-init init
TimeoutStartSec=300
```

```ini
# cloud-config.service
# Module execution: firewall, containerd, k3s configs.
[Unit]
Description=AOS Cloud-Init (Config Modules)
After=cloud-init.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/cloud-init modules --mode=config
TimeoutStartSec=300
```

```ini
# cloud-final.service
# Late-boot: k3s server/agent start, Cilium install, user scripts.
[Unit]
Description=AOS Cloud-Init (Final)
After=cloud-config.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/cloud-init modules --mode=final
ExecStartPost=/usr/bin/touch /var/lib/cloud/instance/boot-finished
TimeoutStartSec=600
```

## 4.2 Datasource Strategy

| Datasource  | Priority    | Transport                          | Use Case                  |
|-------------|-------------|------------------------------------|---------------------------|
| NoCloud     | 1 (local)   | Filesystem label `cidata`          | Bare-metal, libvirt, QEMU |
| ConfigDrive | 2 (local)   | Filesystem label `config-2`        | OpenStack, on-prem        |
| Ec2         | 3 (network) | `http://169.254.169.254/latest/`   | AWS, Hetzner              |
| GCE         | 4 (network) | `http://metadata.google.internal/` | Google Cloud              |
| Azure       | 5 (network) | `http://169.254.169.254/metadata/` | Microsoft Azure           |
| None        | 6 (fallback)| N/A                                | No metadata = base role   |

Default configuration baked into the image at `/etc/cloud/cloud.cfg`:

```yaml
datasource_list: [NoCloud, ConfigDrive, Ec2, GCE, Azure, None]

system_info:
  default_user:
    name: aos
    lock_passwd: true
    groups: [wheel, systemd-journal]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
  distro: aos
  paths:
    cloud_dir: /var/lib/cloud
    run_dir: /run/cloud-init
```

## 4.3 Overlay /etc Interaction

```
Read-only lower (/etc.lower from immutable root):
  os-release, fstab, sysctl.d/, ssh/sshd_config, chrony.conf,
  systemd/network/80-dhcp.network, resolved.conf,
  aos/unit-templates/, cloud/cloud.cfg

Writable upper (/run/etc-upper/upper, tmpfs -- lost on reboot):
  Cloud-init writes: systemd/system/*.service, nftables.conf,
  containerd/config.toml, rancher/k3s/config.yaml,
  ssh/authorized_keys/*, hostname, aos/active-role
```

Because the upper layer is tmpfs, cloud-init re-applies on every boot.
Configuration drift is impossible. Role changes take effect on reboot by
updating the datasource.

**Interaction with generations**: The generation determines the **available
software** (package closure in the store). Cloud-init determines the
**active configuration** (which services run, network config, etc.).
Switching generations may change available packages or unit templates, but
cloud-init still applies the same role config from the same datasource.
A generation switch followed by cloud-init re-application is the normal
upgrade path.

## 4.4 AOS-Specific Cloud-Init Modules

| Module           | Stage      | Writes                                       | Maps to AOS option           |
|------------------|------------|----------------------------------------------|------------------------------|
| `aos_hostname`   | init-local | `/etc/hostname`                              | `aos.networking.hostName`    |
| `aos_networking` | init-local | `/etc/systemd/network/*.network`, `*.netdev` | `aos.networking.*`           |
| `aos_users`      | config     | `/etc/passwd`, `/etc/group`, `/etc/shadow`   | `aos.users.*`                |
| `aos_ssh_keys`   | config     | `/etc/ssh/authorized_keys/*`                 | `aos.services.ssh.*`         |
| `aos_firewall`   | config     | `/etc/nftables.conf`                         | `aos.firewall.*`             |
| `aos_k3s`        | config     | `/etc/rancher/k3s/config.yaml`, unit files   | `aos.kubernetes.*`           |
| `aos_services`   | config     | systemd unit enable/disable symlinks         | `aos.services.*`             |
| `aos_k3s_start`  | final      | Starts `k3s server` or `k3s agent`           | `aos.kubernetes.role`        |
| `aos_cilium`     | final      | Installs Cilium via Helm (first CP only)     | `aos.kubernetes.cilium.*`    |

## 4.5 Configuration Schema and Examples

### Pure Server (No Kubernetes)

```yaml
#cloud-config
aos:
  role: server
  system:
    hostname: web-prod-01
  users:
    - name: deploy
      uid: 1000
      groups: [wheel]
      ssh_authorized_keys:
        - ssh-ed25519 AAAA... deploy@workstation
  firewall:
    allowed_tcp: [22, 80, 443]
  services:
    chrony: {enable: true}
    fail2ban: {enable: true}
```

Activated: SELinux, audit, hardening, nftables, sshd, chrony, fail2ban.
Kubernetes services remain absent.

### Kubernetes Worker

```yaml
#cloud-config
aos:
  role: k8s-worker
  system:
    hostname: k8s-worker-03
  networking:
    interfaces:
      ens3:
        address: 10.0.3.3/24
        gateway: 10.0.3.1
        dns: [10.0.0.2]
  kubernetes:
    server_url: https://10.0.0.10:6443
    token_file: /run/secrets/k3s-token
    node_labels:
      topology.kubernetes.io/zone: zone1
    containerd:
      registry_mirrors:
        docker.io: https://mirror.internal/v2
  firewall:
    allowed_tcp: [22, 10250]
    allowed_udp: [8472, 51871]
    forward_policy: accept
```

Activated: All server services plus containerd, k3s agent. k3s connects
to the control plane using the provided token.

### Kubernetes Control Plane

```yaml
#cloud-config
aos:
  role: k8s-control-plane
  system:
    hostname: k8s-cp-01
  networking:
    interfaces:
      ens3:
        address: 10.0.0.10/24
        gateway: 10.0.0.1
        dns: [10.0.0.2]
  kubernetes:
    cluster_init: true    # First control plane node
    token_file: /run/secrets/k3s-token
    tls_san:
      - k8s-api.internal
      - 10.0.0.10
    cluster_cidr: 10.244.0.0/16
    service_cidr: 10.96.0.0/12
    node_taints:
      - "node-role.kubernetes.io/control-plane:NoSchedule"
    cilium:
      version: "1.16"
      hubble: true
      gateway_api: true
      ingress: true
      l2_announcements: true
      l2_cidrs: ["10.0.0.128/25"]
  firewall:
    allowed_tcp: [22, 6443, 2379, 2380, 10250, 10257, 10259]
    allowed_udp: [8472, 51871]
    forward_policy: accept
```

Activated: All worker services plus k3s server mode with embedded etcd.
`cloud-final` runs `k3s server --cluster-init` and installs Cilium.

### Joining Control Plane (HA)

```yaml
#cloud-config
aos:
  role: k8s-control-plane
  system:
    hostname: k8s-cp-02
  kubernetes:
    server_url: https://k8s-api.internal:6443
    token_file: /run/secrets/k3s-token
    tls_san:
      - k8s-api.internal
      - 10.0.0.11
```

Joins existing cluster as additional control plane node. `cluster_init`
is omitted (defaults to false), so k3s connects to the existing server.

### No Cloud-Init Data (DataSourceNone)

System boots with image defaults:
- Hostname: `aos`
- Networking: DHCP on all `en*` interfaces
- SSH: enabled, key-only auth, host keys auto-generated
- Firewall: default-deny, port 22 open
- Users: root (locked password), aos service user
- No Kubernetes

The machine is SSH-accessible once an authorized key is added.

## 4.6 State Management

**Per-boot modules** (`aos_hostname`, `aos_networking`, `aos_firewall`,
`aos_k3s`, `aos_services`): run on every boot because the overlay
`/etc` is fresh each time.

**Per-instance modules** (`aos_k3s_start`, `aos_cilium`): k3s detects
existing state on ZFS-backed `/var/lib/rancher/k3s/` and resumes. Cilium
install is idempotent (Helm upgrade).

**Instance-id change**: When the datasource returns a different instance-id,
all per-instance semaphores clear and modules re-run.

**Datasource caching**: Cloud-init caches metadata at
`/var/lib/cloud/instance/obj.pkl` (ZFS-backed). On reboot, if the network
is unreachable, cached data is used.
