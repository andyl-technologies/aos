# Cloud-Init Integration

The AOS cloud-init module (`cc_aos`) provides native cloud-init support for
configuring the AOS daemon. It is a superset of the daemon TOML config —
everything configurable in `daemon.toml` is also configurable via cloud-init,
plus additional systemd service and slice configuration that controls the
daemon's own resource limits.

## NixOS Module

The cloud-init module is implemented as a NixOS module
(`modules/cloud-init-aos.nix`) that generates cloud-init module configuration
from the NixOS module system. This gives full type-checking, option
validation, and merge semantics at evaluation time — before the instance
boots.

## Cloud-Init Config Schema

```yaml
#cloud-config
aos:
  # --- Network-wide (maps to daemon.toml sections) ---
  network:
    seed_peers:
      - /ip4/10.0.1.1/udp/4001/quic-v1/p2p/QmSeed1
      - /ip4/10.0.2.1/udp/4001/quic-v1/p2p/QmSeed2

  store:
    db_dir: /var/lib/aos/db
    chunk_dir: /var/lib/aos/chunks
    gc:
      budget: 500GB
      target: 0.8
    replication:
      reserved: "100Gi"

  volumes:
    zfs_pool: aos                    # ZFS pool name for volume datasets

  workflows:
    max_steps: 10000
    max_depth: 500
    max_concurrent: 100
    sync_window: 60
    accept_remote: false

  # --- Daemon systemd service configuration ---
  # Controls the aos-daemon.service unit and the parent slice hierarchy.
  service:
    # Resource limits for the daemon process itself (not jobs).
    # These apply to the aos-daemon.service unit.
    memory_max: 2G
    memory_high: 1G
    cpu_weight: 200             # daemon gets higher CPU priority than jobs

    # Aggregate resource limits for ALL cluster workloads.
    # These apply to the aos-clusters.slice (parent of per-cluster slices).
    clusters_slice:
      cpu_quota: 75%            # all jobs across all clusters capped at 75% CPU
      memory_max: 56G           # all jobs across all clusters capped at 56G
      io_weight: 100

  # --- Per-cluster configuration ---
  clusters:
    prod:
      ucan_file: /etc/aos/prod.ucan
      node:
        system: x86_64-linux
        features:
          - kvm
          - big-parallel
        labels:
          rack: r1
          gpu: a100
          region: us-east
        taints:
          - key: dedicated
            value: ci
            effect: NoSchedule
      jobs:
        max_concurrent: 8
        accept_remote: false
      slice:
        cpu_weight: 100
        memory_max: 32G
        memory_high: 30G
        io_weight: 100

    staging:
      ucan_file: /etc/aos/staging.ucan
      node:
        system: x86_64-linux
        features:
          - kvm
      jobs:
        max_concurrent: 4
        accept_remote: true
      slice:
        cpu_weight: 50
        memory_max: 16G
        memory_high: 14G
        io_weight: 50
```

## Systemd Unit Hierarchy

The cloud-init module generates the following systemd hierarchy:

```
-.slice (root)
  └── aos-daemon.service                 (the daemon process itself)
  └── aos-clusters.slice                 (aggregate: ALL cluster workloads)
      ├── aos-cluster-prod.slice         (prod cluster workloads)
      │   ├── aos-cluster-prod-job-abc123.scope
      │   └── aos-cluster-prod-job-def456.scope
      └── aos-cluster-staging.slice      (staging cluster workloads)
          └── aos-cluster-staging-job-ghi789.scope
```

### Why Separate the Daemon from Clusters

The daemon process (`aos-daemon.service`) and the cluster workloads
(`aos-clusters.slice`) have different resource characteristics:

- The **daemon** is a system service: it must always be responsive for mesh
  communication, DHT queries, GossipSub message validation, and stream
  protocol handling. It should not be starved by job workloads.
- **Cluster workloads** (nspawn containers) are batch compute: they can
  tolerate CPU contention and memory pressure.

By placing them in separate cgroup subtrees, the daemon's resource limits
(`service.memory_max`, `service.cpu_weight`) are independent of the aggregate
cluster limits (`service.clusters_slice.*`). The daemon can use its full
allocation even when all cluster slices are saturated.

### Resource Flow

```
Host total: 64 GB RAM, 16 cores
  │
  ├── aos-daemon.service:    memory_max=2G, cpu_weight=200
  │     (daemon process, mesh, DHT, GossipSub)
  │
  └── aos-clusters.slice:    memory_max=56G, cpu_quota=75%
        │                    (aggregate limit for ALL jobs)
        │
        ├── aos-cluster-prod.slice:     memory_max=32G, cpu_weight=100
        │     (prod jobs compete within this slice)
        │
        └── aos-cluster-staging.slice:  memory_max=16G, cpu_weight=50
              (staging jobs compete within this slice)

  Remaining: ~6 GB RAM, 25% CPU for OS, kernel, other services
```

The hierarchy ensures:
- The daemon always has 2 GB RAM and high CPU priority, regardless of job load.
- All jobs across all clusters are capped at 75% CPU and 56 GB RAM.
- Within the 56 GB, prod gets up to 32 GB and staging gets up to 16 GB.
- The remaining ~6 GB and 25% CPU are available for the OS, kernel, sshd, etc.

### Slice Configuration Reference

**`service` section** (applied to `aos-daemon.service`):

| Field | systemd Property | Description |
|---|---|---|
| `memory_max` | `MemoryMax` | Hard memory limit for the daemon process |
| `memory_high` | `MemoryHigh` | Memory pressure threshold for the daemon |
| `cpu_weight` | `CPUWeight` | Relative CPU priority (higher = preferred over jobs) |

**`service.clusters_slice` section** (applied to `aos-clusters.slice`):

| Field | systemd Property | Description |
|---|---|---|
| `cpu_quota` | `CPUQuota` | Hard CPU cap for all jobs combined (e.g., `75%`) |
| `memory_max` | `MemoryMax` | Hard memory limit for all jobs combined |
| `memory_high` | `MemoryHigh` | Memory pressure threshold for all jobs |
| `io_weight` | `IOWeight` | Relative I/O share for all jobs |

**`clusters.X.slice` section** (applied to `aos-cluster-{X}.slice`):

| Field | systemd Property | Description |
|---|---|---|
| `cpu_weight` | `CPUWeight` | Relative CPU share within the clusters slice |
| `memory_max` | `MemoryMax` | Hard memory limit for this cluster's jobs |
| `memory_high` | `MemoryHigh` | Memory pressure threshold |
| `io_weight` | `IOWeight` | Relative I/O share within the clusters slice |

## Module Behavior

### Schema Validation

The cloud-init module validates the config at cloud-init time, before the
daemon starts. Invalid config (missing required fields, type errors,
inconsistent resource limits) fails the cloud-init stage with a clear error
rather than a daemon crash loop.

Validation checks include:
- At least one seed peer specified
- At least one cluster configured
- Per-cluster slice memory_max does not exceed clusters_slice memory_max
- `max_concurrent` is positive
- `features` and `labels` values are strings
- `effect` is one of `NoSchedule`, `PreferNoSchedule`, `NoExecute`

### Merge Semantics

Cloud-init supports merging configs from multiple sources (vendor data, user
data, instance metadata). The AOS module handles merges correctly:

- **Vendor data** provides defaults (seed peers, store paths, default cluster
  config).
- **User data** overrides specific fields (cluster membership, features,
  labels, resource shares).
- **Instance metadata** can inject auto-detected values (see below).

Standard cloud-init merge rules apply: later sources override earlier sources
at the key level.

### Auto-Detection

The module can read instance metadata and inject values automatically:

| Source | Injected as |
|---|---|
| Instance type (e.g., `m5.4xlarge`) | Auto-computed `memory_max` and `cpu_quota` |
| Availability zone | `node.labels.az` |
| Region | `node.labels.region` |
| Instance ID | `node.labels.instance_id` |
| GPU presence (e.g., `p3.2xlarge`) | `node.features` += `gpu` |
| NVMe local disks | `node.features` += `local-ssd`, auto-set `chunk_dir` |
| NVMe local disks (ZFS) | If NVMe local disks are detected and no ZFS pool named `volumes.zfs_pool` exists, the cloud-init module creates it automatically. |

Auto-detected values are defaults — explicit config overrides them.

### Secrets Integration

The module can fetch sensitive values from cloud provider secrets managers
rather than embedding them in userdata:

```yaml
aos:
  clusters:
    prod:
      ucan_source:
        type: aws_secretsmanager
        secret_id: aos/prod/ucan
```

Supported sources (cloud-provider-specific):
- `aws_secretsmanager` — AWS Secrets Manager
- `aws_ssm` — AWS Systems Manager Parameter Store
- `gcp_secretmanager` — GCP Secret Manager
- `file` — local file path (for pre-provisioned instances)

The module fetches the secret at cloud-init time, writes it to `ucan_file`,
and sets restrictive permissions (0600).

### Idempotency

The module tracks whether it has already run via a sentinel file. Re-running
cloud-init on reboot does not regenerate the config, re-create slices, or
re-fetch secrets. To force reconfiguration, delete the sentinel and re-run.

### Generated Artifacts

The module generates:

| Artifact | Path | Description |
|---|---|---|
| Daemon config | `/etc/aos/daemon.toml` | Generated from the `aos` cloud-config block |
| Systemd service override | `/etc/systemd/system/aos-daemon.service.d/cloud-init.conf` | Resource limits for the daemon process |
| Clusters slice | `/etc/systemd/system/aos-clusters.slice` | Aggregate resource limits for all jobs |
| Per-cluster slices | `/etc/systemd/system/aos-cluster-{name}.slice` | Per-cluster resource limits |
| UCAN files | `/etc/aos/{cluster}.ucan` | Fetched from secrets source |
| Sentinel | `/var/lib/aos/.cloud-init-done` | Idempotency marker |

## LoadReport Integration

The daemon's LoadReport for each cluster reflects the cgroup hierarchy:

- **`ResourceCapacity.total`** is read from the cluster's cgroup limits
  (`aos-cluster-{name}.slice`). If `memory_max = 32G`, that's the total.
- **`ResourceCapacity.reserved`** is computed from overhead: the daemon's own
  resource usage (from `aos-daemon.service` cgroup) divided proportionally
  across clusters, plus any resources consumed by the OS outside the AOS
  cgroup hierarchy.
- **`ResourceState.active/claimed/free`** is read from the cluster's cgroup
  `memory.current`, `cpu.stat`, etc.

The `ResourceState.local_space` field in LoadReports is derived from the ZFS
pool's available space minus persistent volume reservations.

This ensures that each cluster's LoadReport accurately reflects the resources
available to its workloads, accounting for the daemon's overhead and
cross-cluster isolation.

## Example: Auto-Scaling Group

A launch template for an ASG where every instance joins the prod cluster as
a builder:

```yaml
#cloud-config
merge_how:
  - name: list
    settings: [append]
  - name: dict
    settings: [recurse_array]

aos:
  network:
    seed_peers:
      - /ip4/10.0.1.1/udp/4001/quic-v1/p2p/QmSeed1

  store:
    chunk_dir: /var/lib/aos/chunks
    gc:
      budget: 80%                # use 80% of available disk
    replication:
      reserved: "50Gi"

  service:
    memory_max: 2G
    cpu_weight: 200
    clusters_slice:
      cpu_quota: 90%
      memory_max: auto           # auto-detect from instance type

  clusters:
    prod:
      ucan_source:
        type: aws_secretsmanager
        secret_id: aos/prod/builder-ucan
      node:
        system: x86_64-linux
        features:
          - kvm
          - big-parallel
        # labels.az and labels.region auto-detected from instance metadata
      jobs:
        max_concurrent: auto     # auto-detect from instance CPU count
        accept_remote: true
      slice:
        cpu_weight: 100
        memory_max: auto         # auto-detect, apply clusters_slice proportionally
```

The `auto` value triggers auto-detection from the instance type and cgroup
hierarchy. For an `m5.4xlarge` (16 vCPU, 64 GB RAM):
- `clusters_slice.memory_max` = auto → `~56 GB` (64 GB - 2 GB daemon - ~6 GB OS)
- `clusters.prod.slice.memory_max` = auto → `~56 GB` (only cluster, gets all)
- `clusters.prod.jobs.max_concurrent` = auto → `14` (16 vCPU - 2 reserved)

## Relationship to Other Docs

- [daemon.md](daemon.md) -- daemon architecture, TOML config format, systemd
  slice hierarchy.
- [scheduling.md](scheduling.md) -- how LoadReports from cgroup stats influence
  scheduling decisions.
- [load-reports.md](load-reports.md) -- LoadReport format and resource state
  model.
- [volumes.md](volumes.md) -- volume types, ZFS dataset lifecycle.
- [auth.md](auth.md) -- UCAN chain and cluster identity (referenced by
  `ucan_file` / `ucan_source`).
