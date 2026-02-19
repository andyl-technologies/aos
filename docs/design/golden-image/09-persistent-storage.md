# 9. Persistent Storage (ZFS)

## 9.1 ZFS Dataset Layout

```
aos-pool/
  aos-pool/var           -> /var                    (general state)
  aos-pool/var/log       -> /var/log                (journals, audit)
  aos-pool/containerd    -> /var/lib/containerd     (container images/layers)
  aos-pool/k3s           -> /var/lib/rancher/k3s    (k3s state, embedded etcd)
  aos-pool/etcd          -> /var/lib/rancher/k3s/server/db/etcd  (dedicated)
  aos-pool/cloud         -> /var/lib/cloud          (cloud-init state)
  aos-pool/ssh           -> /var/lib/ssh            (host keys)
  aos-pool/pvs           -> /var/lib/aos-zfs-pv     (CSI persistent volumes)
```

**etcd dataset tuning**:
- `recordsize=4K` (matches etcd page size)
- `sync=always` (etcd requires fsync)
- `compression=lz4`

**containerd dataset tuning**:
- `recordsize=128K` (large sequential reads for image layers)
- `compression=lz4`

**PV dataset tuning**:
- `recordsize=128K` (default, overridable per-PV via StorageClass)
- `compression=lz4`
- `quota` set per-PV to enforce capacity limits

## 9.2 ZFS CSI Driver for Persistent Volumes

The golden image includes a ZFS-based CSI driver that provisions
Kubernetes PersistentVolumes as ZFS datasets under `aos-pool/pvs/`:

```
aos-pool/pvs/
  pvc-abc123   -> mounted into pod via CSI NodePublish
  pvc-def456   -> mounted into pod via CSI NodePublish
```

**StorageClass**:

```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: aos-zfs
provisioner: zfs.aos.dev
parameters:
  poolname: aos-pool/pvs
  recordsize: "128k"
  compression: "lz4"
reclaimPolicy: Delete
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
```

**CSI driver deployment**: Installed as a k3s manifest at
`/var/lib/rancher/k3s/server/manifests/zfs-csi.yaml`. The driver runs as
a DaemonSet (node plugin) + Deployment (controller) in `kube-system`.

**Capabilities**:

| Feature | Supported | Notes |
|---------|-----------|-------|
| Dynamic provisioning | Yes | Creates ZFS dataset per PVC |
| Volume expansion | Yes | `zfs set quota=<new-size>` |
| Snapshots | Yes | ZFS snapshots, VolumeSnapshot CRD |
| Clones | Yes | ZFS clone from snapshot |
| ReadWriteOnce | Yes | Local node mount |
| ReadWriteMany | No | Local storage only (not distributed) |
| Capacity tracking | Yes | Reports ZFS pool free space |
| Encryption | Yes | ZFS native encryption per-dataset |

**Snapshot example**:

```yaml
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata:
  name: db-snapshot
spec:
  volumeSnapshotClassName: aos-zfs-snapshot
  source:
    persistentVolumeClaimName: postgres-data
```

This creates a ZFS snapshot `aos-pool/pvs/pvc-abc123@db-snapshot` which
can be restored as a new PVC.

## 9.3 State Persistence Across Generation Switches

| Path | Survives Reboot | Survives Generation Switch |
|------|:---------------:|:--------------------------:|
| `/` (root) | Yes | No (new generation root) |
| `/etc` (overlay) | No (tmpfs) | No |
| `/boot` (ESP) | Yes | Yes |
| `/var/lib/store` | **Yes** | **Yes** (holds all generations) |
| `/var` (ZFS) | **Yes** | **Yes** |
| `/var/lib/cloud` | **Yes** | **Yes** |
| `/var/lib/containerd` | **Yes** | **Yes** |
| `/var/lib/rancher/k3s` | **Yes** | **Yes** |
| `/var/lib/rancher/k3s/server/db/etcd` | **Yes** | **Yes** |
| `/var/lib/aos-zfs-pv` | **Yes** | **Yes** |
| `/var/lib/ssh/host_keys` | **Yes** | **Yes** |
| `/var/log` | **Yes** | **Yes** |

Cloud-init re-generates all `/etc` config from (new generation) + (same
userdata). Container images, etcd data, k3s state, ZFS persistent
volumes, SSH host keys, and logs survive. The store partition retains
all generations until explicitly removed by `aos gc --generations`.
