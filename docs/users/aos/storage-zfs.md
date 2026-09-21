# ZFS storage

AOS treats ZFS as a bounded tenant of the host rather than as a filesystem that
sizes itself. This page covers what that means in practice, how to declare
datasets, and how to operate a pool.

## Why the defaults look conservative

OpenZFS sizes most of its memory structures from installed RAM rather than from
pool capacity. The ARC target, the scrub sort queue, dnode and dbuf caches, and
write buffering all scale with the machine, so defaults that are unremarkable
on a 64 GiB server permit hundreds of gigabytes on a large host that gains
nothing from them.

Two consequences follow, and both have caused real outages:

- `zfs_arc_max` bounds one structure, not ZFS. A scrub queue sized at a
  twentieth of physical memory sits outside it entirely, and so does the
  deduplication table.
- The ARC target is a target. Metadata that is referenced cannot be evicted on
  demand, so the ARC can sit above its cap while reclaim scans millions of
  candidates and frees nothing.

Separately, allocation *shape* matters as much as size. ZFS allocates
long-lived kernel memory that the page allocator cannot move. With the upstream
default of eight objects per SPL slab, a pool using 1 MiB records asks for
roughly 8 MiB of contiguous unmovable memory per slab. One live object pins the
whole slab, compaction cannot relocate it, and high-order free blocks stop
coalescing. A host in that state reports hundreds of gigabytes free while
failing the allocations that matter.

AOS therefore sets one budget and derives everything from it, keeps records at
128 KiB and SPL slabs at one object unless a host opts out, and reboots on a
kernel oops instead of leaving a wedged storage stack behind.

## The memory budget

```nix
aos.filesystems.zfs.memory = {
  maxBytes = 8 * 1024 * 1024 * 1024;
  maxPercent = 25;
  arcPercent = 70;
  scrubPercent = 10;
  dirtyDataPercent = 15;
};
```

The effective budget is the lesser of `maxBytes` and `maxPercent` of installed
RAM, resolved at boot by `aos-zfs-memory-policy.service`. The absolute ceiling
is what protects a large host; the percentage is what keeps the same
configuration safe on a small one. The share options divide that budget and
must sum to at most 100.

Raise `maxBytes` for a cache-sensitive workload on a host with memory to spare.
Prefer raising it to leaving it unbounded: an explicit number is reviewable, and
a percentage of a large machine is not.

`committedPercentLimit` caps what ZFS and compressed swap may commit together.
It is checked against the running host, because `aos.zram.size` is an
arithmetic expression the module system cannot evaluate.

## Swap

A ZFS host runs no first-boot repart pass, so the encrypted swap partition that
pass creates does not exist. Enabling ZFS therefore enables compressed swap in
RAM, sized at a small share of memory rather than the stock half: reclaim needs
somewhere to put anonymous pages, not a swap device sized like a disk, and
zram's capacity is memory the host can still end up spending.

Never place swap on a zvol. Writing a swap page asks ZFS to allocate the memory
the write exists to reclaim, which deadlocks under exactly the pressure swap is
meant to relieve. The boot-time verification refuses a host configured that
way.

## Declaring datasets

Datasets are declared, then created and converged at boot. A dataset that
exists with the wrong properties is corrected; one that no configuration
declares is reported by `aos-zfs-report-undeclared.service`.

```nix
aos.filesystems.zfs.datasets = {
  "srv/media" = {
    mountPoint = "/srv/media";
    recordSize = "128K";
    compression = "zstd-3";
    quota = "500G";
  };
};
```

Each declared dataset with a mount point gets a generated systemd mount unit,
so ordering and dependencies are explicit. Datasets use a legacy mount point so
systemd owns the mount; a dataset that mounted itself would race the units that
expect it.

Set `aos.filesystems.zfs.systemState = false` for a pool that carries data
only. `/var` then stays on the partition the image provides, along with the
first-boot provisioning and recovery path that comes with it.

### Gated properties

Two properties are refused unless a host opts in, because both convert into
kernel memory that no other limit covers.

| Property | Gate | Why |
|---|---|---|
| Record size above 128 KiB | `allowLargeRecords` | Large records make each buffer-cache slab a large unmovable allocation |
| `deduplicate` | `allowDeduplication` plus `deduplicationTableQuota` | The table is pinned kernel memory sized by unique block count, outside the ARC budget |

Give every dataset a `quota` where you can. A dataset that grows without limit
turns a local problem into a pool-wide one, and in a copy-on-write filesystem a
full pool can refuse the deletes that would relieve it. AOS holds a reservation
(`reservedSpace`) for exactly that case: releasing it gives an operator room to
recover.

## Operating a pool

The event daemon, scheduled scrubs and trims, health checks, and metrics come
from `aos.services.zfsMaintenance`, which follows `aos.filesystems.zfs.enable`.

```sh
systemctl status zfs-zed.service
systemctl list-timers 'aos-zfs-*'
systemctl start aos-zfs-health.service
zpool status -v
```

`aos-zfs-health.service` fails when the pool is not online, when devices have
accumulated read, write, or checksum errors, or when the pool pins no feature
set. A failing health check appears in `systemctl --failed`.

### Replacing a failed device

```sh
zpool status -v
zpool offline rpool <old-device>
# physically replace the device, then:
zpool replace rpool <old-device> /dev/disk/by-id/<new-device>
zpool status 1
```

Resilver rebuilds only the replaced device. A scrub afterwards is what confirms
the rest of the pool survived whatever took it out, and
`scrubAfterResilver` starts one automatically.

### Expanding a pool

Add redundancy groups rather than single devices; a striped addition makes the
whole pool depend on the new device.

```sh
zpool add rpool mirror /dev/disk/by-id/<new-a> /dev/disk/by-id/<new-b>
zpool list -v rpool
```

A vdev cannot be removed from a pool that contains a RAIDZ vdev, so treat
`zpool add` as permanent and check the layout before running it.

### Pool features and rollback

The installer creates the pool with a pinned feature set
(`aos.boot.storage.zfs.compatibility`). A pool that enables every feature its
creating release supports can stop being importable by an older release, and on
an A/B image that is the slot rollback depends on.

Nothing in AOS runs `zpool upgrade`. Enabling new features is a deliberate
step, taken once every slot that could be rolled back to can read them.

## Reading the telemetry

`aos-zfs-metrics.service` publishes `/var/lib/aos-metrics/zfs.prom` in the
Prometheus textfile format. The series worth alerting on are the ones that move
before anything else does:

| Series | What a bad value looks like |
|---|---|
| `aos_zfs_arc_bytes` against `aos_zfs_arc_target_bytes` | Size persistently above target |
| `aos_zfs_arc_metadata_bytes{state="pinned"}` | Growing while `state="evictable"` does not |
| `aos_zfs_arc_evict_skip_total` | Rising by millions per minute |
| `aos_memory_free_blocks` at high orders | Reaching zero while the host reports ample free memory |
| `aos_memory_compaction_total{outcome="fail"}` | Rising steadily |

Free memory and pool capacity are lagging indicators. A host can show hundreds
of gigabytes free, a healthy pool, and no swap use while already unable to
satisfy a higher-order allocation.

## When configuration is not what is running

Several ZFS parameters are read only when the module loads. SPL slab geometry
is fixed as each cache is created and cannot be corrected at runtime, so a host
that applied new configuration without rebooting keeps its previous allocation
policy with no other visible signal.

`aos-zfs-verify-parameters.service` exists to make that visible. It fails when:

- a load-time parameter does not match the configuration, naming the parameter
  and saying a reboot is required;
- the ARC ceiling is above the configured budget;
- the OpenZFS userland and the loaded kernel module report different versions,
  which is what a live upgrade without a reboot produces;
- a swap device is backed by a zvol, where writing a swap page asks ZFS to
  allocate the memory the write is trying to free;
- ZFS and compressed swap together commit more than `committedPercentLimit`.

```sh
systemctl status aos-zfs-verify-parameters.service
journalctl -u aos-zfs-verify-parameters.service
```

## Recovery

The recovery environment carries the ZFS kernel module and userland, so a
recovery boot can import the pool holding the host's state.

```sh
zpool import
zpool import -N -f rpool
zfs load-key -a
zfs mount -a
```

Keep the recovery key produced at install time
(`--recovery-key-output`) outside the host. Without it, a pool whose TPM-sealed
key can no longer be released is unrecoverable.

## See also

- [Installation](installation.md) for creating the pool
- [Operations](operations.md) for day-to-day host inspection
- [Recovery](recovery.md) for the signed recovery environment
