;;; ANDYL OS -- ZFS Pool and Dataset Setup Service (First Boot)
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the andyl-os-zfs-setup.service, a first-boot
;;; oneshot systemd unit that creates the ZFS pool and datasets on the
;;; ANDYL-ZFS partition provisioned by Ignition.
;;;
;;; This module is the single source of truth for the ZFS dataset layout.
;;; The andyl-os-zfs-setup.service creates the datapool and all datasets
;;; with correct properties.  Role-specific datasets (etcd, postgresql)
;;; are created conditionally based on the machine role file written by
;;; Ignition at /etc/andyl-os/role.
;;;
;;; First-boot execution order:
;;;
;;;   Ignition (initrd)
;;;     -> creates ANDYL-ZFS partition (partition 3, remaining disk space)
;;;     -> writes /etc/andyl-os/role (machine role)
;;;     -> enables andyl-os-zfs-setup.service
;;;   switch-root
;;;     -> andyl-os-zfs-setup.service runs (this module)
;;;       -> modprobe zfs
;;;       -> zpool create datapool on ANDYL-ZFS
;;;       -> create core datasets (var, var/lib, var/log, etc-overlay, ...)
;;;       -> create role-specific datasets (containerd, etcd, postgresql)
;;;       -> write completion marker
;;;     -> ZFS datasets are mounted
;;;     -> /etc overlay mounts (upper = datapool/etc-overlay)
;;;     -> services start
;;;
;;; On subsequent boots:
;;;   - ConditionPathExists guard prevents re-execution
;;;   - zfs-import-cache.service imports the pool normally
;;;
;;; See:
;;;   RFC-0006 section 3 (ZFS Pool and Dataset Creation)
;;;   RFC-0001 section 5 (/var as the Writable Persistent Area)
;;;   Phase 6 section 6.4 (ZFS Pool and Dataset Setup)

(define-module (andyl services zfs-setup)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:export (%andyl-zfs-setup-completion-marker
            %andyl-zfs-setup-unit
            %andyl-zfs-setup-tmpfiles
            andyl-zfs-setup-units))


;;;
;;; Completion marker path
;;;
;;; After successful ZFS pool and dataset creation, this file is
;;; created.  The ConditionPathExists guard in the service unit
;;; checks for this file to skip execution on subsequent boots.
;;;

(define %andyl-zfs-setup-completion-marker
  "/var/lib/andyl-os/zfs-setup-complete")


;;;
;;; andyl-os-zfs-setup.service
;;;
;;; Creates the ZFS pool "datapool" on the ANDYL-ZFS partition and
;;; the full dataset hierarchy.  This is the most critical first-boot
;;; service: without it, /var, /etc overlay, and all mutable state
;;; have no backing storage.
;;;
;;; ZFS dataset layout:
;;;
;;;   datapool                                    Pool on ANDYL-ZFS partition
;;;     datapool/var                    /var       Persistent mutable state
;;;       datapool/var/lib              /var/lib   Application state
;;;         datapool/var/lib/containerd /var/lib/containerd  Container images
;;;         datapool/var/lib/etcd       /var/lib/etcd        etcd data (control-plane)
;;;         datapool/var/lib/postgresql /var/lib/postgresql   PostgreSQL data (database)
;;;       datapool/var/log              /var/log   Logs (quota=2G)
;;;       datapool/var/tmp              /var/tmp   Persistent temp
;;;     datapool/etc-overlay            (none)     /etc overlay upper layer
;;;
;;; Pool-level defaults:
;;;   ashift=12         4K sector alignment (correct for modern SSDs/HDDs)
;;;   autotrim=on       TRIM/UNMAP for SSDs
;;;   compression=zstd-3  Zstandard compression (good ratio + speed)
;;;   atime=off         No access time updates (reduces write I/O)
;;;   xattr=sa          Store extended attributes in inode (SELinux labels)
;;;   acltype=posixacl  POSIX ACL support
;;;   dnodesize=auto    Automatic dnode sizing for metadata-heavy workloads
;;;
;;; Dataset-specific overrides:
;;;   containerd: recordsize=128K (matches container layer chunk size)
;;;   etcd:       recordsize=4K   (matches etcd's 4K page writes)
;;;   postgresql: recordsize=8K   (matches PostgreSQL 8K page size)
;;;   var/log:    quota=2G        (prevent log storms from filling the pool)
;;;

(define %andyl-zfs-setup-unit
  (string-append
   "\
[Unit]
Description=Create ZFS pool and datasets (first boot)
Documentation=man:zpool(8) man:zfs(8)

# Run only on first boot.  The completion marker is created after
# successful ZFS setup.  On subsequent boots this service is skipped,
# and zfs-import-cache.service imports the pool normally.
ConditionPathExists=!" %andyl-zfs-setup-completion-marker "

# Ordering: must run after udev has settled (so /dev/disk/by-partlabel/
# symlinks exist) but before anything that needs /var.
DefaultDependencies=no
Before=local-fs.target var.mount
After=systemd-udevd.service
Requires=systemd-udevd.service

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=/usr/bin/bash -c '\
  set -euo pipefail; \
  \
  echo \"ANDYL OS ZFS Setup: creating datapool and datasets\"; \
  \
  # Load the ZFS kernel module. \
  modprobe zfs; \
  \
  # Wait for the ANDYL-ZFS partition device node to appear. \
  # Ignition created this partition in the initrd. \
  udevadm settle --timeout=30; \
  \
  if [ ! -e /dev/disk/by-partlabel/ANDYL-ZFS ]; then \
    echo \"ERROR: /dev/disk/by-partlabel/ANDYL-ZFS not found\"; \
    echo \"Ignition may not have partitioned the disk correctly.\"; \
    exit 1; \
  fi; \
  \
  # --- Create the ZFS pool --- \
  # Using by-partlabel for stable device naming across reboots. \
  zpool create -f \
    -o ashift=12 \
    -o autotrim=on \
    -O compression=zstd-3 \
    -O atime=off \
    -O xattr=sa \
    -O acltype=posixacl \
    -O dnodesize=auto \
    datapool /dev/disk/by-partlabel/ANDYL-ZFS; \
  echo \"ZFS pool datapool created\"; \
  \
  # --- Create core datasets --- \
  zfs create -o mountpoint=/var datapool/var; \
  zfs create -o mountpoint=/var/lib datapool/var/lib; \
  zfs create -o mountpoint=/var/log -o quota=2G datapool/var/log; \
  zfs create -o mountpoint=/var/tmp datapool/var/tmp; \
  echo \"Core datasets created: var, var/lib, var/log, var/tmp\"; \
  \
  # --- Container storage --- \
  # 128K recordsize matches container layer chunk sizes for \
  # optimal I/O alignment with containerd/overlayfs2. \
  zfs create -o mountpoint=/var/lib/containerd \
    -o recordsize=128K datapool/var/lib/containerd; \
  echo \"Container dataset created: var/lib/containerd (recordsize=128K)\"; \
  \
  # --- /etc overlay upper layer --- \
  # Stores machine-specific config written by Ignition (hostname, \
  # network, SSH keys, certs).  Backs the OverlayFS upper layer. \
  zfs create -o mountpoint=/var/etc-overlay datapool/etc-overlay; \
  echo \"/etc overlay dataset created: etc-overlay\"; \
  \
  # Work directory for OverlayFS (must be on same filesystem as upper). \
  mkdir -p /var/etc-overlay-work; \
  \
  # --- Role-specific datasets --- \
  # Read the machine role from Ignition-written config. \
  ROLE=\"\"; \
  if [ -f /etc/andyl-os/role ]; then \
    ROLE=$(cat /etc/andyl-os/role); \
  fi; \
  \
  # etcd dataset for control plane nodes. \
  # recordsize=4K matches etcd bbolt page size for optimal \
  # write amplification. \
  if [ \"$ROLE\" = \"k8s-control-plane\" ]; then \
    zfs create -o mountpoint=/var/lib/etcd \
      -o recordsize=4K datapool/var/lib/etcd; \
    echo \"Control plane dataset created: var/lib/etcd (recordsize=4K)\"; \
  fi; \
  \
  # PostgreSQL dataset for database nodes. \
  # recordsize=8K matches PostgreSQL page size (8192 bytes). \
  if [ \"$ROLE\" = \"database\" ]; then \
    zfs create -o mountpoint=/var/lib/postgresql \
      -o recordsize=8K datapool/var/lib/postgresql; \
    echo \"Database dataset created: var/lib/postgresql (recordsize=8K)\"; \
  fi; \
  \
  # --- Create state directory and completion marker --- \
  mkdir -p /var/lib/andyl-os; \
  touch " %andyl-zfs-setup-completion-marker "; \
  \
  echo \"ANDYL OS ZFS Setup complete.\"; \
  zfs list -o name,mountpoint,used,avail,recordsize,compression datapool -r'

[Install]
WantedBy=local-fs.target
"))


;;;
;;; tmpfiles.d configuration for ZFS-related directories
;;;
;;; Ensures directories that need to exist on /var are created on
;;; every boot.  These are created by tmpfiles.d after ZFS datasets
;;; are mounted, complementing the first-boot dataset creation.
;;;

(define %andyl-zfs-setup-tmpfiles
  "\
# ANDYL OS ZFS dataset auxiliary directories
# Created on every boot after ZFS datasets are mounted.

# ANDYL OS state directory (completion markers, agent state)
d /var/lib/andyl-os 0755 root root -

# systemd journal persistent storage on ZFS
d /var/log/journal 2755 root systemd-journal -

# systemd persistent state
d /var/lib/systemd 0755 root root -

# /etc overlay OverlayFS work directory
d /var/etc-overlay-work 0755 root root -
")


;;;
;;; Collected unit files
;;;

(define (andyl-zfs-setup-units)
  "Return an alist of (filename . content) pairs for the ZFS setup
service and related configuration."
  (list
   ;; ZFS pool and dataset creation (first boot)
   (cons "lib/systemd/system/andyl-os-zfs-setup.service"
         %andyl-zfs-setup-unit)

   ;; tmpfiles.d for auxiliary directories
   (cons "lib/tmpfiles.d/andyl-zfs-setup.conf"
         %andyl-zfs-setup-tmpfiles)))
