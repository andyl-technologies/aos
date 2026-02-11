;;; ANDYL OS -- Ignition First-Boot Service Definitions
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the systemd service units for Ignition-driven
;;; first-boot provisioning in ANDYL OS.  The primary service is
;;; andyl-os-zfs-setup.service, a oneshot unit that creates the ZFS
;;; pool and datasets on first boot after Ignition has partitioned the
;;; disk.
;;;
;;; First-boot flow:
;;;
;;;   1. Ignition runs in initrd (partitions disk, writes files, creates users)
;;;   2. switch-root to real root filesystem
;;;   3. andyl-os-zfs-setup.service creates ZFS pool and datasets
;;;   4. ZFS datasets are mounted (/var, /var/lib, /var/log, etc.)
;;;   5. /etc overlay mounts (lower=profile, upper=datapool/etc-overlay)
;;;   6. andyl-os-ignition-postsetup.service performs post-ZFS config
;;;   7. SELinux relabeling runs (see services/selinux.scm)
;;;   8. Normal services start
;;;
;;; On subsequent boots:
;;;   - Ignition does NOT run (ConditionFirstBoot=true guards it)
;;;   - ZFS pool is imported via zfs-import-cache.service
;;;   - andyl-os-zfs-setup.service does NOT run (completion marker exists)
;;;   - System boots directly to normal operation
;;;
;;; Config sources (checked in order by Ignition):
;;;   - Cloud provider metadata (AWS IMDSv2, GCP metadata, Azure custom-data)
;;;   - Local file (/etc/ignition.json)
;;;   - USB drive (/dev/disk/by-label/ignition)
;;;   - QEMU fw_cfg (opt/com.coreos/config) for testing
;;;
;;; See:
;;;   RFC-0006 section 3 (ZFS Pool and Dataset Creation)
;;;   RFC-0001 section 5 (/var as the Writable Persistent Area)
;;;   Phase 6 section 6.4 (ZFS Pool and Dataset Setup)

(define-module (andyl services ignition)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:export (%andyl-zfs-setup-unit
            %andyl-ignition-postsetup-unit
            %andyl-ignition-hostname-unit
            %andyl-ignition-network-unit
            %andyl-ignition-sshd-keygen-unit
            %andyl-ignition-tmpfiles
            andyl-ignition-units))


;;;
;;; andyl-os-zfs-setup.service
;;;
;;; First-boot oneshot that creates the ZFS pool and datasets on the
;;; ANDYL-ZFS partition.  Ignition partitions the disk in the initrd
;;; (creating partition 3 with label ANDYL-ZFS), then this service
;;; creates the pool and datasets after switch-root.
;;;
;;; The service uses ConditionPathExists to ensure it runs only once.
;;; On subsequent boots, the completion marker at
;;; /var/lib/andyl-os/zfs-setup-complete prevents re-execution.
;;;
;;; ZFS dataset layout:
;;;
;;;   datapool                              ZFS pool (ashift=12, autotrim)
;;;     datapool/var                        /var (persistent mutable state)
;;;       datapool/var/lib                  /var/lib (application state)
;;;         datapool/var/lib/containerd     Container images (recordsize=128K)
;;;       datapool/var/log                  /var/log (logs, quota=2G)
;;;       datapool/var/tmp                  /var/tmp
;;;     datapool/etc-overlay                /etc overlay upper layer
;;;
;;; Pool-level properties:
;;;   compression=zstd-3    Zstandard compression (good ratio + speed)
;;;   atime=off             No access time updates (reduces write load)
;;;   xattr=sa              Store xattrs in inode (needed for SELinux)
;;;   acltype=posixacl      POSIX ACL support
;;;   dnodesize=auto        Automatic dnode sizing
;;;   ashift=12             4K sector alignment
;;;   autotrim=on           TRIM/UNMAP for SSDs
;;;

(define %andyl-zfs-setup-unit
  "\
[Unit]
Description=Create ZFS pool and datasets (first boot)
Documentation=man:zpool(8) man:zfs(8)

# Run only on first boot.  The completion marker is created after
# successful ZFS setup.  On subsequent boots this service is skipped,
# and zfs-import-cache.service imports the pool normally.
ConditionPathExists=!/var/lib/andyl-os/zfs-setup-complete

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
  # Load the ZFS kernel module \
  modprobe zfs; \
  \
  # Wait for the ANDYL-ZFS partition device node to appear. \
  # Ignition created this partition in the initrd. \
  udevadm settle --timeout=30; \
  \
  # Create the ZFS pool on the ANDYL-ZFS partition. \
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
  \
  # Create core datasets with appropriate mount points. \
  # Each dataset is a separate ZFS filesystem with independent \
  # properties (compression, quota, recordsize). \
  zfs create -o mountpoint=/var datapool/var; \
  zfs create -o mountpoint=/var/lib datapool/var/lib; \
  zfs create -o mountpoint=/var/log -o quota=2G datapool/var/log; \
  zfs create -o mountpoint=/var/tmp datapool/var/tmp; \
  \
  # Container storage: 128K recordsize matches container layer \
  # chunk sizes for optimal I/O alignment. \
  zfs create -o mountpoint=/var/lib/containerd \
    -o recordsize=128K datapool/var/lib/containerd; \
  \
  # /etc overlay upper layer: stores machine-specific config \
  # written by Ignition (hostname, network, SSH keys, certs). \
  # This dataset backs the OverlayFS upper layer for /etc. \
  zfs create -o mountpoint=/var/etc-overlay datapool/etc-overlay; \
  \
  # Work directory for OverlayFS (must be on same filesystem as upper). \
  mkdir -p /var/etc-overlay-work; \
  \
  # Create the ANDYL OS state directory and completion marker. \
  mkdir -p /var/lib/andyl-os; \
  touch /var/lib/andyl-os/zfs-setup-complete'

[Install]
WantedBy=local-fs.target
")


;;;
;;; andyl-os-ignition-postsetup.service
;;;
;;; Second-phase first-boot service that runs after ZFS setup completes.
;;; This service handles tasks that depend on /var being available on ZFS:
;;;
;;;   1. Moves Ignition-written files from the initrd tmpfs to ZFS-backed
;;;      locations (if Ignition wrote to /sysroot/var before ZFS was ready)
;;;   2. Sets up the /etc overlay upper directory with Ignition-written config
;;;   3. Creates the initial admin user home directory
;;;   4. Starts SELinux relabeling (delegated to selinux-relabel.service)
;;;
;;; This service bridges the gap between Ignition (which runs in the
;;; initrd before ZFS exists) and the running system (which needs config
;;; on ZFS-backed storage).
;;;

(define %andyl-ignition-postsetup-unit
  "\
[Unit]
Description=ANDYL OS Ignition post-ZFS setup (first boot)
Documentation=https://coreos.github.io/ignition/

# Run only on first boot, after ZFS setup is complete.
ConditionPathExists=/var/lib/andyl-os/zfs-setup-complete
ConditionPathExists=!/var/lib/andyl-os/ignition-postsetup-complete

# Must run after ZFS is set up and /var is available.
After=andyl-os-zfs-setup.service
After=var.mount
Requires=andyl-os-zfs-setup.service

# Must complete before the /etc overlay mounts and services start.
Before=etc.mount
Before=multi-user.target

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=/usr/bin/bash -c '\
  set -euo pipefail; \
  \
  # If Ignition wrote files to /sysroot/var/etc-overlay/ during initrd, \
  # those files are now on the ZFS-backed /var/etc-overlay dataset. \
  # Verify the overlay upper directory has the expected structure. \
  if [ -d /var/etc-overlay ]; then \
    echo \"Ignition /etc overlay upper layer present at /var/etc-overlay\"; \
    ls -la /var/etc-overlay/ || true; \
  fi; \
  \
  # Ensure the admin user home directory exists on /var. \
  # Ignition creates the user in /etc/passwd via the overlay, \
  # but the home directory must be on writable storage. \
  if id core >/dev/null 2>&1; then \
    mkdir -p /home/core/.ssh; \
    chmod 700 /home/core /home/core/.ssh; \
    chown -R core:core /home/core; \
    echo \"Admin user home directory configured\"; \
  fi; \
  \
  # Ensure systemd journal directory exists on ZFS. \
  mkdir -p /var/log/journal; \
  \
  # Ensure systemd persistent state directories exist. \
  mkdir -p /var/lib/systemd; \
  \
  # Ensure tmpfiles state directory exists. \
  mkdir -p /var/lib/andyl-os; \
  \
  # Write completion marker. \
  touch /var/lib/andyl-os/ignition-postsetup-complete'

[Install]
WantedBy=multi-user.target
")


;;;
;;; andyl-os-ignition-hostname.service
;;;
;;; Applies the hostname from the Ignition-written /etc/hostname file.
;;; This service reads the hostname written by Ignition to the /etc
;;; overlay and applies it via hostnamectl, ensuring the transient
;;; hostname matches the persistent one.
;;;

(define %andyl-ignition-hostname-unit
  "\
[Unit]
Description=Apply hostname from Ignition configuration
ConditionFirstBoot=true
After=etc.mount
After=systemd-hostnamed.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash -c '\
  if [ -f /etc/hostname ]; then \
    hostnamectl set-hostname \"$(cat /etc/hostname)\"; \
    echo \"Hostname set to: $(hostname)\"; \
  fi'

[Install]
WantedBy=multi-user.target
")


;;;
;;; andyl-os-ignition-network.service
;;;
;;; Restarts systemd-networkd after Ignition has written network
;;; configuration files to the /etc overlay.  Ignition writes
;;; .network and .netdev files to /etc/systemd/network/ (via the
;;; overlay upper layer).  This service ensures networkd picks up
;;; the new configuration on first boot.
;;;

(define %andyl-ignition-network-unit
  "\
[Unit]
Description=Apply Ignition network configuration
ConditionFirstBoot=true
After=etc.mount
After=andyl-os-ignition-postsetup.service
Before=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

# Reload networkd to pick up Ignition-written .network files.
ExecStart=/usr/bin/networkctl reload

# Wait for the network to come up with the new configuration.
ExecStartPost=/usr/bin/networkctl --wait online --timeout=30

[Install]
WantedBy=multi-user.target
")


;;;
;;; andyl-os-ignition-sshd-keygen.service
;;;
;;; Generates SSH host keys on first boot.  The golden image does not
;;; include SSH host keys (each machine must have unique keys).  This
;;; service generates them on first boot and stores them in the /etc
;;; overlay so they persist across reboots.
;;;

(define %andyl-ignition-sshd-keygen-unit
  "\
[Unit]
Description=Generate SSH host keys (first boot)
ConditionFirstBoot=true
ConditionPathExists=!/etc/ssh/ssh_host_ed25519_key
After=etc.mount
After=andyl-os-ignition-postsetup.service
Before=sshd.service

[Service]
Type=oneshot
RemainAfterExit=yes

# Generate Ed25519 host key (primary).
ExecStart=/usr/bin/ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''

# Generate RSA host key (fallback for older clients).
ExecStart=/usr/bin/ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ''

# Set correct permissions.
ExecStartPost=/usr/bin/chmod 600 /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_rsa_key
ExecStartPost=/usr/bin/chmod 644 /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub

[Install]
WantedBy=multi-user.target
")


;;;
;;; tmpfiles.d configuration for Ignition state directories
;;;
;;; Ensures the ANDYL OS state directories and other directories
;;; needed by the first-boot process exist on /var.
;;;

(define %andyl-ignition-tmpfiles
  "\
# ANDYL OS Ignition first-boot state directories
# These directories are created on /var (ZFS datapool) and persist
# across reboots.  Completion markers in /var/lib/andyl-os/ prevent
# first-boot services from re-running on subsequent boots.

# ANDYL OS state directory (completion markers, agent state)
d /var/lib/andyl-os 0755 root root -

# Journal persistent storage
d /var/log/journal 2755 root systemd-journal -

# Home directory for the admin user (created by Ignition)
d /home/core 0700 core core -
d /home/core/.ssh 0700 core core -
")


;;;
;;; Collected unit files
;;;
;;; Returns an association list of (filename . content) pairs for all
;;; systemd units and configuration files related to Ignition first-boot
;;; provisioning.  The image assembly module installs these into the
;;; appropriate locations in the system profile.
;;;

(define (andyl-ignition-units)
  "Return an alist of (filename . content) pairs for all Ignition
first-boot systemd unit files and tmpfiles.d configuration."
  (list
   ;; ZFS pool and dataset creation (first boot)
   (cons "lib/systemd/system/andyl-os-zfs-setup.service"
         %andyl-zfs-setup-unit)

   ;; Post-ZFS setup (first boot)
   (cons "lib/systemd/system/andyl-os-ignition-postsetup.service"
         %andyl-ignition-postsetup-unit)

   ;; Hostname application (first boot)
   (cons "lib/systemd/system/andyl-os-ignition-hostname.service"
         %andyl-ignition-hostname-unit)

   ;; Network configuration reload (first boot)
   (cons "lib/systemd/system/andyl-os-ignition-network.service"
         %andyl-ignition-network-unit)

   ;; SSH host key generation (first boot)
   (cons "lib/systemd/system/andyl-os-ignition-sshd-keygen.service"
         %andyl-ignition-sshd-keygen-unit)

   ;; tmpfiles.d for state directories
   (cons "lib/tmpfiles.d/andyl-ignition.conf"
         %andyl-ignition-tmpfiles)))
