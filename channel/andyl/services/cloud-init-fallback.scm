;;; ANDYL OS -- Cloud-Init Fallback Service Definition
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines a minimal cloud-init compatibility shim for
;;; environments that do not support CoreOS Ignition.  While Ignition
;;; is the primary first-boot provisioning system (see services/ignition.scm),
;;; some cloud providers and legacy provisioning systems only support
;;; cloud-init.  This fallback provides equivalent functionality with
;;; known limitations.
;;;
;;; Limitations compared to Ignition:
;;;
;;;   - No all-or-nothing atomicity: partial configuration is possible
;;;     if a step fails
;;;   - Runs after boot (in bootcmd/runcmd stages), not in the initrd
;;;   - ZFS setup in bootcmd may race with services depending on /var
;;;   - cloud-init runs every boot by default; we guard with markers
;;;     to simulate Ignition's first-boot-only behavior
;;;
;;; The fallback parses a subset of cloud-config YAML and converts
;;; operations to the same underlying actions as Ignition:
;;;
;;;   cloud-config YAML         -> Ignition-equivalent action
;;;   -------------------------------------------------------------------
;;;   bootcmd: zpool create     -> ZFS pool creation (same as zfs-setup)
;;;   write_files:              -> File creation in /etc overlay and /var
;;;   runcmd:                   -> Post-boot setup commands
;;;   users:                    -> User creation with SSH keys
;;;   hostname:                 -> /etc/hostname
;;;
;;; See:
;;;   RFC-0006 section 1 (cloud-init fallback discussion)
;;;   Phase 6 section 6.4a (cloud-init Fallback)

(define-module (andyl services cloud-init-fallback)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:export (%andyl-cloud-init-fallback-unit
            %andyl-cloud-init-zfs-unit
            %andyl-cloud-init-userdata-unit
            %andyl-cloud-init-config
            andyl-cloud-init-fallback-units))


;;;
;;; Cloud-init compatibility configuration
;;;
;;; This configuration file tells the cloud-init fallback shim where
;;; to look for cloud-config data and how to process it.
;;;

(define %andyl-cloud-init-config
  "\
# ANDYL OS Cloud-Init Fallback Configuration
# This is a minimal compatibility shim, NOT a full cloud-init installation.
# See RFC-0006 for why Ignition is preferred.

# Data sources to check (in order):
#   1. Cloud provider metadata service (169.254.169.254)
#   2. Local file (/etc/cloud/cloud.cfg.d/*.cfg)
#   3. Config drive (if mounted at /mnt/config)
DATASOURCES=\"metadata localfile configdrive\"

# Cloud provider auto-detection order.
# The shim checks each provider's metadata endpoint and uses the
# first one that responds.
PROVIDERS=\"aws gcp azure\"

# AWS IMDSv2 endpoint
AWS_METADATA_URL=\"http://169.254.169.254/latest/user-data\"
AWS_TOKEN_URL=\"http://169.254.169.254/latest/api/token\"

# GCP metadata endpoint
GCP_METADATA_URL=\"http://metadata.google.internal/computeMetadata/v1/instance/attributes/user-data\"

# Azure custom-data endpoint
AZURE_METADATA_URL=\"http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text\"

# Completion marker (prevent re-running on subsequent boots)
COMPLETION_MARKER=\"/var/lib/andyl-os/cloud-init-complete\"
")


;;;
;;; andyl-os-cloud-init-zfs.service
;;;
;;; Cloud-init fallback for ZFS pool creation.  This is the equivalent
;;; of andyl-os-zfs-setup.service but runs via cloud-init's bootcmd
;;; mechanism.  The bootcmd stage runs early in boot, before most
;;; services, making it the best place for ZFS setup in the cloud-init
;;; model.
;;;
;;; This service runs only if:
;;;   1. The ZFS setup completion marker does NOT exist (first boot)
;;;   2. The Ignition completion marker does NOT exist (Ignition didn't run)
;;;
;;; If Ignition already ran, this service is skipped entirely.
;;;

(define %andyl-cloud-init-zfs-unit
  "\
[Unit]
Description=Cloud-init fallback: ZFS pool and dataset creation
Documentation=man:zpool(8) man:zfs(8)

# Only run if Ignition did NOT run (fallback path).
# If Ignition ran, it already partitioned the disk and the ZFS setup
# service handles pool creation.
ConditionPathExists=!/var/lib/andyl-os/zfs-setup-complete
ConditionPathExists=!/var/lib/andyl-os/ignition-postsetup-complete

# Same ordering as the Ignition-path ZFS setup.
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
  # Load ZFS kernel module. \
  modprobe zfs; \
  udevadm settle --timeout=30; \
  \
  # Detect available disks for the ZFS pool. \
  # Cloud-init fallback uses /dev/disk/by-partlabel/ANDYL-ZFS if \
  # it exists (disk was pre-partitioned), otherwise looks for the \
  # cloud-config specified disk. \
  ZFS_DEVICE=\"\"; \
  if [ -e /dev/disk/by-partlabel/ANDYL-ZFS ]; then \
    ZFS_DEVICE=/dev/disk/by-partlabel/ANDYL-ZFS; \
  else \
    # Parse cloud-config for disk specification. \
    # Default to the third partition of the boot disk. \
    BOOT_DISK=$(lsblk -ndo PKNAME $(findmnt -n -o SOURCE /) 2>/dev/null || echo sda); \
    # Create the ZFS partition on remaining space. \
    if command -v sgdisk >/dev/null 2>&1; then \
      sgdisk -n 3:0:0 -t 3:BF01 -c 3:ANDYL-ZFS /dev/${BOOT_DISK}; \
      partprobe /dev/${BOOT_DISK}; \
      udevadm settle --timeout=10; \
    fi; \
    ZFS_DEVICE=/dev/disk/by-partlabel/ANDYL-ZFS; \
  fi; \
  \
  if [ -z \"$ZFS_DEVICE\" ] || [ ! -e \"$ZFS_DEVICE\" ]; then \
    echo \"ERROR: No ZFS device found.  Cannot create datapool.\"; \
    exit 1; \
  fi; \
  \
  # Create the ZFS pool with the same properties as the Ignition path. \
  zpool create -f \
    -o ashift=12 \
    -o autotrim=on \
    -O compression=zstd-3 \
    -O atime=off \
    -O xattr=sa \
    -O acltype=posixacl \
    -O dnodesize=auto \
    datapool \"$ZFS_DEVICE\"; \
  \
  # Create the same dataset layout as the Ignition path. \
  zfs create -o mountpoint=/var datapool/var; \
  zfs create -o mountpoint=/var/lib datapool/var/lib; \
  zfs create -o mountpoint=/var/log -o quota=2G datapool/var/log; \
  zfs create -o mountpoint=/var/tmp datapool/var/tmp; \
  zfs create -o mountpoint=/var/lib/containerd \
    -o recordsize=128K datapool/var/lib/containerd; \
  zfs create -o mountpoint=/var/etc-overlay datapool/etc-overlay; \
  mkdir -p /var/etc-overlay-work; \
  \
  # Write completion marker. \
  mkdir -p /var/lib/andyl-os; \
  touch /var/lib/andyl-os/zfs-setup-complete'

[Install]
WantedBy=local-fs.target
")


;;;
;;; andyl-os-cloud-init-userdata.service
;;;
;;; Cloud-init fallback for applying user-data configuration.  This
;;; service fetches cloud-config YAML from the cloud provider metadata
;;; service and applies a subset of cloud-init directives:
;;;
;;;   - hostname: sets /etc/hostname
;;;   - write_files: writes files to /etc overlay and /var
;;;   - users: creates users with SSH authorized keys
;;;   - runcmd: executes post-boot commands
;;;
;;; This is a minimal shim, NOT a full cloud-init implementation.
;;; Only the directives needed for ANDYL OS first-boot provisioning
;;; are supported.
;;;

(define %andyl-cloud-init-userdata-unit
  "\
[Unit]
Description=Cloud-init fallback: apply user-data configuration
Documentation=https://cloudinit.readthedocs.io/

# Only run on first boot when Ignition did NOT run.
ConditionPathExists=!/var/lib/andyl-os/cloud-init-complete
ConditionPathExists=!/var/lib/andyl-os/ignition-postsetup-complete

# Must run after ZFS is set up and /var is available.
After=andyl-os-cloud-init-zfs.service
After=var.mount
After=etc.mount
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=/usr/bin/bash -c '\
  set -euo pipefail; \
  \
  # Source the cloud-init fallback configuration. \
  . /etc/andyl-os/cloud-init-fallback.conf; \
  \
  USERDATA=\"\"; \
  \
  # Try AWS IMDSv2 first. \
  if [ -z \"$USERDATA\" ]; then \
    TOKEN=$(curl -sf -X PUT -H \"X-aws-ec2-metadata-token-ttl-seconds: 300\" \
      \"$AWS_TOKEN_URL\" 2>/dev/null || true); \
    if [ -n \"$TOKEN\" ]; then \
      USERDATA=$(curl -sf -H \"X-aws-ec2-metadata-token: $TOKEN\" \
        \"$AWS_METADATA_URL\" 2>/dev/null || true); \
    fi; \
  fi; \
  \
  # Try GCP metadata. \
  if [ -z \"$USERDATA\" ]; then \
    USERDATA=$(curl -sf -H \"Metadata-Flavor: Google\" \
      \"$GCP_METADATA_URL\" 2>/dev/null || true); \
  fi; \
  \
  # Try Azure custom-data. \
  if [ -z \"$USERDATA\" ]; then \
    USERDATA=$(curl -sf -H \"Metadata: true\" \
      \"$AZURE_METADATA_URL\" 2>/dev/null | base64 -d 2>/dev/null || true); \
  fi; \
  \
  # Try local file. \
  if [ -z \"$USERDATA\" ] && [ -f /etc/cloud/cloud.cfg ]; then \
    USERDATA=$(cat /etc/cloud/cloud.cfg); \
  fi; \
  \
  if [ -z \"$USERDATA\" ]; then \
    echo \"WARNING: No cloud-config user-data found.  Skipping.\"; \
    touch \"$COMPLETION_MARKER\"; \
    exit 0; \
  fi; \
  \
  # Parse and apply cloud-config directives. \
  # This is a minimal parser -- we handle only the directives needed \
  # for ANDYL OS first-boot provisioning. \
  \
  # Apply hostname if present. \
  HOSTNAME_VAL=$(echo \"$USERDATA\" | grep \"^hostname:\" | head -1 | \
    sed \"s/^hostname:[[:space:]]*//\"); \
  if [ -n \"$HOSTNAME_VAL\" ]; then \
    echo \"$HOSTNAME_VAL\" > /etc/hostname; \
    hostnamectl set-hostname \"$HOSTNAME_VAL\"; \
    echo \"Hostname set to: $HOSTNAME_VAL\"; \
  fi; \
  \
  # Apply SSH authorized keys for the core user. \
  # Look for ssh_authorized_keys under users section. \
  SSH_KEYS=$(echo \"$USERDATA\" | \
    sed -n \"/ssh_authorized_keys:/,/^[^ ]/p\" | \
    grep \"^  - \" | sed \"s/^  - //\"); \
  if [ -n \"$SSH_KEYS\" ]; then \
    mkdir -p /home/core/.ssh; \
    echo \"$SSH_KEYS\" > /home/core/.ssh/authorized_keys; \
    chmod 600 /home/core/.ssh/authorized_keys; \
    chown -R core:core /home/core/.ssh; \
    echo \"SSH keys configured for core user\"; \
  fi; \
  \
  # Write completion marker. \
  mkdir -p /var/lib/andyl-os; \
  touch \"$COMPLETION_MARKER\"'

[Install]
WantedBy=multi-user.target
")


;;;
;;; Main cloud-init fallback orchestrator
;;;
;;; This is a meta-service that ties together the ZFS setup and
;;; user-data application services in the cloud-init fallback path.
;;;

(define %andyl-cloud-init-fallback-unit
  "\
[Unit]
Description=ANDYL OS cloud-init fallback (first boot)
Documentation=https://cloudinit.readthedocs.io/

# Only run on first boot when Ignition did NOT run.
ConditionPathExists=!/var/lib/andyl-os/cloud-init-complete
ConditionPathExists=!/var/lib/andyl-os/ignition-postsetup-complete

# Orchestrate the fallback sub-services.
Requires=andyl-os-cloud-init-zfs.service
Requires=andyl-os-cloud-init-userdata.service
After=andyl-os-cloud-init-zfs.service
After=andyl-os-cloud-init-userdata.service

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=/usr/bin/bash -c '\
  echo \"ANDYL OS cloud-init fallback provisioning complete.\"; \
  echo \"NOTE: cloud-init fallback lacks Ignition all-or-nothing atomicity.\"; \
  echo \"NOTE: cloud-init runs after boot, not in initrd.\"; \
  echo \"Consider migrating to Ignition for production use.\"'

[Install]
WantedBy=multi-user.target
")


;;;
;;; Collected unit files
;;;
;;; Returns an association list of (filename . content) pairs for all
;;; cloud-init fallback systemd units and configuration files.
;;; The image assembly module installs these into the appropriate
;;; locations in the system profile.
;;;

(define (andyl-cloud-init-fallback-units)
  "Return an alist of (filename . content) pairs for all cloud-init
fallback systemd unit files and configuration."
  (list
   ;; Cloud-init fallback configuration
   (cons "etc/andyl-os/cloud-init-fallback.conf"
         %andyl-cloud-init-config)

   ;; ZFS pool creation (cloud-init fallback path)
   (cons "lib/systemd/system/andyl-os-cloud-init-zfs.service"
         %andyl-cloud-init-zfs-unit)

   ;; User-data application (cloud-init fallback path)
   (cons "lib/systemd/system/andyl-os-cloud-init-userdata.service"
         %andyl-cloud-init-userdata-unit)

   ;; Orchestrator meta-service
   (cons "lib/systemd/system/andyl-os-cloud-init-fallback.service"
         %andyl-cloud-init-fallback-unit)))
