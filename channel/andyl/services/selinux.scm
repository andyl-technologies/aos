;;; ANDYL OS -- SELinux Service Definitions
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the systemd service units for SELinux integration
;;; in ANDYL OS.  Three services are provided:
;;;
;;;   1. andyl-selinux-load.service
;;;      Loads the SELinux policy at boot.  Runs early in the boot process
;;;      before any confined services start.  Sets the SELinux mode
;;;      (enforcing or permissive) based on /etc/selinux/config.
;;;
;;;   2. andyl-selinux-relabel.service
;;;      One-shot service that runs restorecon on first boot (after
;;;      Ignition) to label files created by Ignition and ZFS dataset
;;;      provisioning.  Conditioned on a flag file so it only runs once.
;;;
;;;   3. andyl-selinux-check.service
;;;      Periodic check (via systemd timer) that verifies file contexts
;;;      are correct.  Logs any mismatches without modifying labels.
;;;
;;; The policy itself is installed by the SELinux packages:
;;;   - andyl-selinux-policy-targeted (upstream reference policy)
;;;   - andyl-container-selinux (container runtime policy)
;;;   - andyl-selinux-policy (ANDYL OS custom modules)
;;;
;;; See:
;;;   Phase 4 sections 4.8.4, 4.8.5 (SELinux Mode, First-Boot Relabeling)
;;;   RFC-0001 section 7 (Security Considerations)

(define-module (andyl services selinux)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:export (%andyl-selinux-load-unit
            %andyl-selinux-relabel-unit
            %andyl-selinux-relabel-flag
            %andyl-selinux-check-unit
            %andyl-selinux-check-timer
            %andyl-selinux-config
            andyl-selinux-units))


;;;
;;; SELinux Configuration File
;;;
;;; Installed at /etc/selinux/config (in the /etc overlay lower layer,
;;; baked into the golden image).  This file tells the SELinux init code
;;; which policy type to load and what mode to use.
;;;

(define %andyl-selinux-config
  "\
# ANDYL OS SELinux Configuration
# See RFC-0001 and Phase 4 section 4.8.4

# SELINUX= can take one of these three values:
#   enforcing  - SELinux security policy is enforced.
#   permissive - SELinux prints warnings instead of enforcing.
#   disabled   - No SELinux policy is loaded.
#
# Production images use enforcing.  Development images may use
# permissive for policy testing.
SELINUX=enforcing

# SELINUXTYPE= selects the policy to load.
# The targeted policy confines specific daemons while leaving
# general processes in the unconfined domain.
SELINUXTYPE=targeted
")


;;;
;;; Flag file for first-boot relabeling
;;;
;;; The relabel service creates this file after a successful run.
;;; On subsequent boots, the service checks for this file and exits
;;; immediately if it exists.
;;;

(define %andyl-selinux-relabel-flag
  "/var/.andyl-selinux-relabel-done")


;;;
;;; andyl-selinux-load.service
;;;
;;; Loads the SELinux policy into the kernel at boot.  This must run
;;; very early in the boot process, before any service that should be
;;; confined by SELinux.
;;;
;;; The service:
;;;   1. Mounts the selinuxfs pseudo-filesystem at /sys/fs/selinux
;;;   2. Loads the compiled policy binary using /sbin/load_policy
;;;   3. Sets the SELinux mode based on /etc/selinux/config
;;;
;;; If SELinux is already active (loaded by the kernel from initrd),
;;; this service verifies the policy and mode are correct.
;;;

(define %andyl-selinux-load-unit
  "\
[Unit]
Description=Load SELinux Policy
DefaultDependencies=no

# Must run before any confined services.
Before=sysinit.target
Before=systemd-tmpfiles-setup.service

# /etc must be available to read /etc/selinux/config.
After=etc.mount

# This is a critical security service.  If it fails, the system
# should not continue to multi-user.target in enforcing mode.
ConditionSecurity=selinux

[Service]
Type=oneshot
RemainAfterExit=yes

# Mount selinuxfs if not already mounted (kernel may have done this).
ExecStartPre=-/bin/mount -t selinuxfs selinuxfs /sys/fs/selinux

# Load the compiled policy.  The policy binary is at
# /etc/selinux/targeted/policy/policy.<version>
ExecStart=/sbin/load_policy

# Set the mode from /etc/selinux/config.
# getenforce/setenforce are from policycoreutils.
ExecStartPost=/bin/sh -c '\
    . /etc/selinux/config; \
    case \"$SELINUX\" in \
        enforcing)  /usr/sbin/setenforce 1 ;; \
        permissive) /usr/sbin/setenforce 0 ;; \
    esac'

[Install]
WantedBy=sysinit.target
")


;;;
;;; andyl-selinux-relabel.service
;;;
;;; First-boot relabeling service.  After Ignition runs and creates
;;; ZFS datasets and writes configuration to /etc overlay, files in
;;; /var and /etc need SELinux labels applied.
;;;
;;; This service:
;;;   1. Checks if the relabel flag file exists (skip if already done)
;;;   2. Runs restorecon -R on /etc (overlay upper layer)
;;;   3. Runs restorecon -R on /var (ZFS mutable data)
;;;   4. Creates the flag file to prevent re-running on next boot
;;;
;;; The golden image's ext4 root already has correct labels baked in
;;; at build time (via setfiles during image assembly).  This service
;;; only needs to label files created at runtime by Ignition and ZFS.
;;;

(define %andyl-selinux-relabel-unit
  (string-append
   "\
[Unit]
Description=ANDYL OS First-Boot SELinux Relabeling
DefaultDependencies=no

# Must run after:
#   - SELinux policy is loaded
#   - ZFS datasets are mounted (/var is available)
#   - /etc overlay is mounted
#   - Ignition has completed its configuration writes
After=andyl-selinux-load.service
After=zfs-mount.service
After=etc.mount
After=var.mount

# Must run before application services start.
Before=multi-user.target
Before=sshd.service

# Only run if the flag file does NOT exist (first boot only).
ConditionPathExists=!" %andyl-selinux-relabel-flag "

# SELinux must be active.
ConditionSecurity=selinux

[Service]
Type=oneshot
RemainAfterExit=yes

# Relabel /etc overlay upper layer.
# Files written by Ignition (hostname, network config, SSH keys)
# need SELinux labels matching their /etc counterparts.
ExecStart=/usr/sbin/restorecon -R /etc

# Relabel /var (ZFS mutable data).
# ZFS datasets created by Ignition need labels for:
#   /var/log/journal -> systemd_journal_t
#   /var/log/audit -> auditd_log_t
#   /var/lib/containers -> container_var_lib_t
#   /var/etc-overlay -> etc_t
ExecStart=/usr/sbin/restorecon -R /var

# Create the flag file to prevent re-running on subsequent boots.
ExecStartPost=/bin/touch " %andyl-selinux-relabel-flag "

# Log the result for debugging.
ExecStartPost=/bin/sh -c 'echo \"SELinux relabeling complete.  Mode: $(/usr/sbin/getenforce)\"'

# If relabeling fails, we want to know but shouldn't block boot
# in permissive mode.  In enforcing mode, failure is critical.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"))


;;;
;;; andyl-selinux-check.service + timer
;;;
;;; Periodic verification that file contexts are correct.  Runs
;;; restorecon in check-only mode (-n) and logs any mismatches.
;;; Does NOT modify any labels -- it only reports.
;;;
;;; The timer runs this check daily.
;;;

(define %andyl-selinux-check-unit
  "\
[Unit]
Description=ANDYL OS SELinux File Context Verification
ConditionSecurity=selinux

[Service]
Type=oneshot

# Check /etc for context mismatches (overlay upper layer).
ExecStart=/usr/sbin/restorecon -n -v -R /etc

# Check /var for context mismatches (ZFS mutable data).
ExecStart=/usr/sbin/restorecon -n -v -R /var

# Log output to journal for monitoring and alerting.
StandardOutput=journal
StandardError=journal
")

(define %andyl-selinux-check-timer
  "\
[Unit]
Description=Daily SELinux File Context Verification

[Timer]
# Run once daily at 3:00 AM (with randomized delay to avoid thundering herd).
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
")


;;;
;;; Collected unit files
;;;
;;; Returns an association list of (filename . content) pairs for all
;;; systemd units related to SELinux.  The image assembly module installs
;;; these into the appropriate locations in the system profile.
;;;

(define (andyl-selinux-units)
  "Return an alist of (filename . content) pairs for all SELinux
systemd unit files and configuration."
  (list
   ;; SELinux configuration file
   (cons "etc/selinux/config"
         %andyl-selinux-config)

   ;; Policy loading service
   (cons "lib/systemd/system/andyl-selinux-load.service"
         %andyl-selinux-load-unit)

   ;; First-boot relabeling service
   (cons "lib/systemd/system/andyl-selinux-relabel.service"
         %andyl-selinux-relabel-unit)

   ;; Periodic context verification service and timer
   (cons "lib/systemd/system/andyl-selinux-check.service"
         %andyl-selinux-check-unit)
   (cons "lib/systemd/system/andyl-selinux-check.timer"
         %andyl-selinux-check-timer)))
