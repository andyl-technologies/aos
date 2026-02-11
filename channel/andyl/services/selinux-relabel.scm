;;; ANDYL OS -- First-Boot SELinux Relabeling Service
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the andyl-selinux-relabel.service, a first-boot
;;; oneshot systemd unit that applies SELinux file context labels to
;;; files created by Ignition and the ZFS dataset setup.
;;;
;;; The golden image's ext4 root filesystem already has correct SELinux
;;; labels baked in at build time (via setfiles during image assembly).
;;; However, files created at runtime by Ignition and ZFS provisioning
;;; need labels applied after first boot:
;;;
;;;   /etc overlay upper layer (Ignition-written files):
;;;     /etc/hostname             -> etc_t
;;;     /etc/andyl-os/role        -> etc_t
;;;     /etc/ssl/andyl-os/*.pem   -> cert_t
;;;     /etc/systemd/network/*    -> systemd_networkd_conf_t
;;;     /etc/ssh/ssh_host_*       -> sshd_key_t
;;;
;;;   /var (ZFS datasets):
;;;     /var/log/journal          -> systemd_journal_t
;;;     /var/lib/containerd       -> container_var_lib_t
;;;     /var/lib/etcd             -> etc_t (or custom etcd_data_t)
;;;     /var/lib/andyl-os         -> var_lib_t
;;;     /var/etc-overlay          -> etc_t
;;;
;;; This module is separate from services/selinux.scm (which handles
;;; policy loading and periodic checks) because the relabeling service
;;; has different ordering requirements -- it must run after both ZFS
;;; setup and /etc overlay mount, but before application services.
;;;
;;; See:
;;;   Phase 4 sections 4.8.4, 4.8.5 (SELinux Mode, First-Boot Relabeling)
;;;   Phase 6 section 6.4 (ZFS Pool and Dataset Setup -- relabeling after)
;;;   RFC-0001 section 7 (Security Considerations)

(define-module (andyl services selinux-relabel)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:export (%andyl-selinux-relabel-flag
            %andyl-selinux-relabel-unit
            %andyl-selinux-relabel-trigger-unit
            andyl-selinux-relabel-units))


;;;
;;; Flag file for first-boot relabeling
;;;
;;; The relabel service creates this file after a successful run.
;;; On subsequent boots, ConditionPathExists prevents re-execution.
;;; This file lives on ZFS (/var) so it persists across reboots.
;;;

(define %andyl-selinux-relabel-flag
  "/var/lib/andyl-os/selinux-relabel-done")


;;;
;;; andyl-selinux-relabel.service
;;;
;;; First-boot relabeling service.  Runs restorecon on /etc (overlay
;;; upper layer) and /var (ZFS mutable data) to apply SELinux file
;;; context labels to files created by Ignition and ZFS provisioning.
;;;
;;; restorecon reads the file context definitions from the installed
;;; SELinux policy (/etc/selinux/targeted/contexts/files/file_contexts)
;;; and applies the correct labels based on path patterns.
;;;
;;; Ordering requirements:
;;;   - After SELinux policy is loaded (andyl-selinux-load.service)
;;;   - After ZFS datasets are mounted (zfs-mount.service)
;;;   - After /etc overlay is mounted (etc.mount)
;;;   - After Ignition post-setup (andyl-os-ignition-postsetup.service)
;;;   - Before application services (multi-user.target)
;;;   - Before sshd (SSH host keys need correct labels)
;;;

(define %andyl-selinux-relabel-unit
  (string-append
   "\
[Unit]
Description=ANDYL OS first-boot SELinux relabeling
Documentation=man:restorecon(8) man:selinux(8)
DefaultDependencies=no

# Must run after SELinux policy is loaded so restorecon knows
# which labels to apply.
After=andyl-selinux-load.service
Requires=andyl-selinux-load.service

# Must run after ZFS datasets and /etc overlay are mounted so
# all files are visible and accessible.
After=zfs-mount.service
After=etc.mount
After=var.mount

# Must run after Ignition post-setup has completed (all files
# written, directories created, permissions set).
After=andyl-os-ignition-postsetup.service
After=andyl-os-zfs-setup.service

# Must complete before application services start.
Before=multi-user.target
Before=sshd.service
Before=systemd-networkd.service
Before=containerd.service

# Only run if the flag file does NOT exist (first boot only).
ConditionPathExists=!" %andyl-selinux-relabel-flag "

# SELinux must be active for restorecon to work.
ConditionSecurity=selinux

[Service]
Type=oneshot
RemainAfterExit=yes

# Relabel the /etc overlay upper layer.
# Files written by Ignition (hostname, network config, SSH keys,
# TLS certificates) need SELinux labels matching their /etc paths.
ExecStart=/usr/sbin/restorecon -R -v /etc

# Relabel /var (ZFS mutable data).
# ZFS datasets created by the ZFS setup service need labels:
#   /var/log/journal     -> systemd_journal_t
#   /var/lib/containerd  -> container_var_lib_t
#   /var/lib/etcd        -> etcd_data_t (or var_lib_t)
#   /var/etc-overlay     -> etc_t
#   /var/lib/andyl-os    -> var_lib_t
ExecStart=/usr/sbin/restorecon -R -v /var

# Relabel /home (admin user created by Ignition).
ExecStart=/usr/sbin/restorecon -R -v /home

# Create the flag file to prevent re-running on subsequent boots.
ExecStartPost=/bin/touch " %andyl-selinux-relabel-flag "

# Log the result for debugging.
ExecStartPost=/bin/sh -c '\
  echo \"SELinux relabeling complete.\"; \
  echo \"Mode: $(/usr/sbin/getenforce)\"; \
  echo \"Relabeled: /etc, /var, /home\"'

# Send output to journal for monitoring.
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"))


;;;
;;; andyl-selinux-relabel-trigger.service
;;;
;;; A trigger service that can be used to force a relabel on the
;;; next boot.  Administrators can enable this service to schedule
;;; a relabel, for example after a policy update or after manual
;;; file modifications.
;;;
;;; Usage:
;;;   systemctl enable andyl-selinux-relabel-trigger.service
;;;   reboot
;;;
;;; The trigger service removes the completion flag, causing the
;;; main relabel service to run on the next boot.
;;;

(define %andyl-selinux-relabel-trigger-unit
  (string-append
   "\
[Unit]
Description=Trigger SELinux relabeling on next boot
Documentation=man:restorecon(8)
DefaultDependencies=no
Before=shutdown.target

[Service]
Type=oneshot

# Remove the completion flag so the relabel service runs on next boot.
ExecStart=/bin/rm -f " %andyl-selinux-relabel-flag "
ExecStart=/bin/sh -c 'echo \"SELinux relabeling scheduled for next boot.\"'

[Install]
WantedBy=shutdown.target
"))


;;;
;;; Collected unit files
;;;

(define (andyl-selinux-relabel-units)
  "Return an alist of (filename . content) pairs for the SELinux
first-boot relabeling service."
  (list
   ;; First-boot relabeling service
   (cons "lib/systemd/system/andyl-selinux-relabel.service"
         %andyl-selinux-relabel-unit)

   ;; Relabel trigger (for manual relabel scheduling)
   (cons "lib/systemd/system/andyl-selinux-relabel-trigger.service"
         %andyl-selinux-relabel-trigger-unit)))
