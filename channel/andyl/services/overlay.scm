;;; ANDYL OS -- OverlayFS /etc Service Definition
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the systemd mount unit and supporting services for
;;; the OverlayFS /etc filesystem.  The overlay merges the immutable base
;;; /etc from the system profile (read-only ext4 root) with a writable
;;; upper layer on ZFS (/var/etc-overlay), allowing targeted modifications
;;; while preserving the full base configuration.
;;;
;;; Mount hierarchy:
;;;
;;;   merged /etc  <-- processes see this
;;;       |
;;;   +---+---+---+
;;;   |       |       |
;;;   lower   upper   work
;;;   (ro)    (rw)    (rw)
;;;   /sysroot/etc  /var/etc-overlay  /var/etc-overlay-work
;;;   (from ext4    (on ZFS           (on ZFS
;;;    profile)      datapool)         datapool)
;;;
;;; Ordering:
;;;   1. ext4 root is mounted read-only by the kernel (initrd)
;;;   2. ZFS datapool is imported and /var is mounted
;;;   3. tmpfiles.d creates /var/etc-overlay and /var/etc-overlay-work
;;;   4. etc.mount mounts the overlay
;;;   5. Services that read /etc start after etc.mount
;;;
;;; See:
;;;   RFC-0001 section 4 (Overlay Strategy for /etc)
;;;   Phase 4 section 4.3 (/etc OverlayFS Setup)

(define-module (andyl services overlay)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:export (%andyl-etc-overlay-mount-unit
            %andyl-etc-overlay-tmpfiles
            %andyl-etc-overlay-automount-unit
            andyl-etc-overlay-units))


;;;
;;; systemd mount unit: etc.mount
;;;
;;; This unit mounts the OverlayFS on /etc.  The unit file name must match
;;; the mount point with path separators replaced by dashes (systemd
;;; convention: /etc -> etc.mount).
;;;
;;; Dependencies:
;;;   - After var.mount: the upper layer lives on /var (ZFS)
;;;   - After local-fs-pre.target: basic filesystem setup complete
;;;   - Before local-fs.target: /etc must be available before services start
;;;   - Before sysinit.target: many early services read /etc
;;;

(define %andyl-etc-overlay-mount-unit
  "\
[Unit]
Description=Overlay filesystem for /etc
DefaultDependencies=no

# The upper layer and work directory live on /var (ZFS datapool).
# /var must be mounted before we can mount the overlay.
After=var.mount
After=local-fs-pre.target

# /etc must be ready before any service that reads configuration.
Before=local-fs.target
Before=sysinit.target

# If /var is not available, the overlay cannot mount.
Requires=var.mount

# Ensure the upper/work directories exist (created by tmpfiles.d).
After=systemd-tmpfiles-setup.service

[Mount]
What=overlay
Where=/etc
Type=overlay
Options=lowerdir=/sysroot/etc,upperdir=/var/etc-overlay,workdir=/var/etc-overlay-work

# If the mount fails, the system cannot function correctly.
# Fail loudly rather than booting with a broken /etc.
DirectoryMode=0755
LazyUnmount=no

[Install]
WantedBy=local-fs.target
")


;;;
;;; tmpfiles.d configuration
;;;
;;; Ensures the upper layer and work directory exist on /var before the
;;; overlay mount unit starts.  These directories must be on the same
;;; filesystem (ZFS /var) for OverlayFS to function correctly.
;;;
;;; Format: type path mode user group age argument
;;;   d = create directory if it doesn't exist
;;;

(define %andyl-etc-overlay-tmpfiles
  "\
# ANDYL OS /etc overlay directories
# Created on /var (ZFS datapool) for the OverlayFS upper and work layers.
# See: RFC-0001 section 4 (Overlay Strategy for /etc)

# Upper layer: writable /etc changes persist here across reboots.
# Ignition writes machine-specific configuration into this directory
# on first boot (hostname, network config, SSH keys, certificates).
d /var/etc-overlay 0755 root root -

# Work directory: required by OverlayFS for atomic operations.
# Must be on the same filesystem as the upper layer.
d /var/etc-overlay-work 0755 root root -
")


;;;
;;; Optional: automount unit for lazy /etc overlay mounting
;;;
;;; This is provided as an alternative to the direct mount unit above.
;;; The automount unit mounts /etc on first access rather than at boot,
;;; which can help with boot ordering issues.  Use this if the direct
;;; mount unit causes dependency cycles.
;;;
;;; To use: enable etc.automount instead of etc.mount.
;;;

(define %andyl-etc-overlay-automount-unit
  "\
[Unit]
Description=Automount for /etc overlay filesystem
DefaultDependencies=no
Before=local-fs.target

[Automount]
Where=/etc
TimeoutIdleSec=0

[Install]
WantedBy=local-fs.target
")


;;;
;;; Collected unit files
;;;
;;; Returns an association list of (filename . content) pairs for all
;;; systemd units and configuration files related to the /etc overlay.
;;; The image assembly module installs these into the appropriate
;;; locations in the system profile.
;;;

(define (andyl-etc-overlay-units)
  "Return an alist of (filename . content) pairs for all systemd unit
files and tmpfiles.d configuration for the /etc OverlayFS overlay."
  (list
   ;; systemd mount unit
   (cons "lib/systemd/system/etc.mount"
         %andyl-etc-overlay-mount-unit)

   ;; tmpfiles.d configuration for upper/work directories
   (cons "lib/tmpfiles.d/andyl-etc-overlay.conf"
         %andyl-etc-overlay-tmpfiles)

   ;; automount unit (optional, not enabled by default)
   (cons "lib/systemd/system/etc.automount"
         %andyl-etc-overlay-automount-unit)))
