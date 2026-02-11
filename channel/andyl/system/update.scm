;;; ANDYL OS -- Update System Configuration
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the system-level configuration for the ANDYL OS
;;; generational update system.  It extends the base operating-system
;;; definition with:
;;;
;;;   - A/B partition scheme for atomic updates
;;;   - Boot entry management with systemd-boot boot counting
;;;   - References to the update and GC service modules
;;;   - Update agent integration into the base service set
;;;
;;; Partition Layout for Updates:
;;;
;;;   +-------+------------------+------------------+------------------+
;;;   | ESP   | ANDYL-ROOT       | ANDYL-ROOT-B     | ANDYL-DATA       |
;;;   | 1 GiB | 8 GiB (ext4, ro) | 8 GiB (ext4, ro) | remainder (ZFS)  |
;;;   +-------+------------------+------------------+------------------+
;;;
;;;   Partition A (ANDYL-ROOT):   Current active root filesystem
;;;   Partition B (ANDYL-ROOT-B): Staging area for incoming updates
;;;   ESP:                        Shared, contains systemd-boot + entries
;;;   ANDYL-DATA:                 ZFS datapool for /var (mutable data)
;;;
;;; Note: The generational model described in Phase 5 uses a single root
;;; partition with an in-place store update approach (NAR unpacking into
;;; /gnu/store).  The A/B partition scheme defined here is an alternative
;;; for environments that prefer full-image swaps.  Both approaches share
;;; the same boot entry management and health check infrastructure.
;;;
;;; Boot Entry Management:
;;;
;;;   Each generation gets a boot entry on the ESP:
;;;     /boot/efi/loader/entries/andyl-os-<N>+3.conf   (new, 3 tries)
;;;     /boot/efi/loader/entries/andyl-os-<N>.conf      (verified)
;;;
;;;   systemd-boot's boot counting protocol:
;;;     - New entry: andyl-os-<N>+3.conf (3 tries remaining)
;;;     - After each boot: tries decremented (andyl-os-<N>+2-1.conf)
;;;     - Health check passes: suffix removed (andyl-os-<N>.conf = verified)
;;;     - All tries exhausted: entry skipped, fallback to previous verified
;;;
;;; Service Modules:
;;;
;;;   Update services are defined in (andyl services update):
;;;     - Update check timer/service, update apply, health check, rollback
;;;
;;;   GC services are defined in (andyl services gc):
;;;     - GC timer/service for mark-and-sweep store cleanup
;;;
;;;   Scripts and tools are provided by the andyl-os-update-tool package
;;;   (andyl packages update).
;;;
;;; See:
;;;   Phase 5 (Generational Deployment Model)
;;;   RFC-0001 section 8 (Filesystem Layout)

(define-module (andyl system update)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl system base)
  #:use-module (andyl images base)
  #:use-module (andyl config)
  #:use-module (andyl services update)
  #:use-module (andyl services gc)
  #:export (%andyl-update-file-systems
            %andyl-update-kernel-arguments
            %andyl-update-services
            %andyl-ab-partitions
            andyl-os-update
            andyl-update-image))


;;;
;;; A/B Partition Definitions
;;;
;;; Extends the base partition layout with a second root partition
;;; for A/B image swapping.  The active root is determined by the
;;; boot entry that systemd-boot selects.
;;;

;; Partition B: staging root (ext4, read-only after update).
;; Identical layout to ANDYL-ROOT but used for incoming updates.
;; The update agent writes the new image here, then swaps the boot
;; entry to point to this partition.
(define %andyl-root-b-partition
  (andyl-partition
   (label "ANDYL-ROOT-B")
   (size (config-ref "boot.partitions.root-mib" (* 8 1024)))
   (type "linux")
   (filesystem "ext4")
   (flags '())))

(define %andyl-ab-partitions
  (list %andyl-esp-partition
        %andyl-root-partition
        %andyl-root-b-partition
        %andyl-zfs-partition))


;;;
;;; Update-Aware Filesystem Layout
;;;
;;; Extends the base filesystem layout with:
;;;   - Partition B mount point (not mounted at boot; used by update agent)
;;;   - /gnu/store explicitly documented as the primary update target
;;;

(define %andyl-update-file-systems
  (append
   ;; Inherit all base file systems.
   %andyl-base-file-systems

   (list
    ;; Partition B: staging root.  Not mounted during normal operation.
    ;; The update agent mounts this partition temporarily to write a new
    ;; image, then unmounts it.  On reboot, systemd-boot may select this
    ;; partition as root via the boot entry.
    (andyl-file-system
     (device "LABEL=ANDYL-ROOT-B")
     (mount-point "/mnt/root-b")
     (type "ext4")
     (flags '("noauto" "noatime")))

    ;; Generation profiles directory on ZFS.
    ;; Each generation has a symlink: system-<N> -> /gnu/store/<hash>-system
    ;; The 'system' symlink points to the current generation.
    ;; This directory persists across root filesystem swaps because it
    ;; lives on ZFS /var.
    (andyl-file-system
     (device "datapool/var-guix")
     (mount-point "/var/guix")
     (type "zfs")
     (flags '("noatime"))))))


;;;
;;; Kernel Arguments for Update System
;;;
;;; Adds boot counting related parameters to the kernel command line.
;;;

(define %andyl-update-kernel-arguments
  (append
   %andyl-base-kernel-arguments
   (list
    ;; Enable systemd-boot's boot counting protocol.
    ;; The boot loader automatically manages try counts.
    "systemd.default_standard_output=journal")))


;;;
;;; Update System Services
;;;
;;; Additional systemd services required for the update system.
;;; These supplement the base service list.
;;;

(define %andyl-update-services
  (list
   ;; Update check timer (periodic polling for new generations).
   "andyl-os-update-check.timer"

   ;; Health check after boot (validates system, triggers bless-boot).
   "andyl-os-health-check.service"

   ;; Boot complete target (dependency for systemd-bless-boot).
   "boot-complete.target"

   ;; Garbage collection timer (weekly cleanup of old generations).
   "andyl-os-gc.timer"))


;;;
;;; Update-Aware Operating System
;;;
;;; Extends the base OS with update system services and the A/B
;;; partition layout.
;;;

(define andyl-os-update
  (andyl-operating-system
   (host-name "andyl-os")
   (kernel-arguments %andyl-update-kernel-arguments)
   (file-systems %andyl-update-file-systems)
   (extra-services %andyl-update-services)))


;;;
;;; Update-Aware Image
;;;
;;; Extends the base image with the A/B partition scheme.
;;; The image includes both root partitions (A and B) and is
;;; larger to accommodate them.
;;;

(define andyl-update-image
  (andyl-image
   (operating-system andyl-os-update)
   (size (* 32 1024))
   (root-size (config-ref "boot.partitions.root-mib" (* 8 1024)))))
