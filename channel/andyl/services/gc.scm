;;; ANDYL OS -- Garbage Collection Service Definitions
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the systemd service units for the ANDYL OS
;;; generational garbage collection system.  The GC pipeline consists of:
;;;
;;;   1. andyl-os-gc.timer
;;;      Weekly timer that triggers garbage collection of old generations
;;;      and unreachable store paths.  Uses randomized delay to prevent
;;;      thundering herd across a fleet.
;;;
;;;   2. andyl-os-gc.service
;;;      One-shot service that executes the mark-and-sweep GC.  The
;;;      andyl-os-gc script (from andyl-os-update-tool package) implements:
;;;
;;;      Phase 0: Determine generations to keep
;;;        - Always keep the currently booted generation
;;;        - Keep the most recent N generations (configurable)
;;;        - Keep generations younger than MIN_AGE_HOURS
;;;
;;;      Phase 1: Compute GC roots
;;;        - Profile symlinks from retained generations
;;;        - Store paths referenced by running processes (/proc/*/maps, /proc/*/exe)
;;;
;;;      Phase 2: Mark (BFS reachability)
;;;        - Starting from GC roots, BFS-walk the reference graph
;;;        - All reachable store paths are marked as live
;;;
;;;      Phase 3: Sweep
;;;        - Remount /gnu/store read-write temporarily
;;;        - Delete unreachable store paths
;;;        - Remount /gnu/store read-only
;;;
;;;      Phase 4: Cleanup
;;;        - Remove old generation symlinks and metadata files
;;;        - Remove orphaned boot entries from the ESP
;;;        - Remove orphaned kernel/initrd files from /boot/efi/andyl-os
;;;
;;; Locking:
;;;   The GC acquires an exclusive lock at /var/lock/andyl-os-gc.lock,
;;;   shared with the update agent.  This prevents simultaneous store
;;;   mutations from GC and update apply.  The GC service also declares
;;;   Conflicts=andyl-os-update.service for systemd-level exclusion.
;;;
;;; Configuration:
;;;   /etc/andyl-os/gc.conf controls retention policy (keep_generations,
;;;   min_age_hours, dry_run).  The configuration file is installed by
;;;   the andyl-os-update-tool package.
;;;
;;; See:
;;;   Phase 5 sections 5.8, 5.9 (Garbage Collection)
;;;   docs/brainstorm/03-image-and-deployment.md section 5

(define-module (andyl services gc)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl config)
  #:export (%andyl-gc-unit
            %andyl-gc-timer
            %andyl-gc-tmpfiles
            andyl-gc-units))


;;;
;;; tmpfiles.d Configuration
;;;
;;; Creates directories needed by the GC service.
;;;

(define %andyl-gc-tmpfiles
  "\
# ANDYL OS garbage collection directories
# Lock directory for update/GC mutual exclusion.
d /var/lock 0755 root root -
")


;;;
;;; systemd Unit: Garbage Collection Service
;;;
;;; One-shot service that runs the mark-and-sweep garbage collector.
;;; Mutually exclusive with the update agent to prevent concurrent
;;; store mutations.
;;;
;;; The ExecStart path references the andyl-os-update-tool package's
;;; store path, resolved at image assembly time by the package.
;;; Here we use the collector pattern to reference the script by name;
;;; the actual ExecStart is set by the systemd unit installed by the
;;; package itself (at <package>/lib/systemd/system/andyl-os-gc.service).
;;;
;;; This module provides an alternative unit definition that can be
;;; used if the service module needs to override the package's unit
;;; (e.g., to add site-specific dependencies or hardening).
;;;

(define %andyl-gc-unit
  (let ((timeout (config-ref "deployment.gc.timeout-sec" 3600)))
    (string-append
     "[Unit]\n"
     "Description=ANDYL OS Garbage Collection\n"
     "Documentation=man:andyl-os-gc(8)\n"
     "Conflicts=andyl-os-update.service\n"
     "After=multi-user.target\n\n"
     "[Service]\n"
     "Type=oneshot\n"
     "ExecStart=/usr/bin/andyl-os-gc\n"
     "IOSchedulingClass=idle\n"
     "Nice=19\n"
     "TimeoutSec=" (number->string timeout) "\n"
     "User=root\n"
     "Group=root\n"
     "StandardOutput=journal\n"
     "StandardError=journal\n"
     "SyslogIdentifier=andyl-os-gc\n")))


;;;
;;; systemd Timer: Garbage Collection Timer
;;;
;;; Triggers GC on a weekly schedule with randomized delay.
;;; Persistent=true ensures missed runs are caught up after reboot.
;;;

(define %andyl-gc-timer
  (let ((schedule  (config-ref "deployment.gc.schedule" "weekly"))
        (rand-delay (config-ref "deployment.gc.randomized-delay-sec" 3600)))
    (string-append
     "[Unit]\n"
     "Description=ANDYL OS Garbage Collection Timer\n"
     "Documentation=man:andyl-os-gc(8)\n\n"
     "[Timer]\n"
     "OnCalendar=" schedule "\n"
     "RandomizedDelaySec=" (number->string rand-delay) "\n"
     "Persistent=true\n\n"
     "[Install]\n"
     "WantedBy=timers.target\n")))


;;;
;;; Collected Unit Files
;;;
;;; Returns an association list of (filename . content) pairs for all
;;; systemd units and configuration files related to garbage collection.
;;; The image assembly module installs these into the appropriate
;;; locations in the system profile.
;;;

(define (andyl-gc-units)
  "Return an alist of (filename . content) pairs for all garbage
collection systemd units and configuration files."
  (list
   ;; tmpfiles.d for directory creation
   (cons "lib/tmpfiles.d/andyl-os-gc.conf"
         %andyl-gc-tmpfiles)

   ;; GC systemd service
   (cons "lib/systemd/system/andyl-os-gc.service"
         %andyl-gc-unit)

   ;; GC timer
   (cons "lib/systemd/system/andyl-os-gc.timer"
         %andyl-gc-timer)))
