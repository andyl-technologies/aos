;;; ANDYL OS -- Update Service Definitions
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the systemd services for the ANDYL OS generational
;;; update system.  The update pipeline consists of:
;;;
;;;   1. andyl-os-update-check.timer / .service
;;;      Periodic timer that queries the update server for new generations.
;;;      Compares the latest available generation against the currently
;;;      running generation and logs the result.
;;;
;;;   2. andyl-os-update.service
;;;      Downloads a new generation bundle from the update server, verifies
;;;      its integrity (SHA-256 manifest hashes + minisign signature),
;;;      atomically unpacks NAR archives into /gnu/store, creates a new
;;;      generation symlink on ZFS /var, installs boot entries on the ESP,
;;;      and prepares the system for reboot into the new generation.
;;;
;;;   3. andyl-os-health-check.service
;;;      Runs after boot to verify the system is healthy.  Checks systemd
;;;      state, networking, DNS, NTP sync, and /gnu/store mount status.
;;;      On success, triggers boot-complete.target which allows
;;;      systemd-bless-boot to mark the generation as verified.
;;;
;;;   4. andyl-os-rollback.service
;;;      Manual rollback: sets the previous verified generation as the
;;;      default boot entry and reboots.  Automatic rollback is handled
;;;      by systemd-boot's boot counting protocol (no service needed).
;;;
;;; Boot counting protocol (automatic rollback):
;;;   - New generation boot entry is created with +3 suffix (3 tries)
;;;   - systemd-boot decrements tries on each boot attempt
;;;   - If health check passes, systemd-bless-boot removes the counter
;;;   - If 3 boots fail, systemd-boot falls back to previous verified entry
;;;
;;; Scripts and configuration files are installed by the andyl-os-update-tool
;;; package (see andyl packages update).  The systemd units installed by
;;; the package reference the package's store path for ExecStart, ensuring
;;; correct dependency tracking.
;;;
;;; This service module provides the collector function (andyl-update-units)
;;; that returns the alist of (filename . content) pairs for the update
;;; system's configuration and tmpfiles.  The systemd units themselves are
;;; installed by the package, so this module only provides configuration
;;; and tmpfiles entries that need to be in the image profile.
;;;
;;; Garbage collection is handled by the separate (andyl services gc) module.
;;;
;;; See:
;;;   Phase 5 (Generational Deployment Model)
;;;   RFC-0001 section 9 (Update Strategy)

(define-module (andyl services update)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl config)
  #:export (%andyl-update-config
            %andyl-update-check-timer
            %andyl-update-check-unit
            %andyl-update-unit
            %andyl-health-check-unit
            %andyl-boot-complete-target
            %andyl-rollback-unit
            %andyl-update-tmpfiles
            andyl-update-units))


;;;
;;; Update Agent Configuration
;;;
;;; Installed at /etc/andyl-os/update.conf.  The update agent reads this
;;; file to determine the update server URL, channel, and behavior.
;;; This is also installed by the andyl-os-update-tool package, but we
;;; define it here as well for the collector function to include in the
;;; image profile's /etc directory.
;;;

(define %andyl-update-config
  (let ((server     (config-ref "deployment.update.server" "https://update.andyl-os.internal"))
        (channel    (config-ref "deployment.update.channel" "stable"))
        (interval   (config-ref "deployment.update.check-interval" 3600))
        (auto       (config-ref "deployment.update.auto-update" #f))
        (retries    (config-ref "deployment.update.max-retries" 3))
        (delay      (config-ref "deployment.update.retry-delay" 300))
        (tries      (config-ref "deployment.update.boot-tries" 3))
        (key        (config-ref "deployment.update.signing-key" "/etc/andyl-os/update-signing-key.pub")))
    (string-append
     "# ANDYL OS Update Agent Configuration\n"
     "# Generated from config/deployment.toml\n\n"
     "server=" server "\n"
     "channel=" channel "\n"
     "check_interval=" (number->string interval) "\n"
     "auto_update=" (if auto "true" "false") "\n"
     "max_retries=" (number->string retries) "\n"
     "retry_delay=" (number->string delay) "\n"
     "boot_tries=" (number->string tries) "\n"
     "signing_key=" key "\n")))


;;;
;;; tmpfiles.d Configuration
;;;
;;; Creates directories needed by the update agent and health check.
;;;

(define %andyl-update-tmpfiles
  "\
# ANDYL OS update agent directories
# Downloaded bundles are cached here until applied.
d /var/cache/andyl-os/updates 0750 root root -

# Update agent state (current generation, lock files).
d /var/lib/andyl-os 0750 root root -

# Generation profiles directory on ZFS.
d /var/guix/profiles 0755 root root -

# Configuration directory (update.conf, signing key).
d /etc/andyl-os 0755 root root -
")


;;;
;;; systemd Unit: Update Check Timer
;;;
;;; Periodic timer that triggers the update check service.
;;; Active when andyl-os-update-check.timer is enabled.
;;;

(define %andyl-update-check-timer
  (let ((check-interval (config-ref "deployment.update.check-interval" 3600))
        (boot-delay     300)
        (rand-delay     600))
    (string-append
     "[Unit]\n"
     "Description=ANDYL OS Periodic Update Check\n"
     "Documentation=man:andyl-os-agent(8)\n\n"
     "[Timer]\n"
     "# Check for updates periodically (interval from config).\n"
     "OnBootSec=" (number->string boot-delay) "\n"
     "OnUnitActiveSec=" (number->string check-interval) "\n"
     "RandomizedDelaySec=" (number->string rand-delay) "\n"
     "Persistent=true\n\n"
     "[Install]\n"
     "WantedBy=timers.target\n")))


;;;
;;; systemd Unit: Update Check Service
;;;
;;; One-shot service triggered by the timer.  Checks for updates
;;; and logs the result.  In auto_update mode, the agent proceeds
;;; to download+verify+apply.
;;;
;;; ExecStart references /usr/bin/andyl-os-agent which is a symlink
;;; to the andyl-os-update-tool package's store path.
;;;

(define %andyl-update-check-unit
  "\
[Unit]
Description=ANDYL OS Update Check
Documentation=man:andyl-os-agent(8)
After=network-online.target
Wants=network-online.target

# Do not run during initial boot setup.
After=multi-user.target

[Service]
Type=oneshot

# Check for updates.  In auto mode, this triggers the full cycle.
ExecStart=/usr/bin/andyl-os-agent check

# Run as root (required for store manipulation).
User=root
Group=root

# Security hardening.
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/cache/andyl-os /var/lib/andyl-os

# Logging.
StandardOutput=journal
StandardError=journal
SyslogIdentifier=andyl-os-update
")


;;;
;;; systemd Unit: Update Apply Service
;;;
;;; Triggered manually or by the auto-update check to download,
;;; verify, and apply an update bundle.
;;;

(define %andyl-update-unit
  "\
[Unit]
Description=ANDYL OS Update Apply
Documentation=man:andyl-os-agent(8)
After=network-online.target
Wants=network-online.target

# Mutually exclusive with garbage collection.
Conflicts=andyl-os-gc.service

[Service]
Type=oneshot

# Full update cycle: download, verify, apply (no automatic reboot).
ExecStart=/usr/bin/andyl-os-agent now

# This service needs extensive privileges.
User=root
Group=root

# Timeout: allow up to 30 minutes for large updates.
TimeoutSec=1800

# Logging.
StandardOutput=journal
StandardError=journal
SyslogIdentifier=andyl-os-update

[Install]
WantedBy=multi-user.target
")


;;;
;;; systemd Unit: Health Check Service
;;;
;;; Runs after boot to verify system health.  On success, activates
;;; boot-complete.target, which triggers systemd-bless-boot to mark
;;; the generation as verified and remove the boot counting suffix.
;;;

(define %andyl-health-check-unit
  "\
[Unit]
Description=ANDYL OS Post-Boot Health Check
Documentation=man:andyl-os-agent(8)

# Run after the system is fully booted.
After=multi-user.target

# Only run if there are boot counting entries present
# (meaning we booted a new, unverified generation).
ConditionPathExists=|/boot/efi/loader/entries/andyl-os-*+*.conf

[Service]
Type=oneshot
RemainAfterExit=yes

ExecStart=/usr/bin/andyl-os-health-check

# On success, activate boot-complete.target.
# This signals systemd-bless-boot to mark the boot as good.
ExecStartPost=/bin/systemctl start boot-complete.target

# On failure, log but do not block.  Boot counting handles rollback.
StandardOutput=journal
StandardError=journal
SyslogIdentifier=andyl-os-health

[Install]
WantedBy=multi-user.target
")


;;;
;;; systemd Target: boot-complete.target
;;;
;;; A synthetic target that is reached when the health check passes.
;;; systemd-bless-boot.service depends on this target to know when
;;; it is safe to mark the current boot entry as verified.
;;;

(define %andyl-boot-complete-target
  "\
[Unit]
Description=ANDYL OS Boot Complete (Health Check Passed)
Documentation=man:andyl-os-agent(8)

# This target is pulled in by the health check service on success.
# systemd-bless-boot.service should be configured to:
#   After=boot-complete.target
#   Requires=boot-complete.target
")


;;;
;;; systemd Unit: Rollback Service
;;;
;;; Manual rollback service.  Sets the previous verified generation
;;; as the default boot entry and reboots.
;;;

(define %andyl-rollback-unit
  "\
[Unit]
Description=ANDYL OS Manual Rollback
Documentation=man:andyl-os-agent(8)

[Service]
Type=oneshot

# Rollback to previous verified generation and reboot.
ExecStart=/usr/bin/andyl-os-agent rollback
ExecStartPost=/bin/systemctl reboot

User=root
Group=root

StandardOutput=journal
StandardError=journal
SyslogIdentifier=andyl-os-rollback
")


;;;
;;; Collected Unit Files
;;;
;;; Returns an association list of (filename . content) pairs for all
;;; systemd units, configuration files, and tmpfiles related to the
;;; update system.  The image assembly module installs these into the
;;; appropriate locations in the system profile.
;;;
;;; Note: The systemd units are defined here for the collector pattern
;;; used by image assembly.  The andyl-os-update-tool package also
;;; installs its own systemd units with store-path-resolved ExecStart
;;; lines.  The package's units take precedence at runtime because
;;; systemd resolves units from the package's lib/systemd/system
;;; directory (linked into the profile).
;;;

(define (andyl-update-units)
  "Return an alist of (filename . content) pairs for all update
service systemd units, scripts, and configuration files."
  (list
   ;; Configuration
   (cons "etc/andyl-os/update.conf"
         %andyl-update-config)

   ;; tmpfiles.d for directory creation
   (cons "lib/tmpfiles.d/andyl-os-update.conf"
         %andyl-update-tmpfiles)

   ;; Update check timer and service
   (cons "lib/systemd/system/andyl-os-update-check.timer"
         %andyl-update-check-timer)
   (cons "lib/systemd/system/andyl-os-update-check.service"
         %andyl-update-check-unit)

   ;; Update apply service
   (cons "lib/systemd/system/andyl-os-update.service"
         %andyl-update-unit)

   ;; Health check service
   (cons "lib/systemd/system/andyl-os-health-check.service"
         %andyl-health-check-unit)

   ;; Boot complete target
   (cons "lib/systemd/system/boot-complete.target"
         %andyl-boot-complete-target)

   ;; Rollback service
   (cons "lib/systemd/system/andyl-os-rollback.service"
         %andyl-rollback-unit)))
