;;; ANDYL OS -- Linux Audit Framework Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the Linux Audit Framework (auditd and related tools)
;;; for ANDYL OS.  The audit subsystem is a critical component of the
;;; security infrastructure:
;;;
;;;   - SELinux requires the audit subsystem for logging AVC (Access Vector
;;;     Cache) denials and policy decisions.
;;;   - The kernel's CONFIG_AUDIT and CONFIG_AUDITSYSCALL options generate
;;;     audit events; auditd collects and writes them to disk.
;;;   - Tools: auditd (daemon), ausearch (query logs), aureport (reports),
;;;     auditctl (configure rules), audit2allow (generate SELinux policy
;;;     from denials).
;;;
;;; See phase-3-kernel-systemd.md section 3.12 (SELinux Policy Development)
;;; for how the audit subsystem integrates with SELinux enforcement.

(define-module (andyl packages audit)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages linux)
  #:use-module (andyl packages base)
  #:use-module (andyl config))


;;; =========================================================================
;;; audit -- Linux Audit Framework
;;; =========================================================================
;;;
;;; The audit framework provides user-space components for the Linux kernel
;;; audit subsystem.  The kernel generates audit events for syscalls, file
;;; access, network activity, and SELinux policy decisions.  auditd collects
;;; these events and writes them to /var/log/audit/audit.log.
;;;
;;; Key components:
;;;   auditd     -- audit event collection daemon
;;;   auditctl   -- configure audit rules at runtime
;;;   ausearch   -- search audit log entries
;;;   aureport   -- generate summary reports from audit logs
;;;   autrace    -- trace a process using audit rules
;;;   audisp     -- audit event dispatcher (plugins for remote logging, etc.)
;;;
;;; For ANDYL OS, the audit daemon runs as a systemd service and its logs
;;; are stored on the ZFS mutable data pool (/var/log/audit/).  SELinux
;;; AVC denials are logged through this subsystem, and tools like ausearch
;;; and audit2allow are used during policy development.

(define-public andyl-audit
  (package
    (name "andyl-audit")
    (version (config-version "security" "audit"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://people.redhat.com/sgrubb/audit/audit-"
                    version ".tar.gz"))
              (sha256
               ;; TODO: guix download https://people.redhat.com/sgrubb/audit/audit-4.0.2.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)

    (arguments
     (list
      #:configure-flags
      #~(list
         ;; Install into our output prefix
         (string-append "--prefix=" #$output)

         ;; Use the system directories expected by systemd and SELinux
         "--sbindir=/sbin"
         (string-append "--with-libdir=" #$output "/lib")

         ;; Disable Python bindings (we don't need them on servers
         ;; and they add a heavyweight dependency)
         "--without-python"
         "--without-python3"

         ;; Disable Go bindings
         "--without-golang"

         ;; Enable systemd integration for the auditd service unit
         "--enable-systemd"

         ;; Use the kernel headers from our toolchain
         (string-append "--with-linux-headers="
                        #$(this-package-input "andyl-linux-headers")
                        "/include")

         ;; Audit log directory (on ZFS mutable data pool)
         "--with-log-dir=/var/log/audit"

         ;; PID file location
         "--with-pid-dir=/run")

      #:phases
      #~(modify-phases %standard-phases
          ;; Fix the sbin installation path to use our output
          (add-before 'configure 'fix-sbindir
            (lambda _
              ;; Override sbindir to install into our output, not /sbin
              (setenv "sbindir" (string-append #$output "/sbin")))))

      #:tests? #f))

    (native-inputs (list andyl-gcc andyl-pkg-config))
    (inputs (list andyl-glibc andyl-linux-headers))

    (home-page "https://people.redhat.com/sgrubb/audit/")
    (synopsis "Linux Audit Framework for ANDYL OS")
    (description
     "The Linux Audit Framework provides the user-space components for the
kernel audit subsystem.  Includes auditd (audit event collection daemon),
auditctl (runtime rule configuration), ausearch (log searching), aureport
(summary reports), and audisp (event dispatcher for plugins).  Required
by SELinux for logging AVC denials and policy decisions.  Audit logs are
stored in /var/log/audit/ on the ZFS mutable data pool.  During SELinux
policy development, ausearch and audit2allow are used to identify and
resolve access denials.")
    (license license:gpl2+)))
