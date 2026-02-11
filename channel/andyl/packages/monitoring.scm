;;; ANDYL OS -- Monitoring Packages
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines monitoring and observability packages for ANDYL OS:
;;;
;;;   andyl-node-exporter -- Prometheus node metrics exporter
;;;
;;; Prometheus node_exporter exposes hardware and OS metrics (CPU, memory,
;;; disk, network, filesystem) as an HTTP endpoint for scraping by a
;;; Prometheus server.  It is included in the ANDYL OS base image as
;;; part of the standard observability stack.
;;;
;;; node_exporter is a Go binary, but since we do not yet have a Go
;;; toolchain in the ANDYL OS bootstrap chain, we use a pre-built
;;; static binary from the official GitHub releases.  This is a
;;; temporary approach; once a Go toolchain is available, this package
;;; should be rebuilt from source.
;;;
;;; See:
;;;   Phase 4 section 4.2 (base package list: node_exporter)
;;;   docs/brainstorm/02-kernel-and-system.md section 4.5 (sysext for monitoring)
;;;
;;; Package dependency graph:
;;;
;;;   andyl-node-exporter
;;;     (pre-built static binary; no runtime library dependencies)

(define-module (andyl packages monitoring)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl config))


;;; =========================================================================
;;; Prometheus node_exporter -- hardware and OS metrics
;;; =========================================================================
;;;
;;; node_exporter is the standard Prometheus exporter for machine-level
;;; metrics.  It collects metrics from:
;;;
;;;   - CPU: usage, frequency, temperature
;;;   - Memory: usage, swap, buffers, caches
;;;   - Disk: I/O, usage, latency per device
;;;   - Network: bytes/packets/errors per interface
;;;   - Filesystem: usage, inodes, mount points
;;;   - systemd: unit states (active, failed, etc.)
;;;   - Pressure: PSI (Pressure Stall Information) metrics
;;;   - ZFS: pool and dataset statistics (via /proc/spl/kstat/zfs)
;;;   - Textfile: custom metrics from /var/lib/node_exporter/textfile/
;;;
;;; The exporter listens on port 9100 by default and serves metrics
;;; at /metrics in Prometheus exposition format.
;;;
;;; A systemd unit file is included to run node_exporter as a service
;;; with appropriate hardening (ProtectSystem, ReadOnlyPaths, etc.).
;;;
;;; Note: This uses a pre-built static binary from the official GitHub
;;; releases.  Once the ANDYL OS Go toolchain is available, this should
;;; be rebuilt from source using gnu-build-system or go-build-system.

(define-public andyl-node-exporter
  (package
    (name "andyl-node-exporter")
    (version (config-version "monitoring" "node-exporter"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/prometheus/node_exporter/releases"
                    "/download/v" version
                    "/node_exporter-" version ".linux-amd64.tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-amd64.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (supported-systems '("x86_64-linux"))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((source  (assoc-ref %build-inputs "source"))
                 (out     (assoc-ref %outputs "out"))
                 (bindir  (string-append out "/bin"))
                 (unitdir (string-append out "/lib/systemd/system"))
                 (textdir (string-append out "/share/doc/"
                                         #$(package-name this-package))))

            ;; Unpack the tarball
            (invoke "tar" "xf" source)
            (chdir (string-append "node_exporter-"
                                  #$(package-version this-package)
                                  ".linux-amd64"))

            ;; Install the binary
            (mkdir-p bindir)
            (copy-file "node_exporter"
                       (string-append bindir "/node_exporter"))
            (chmod (string-append bindir "/node_exporter") #o755)

            ;; Install documentation
            (mkdir-p textdir)
            (for-each
             (lambda (f)
               (when (file-exists? f)
                 (install-file f textdir)))
             '("LICENSE" "NOTICE" "README.md"))

            ;; Create a systemd unit file for node_exporter
            (mkdir-p unitdir)
            (call-with-output-file
                (string-append unitdir "/node-exporter.service")
              (lambda (port)
                (display
                 "[Unit]
Description=Prometheus Node Exporter
Documentation=https://github.com/prometheus/node_exporter
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=node-exporter
Group=node-exporter
ExecStart="
                 port)
                (display (string-append out "/bin/node_exporter") port)
                (display
                 " \\
  --web.listen-address=:9100 \\
  --collector.systemd \\
  --collector.pressure \\
  --collector.zfs \\
  --collector.textfile \\
  --collector.textfile.directory=/var/lib/node_exporter/textfile

# Hardening
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/
ReadWritePaths=/var/lib/node_exporter
NoNewPrivileges=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
"
                 port)))

            ;; Create a sysusers.d entry for the node-exporter user
            (let ((sysusersdir (string-append out
                                              "/lib/sysusers.d")))
              (mkdir-p sysusersdir)
              (call-with-output-file
                  (string-append sysusersdir "/node-exporter.conf")
                (lambda (port)
                  (display "u node-exporter - \"Prometheus Node Exporter\" / /sbin/nologin\n"
                           port))))

            ;; Create a tmpfiles.d entry for the textfile collector dir
            (let ((tmpfilesdir (string-append out
                                              "/lib/tmpfiles.d")))
              (mkdir-p tmpfilesdir)
              (call-with-output-file
                  (string-append tmpfilesdir "/node-exporter.conf")
                (lambda (port)
                  (display "d /var/lib/node_exporter 0755 node-exporter node-exporter -\n"
                           port)
                  (display "d /var/lib/node_exporter/textfile 0755 node-exporter node-exporter -\n"
                           port))))))))

    (home-page "https://github.com/prometheus/node_exporter")
    (synopsis "Prometheus node metrics exporter for ANDYL OS")
    (description
     "Prometheus node_exporter exposes hardware and OS-level metrics for
scraping by a Prometheus server.  Collects CPU, memory, disk, network,
filesystem, systemd unit state, PSI pressure, and ZFS pool metrics.
Includes a systemd service unit with security hardening, a sysusers.d
entry for the service user, and a tmpfiles.d entry for the textfile
collector directory.  Listens on port 9100.")
    (license license:asl2.0)))
