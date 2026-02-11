;;; ANDYL OS -- Base Operating System Definition
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the base operating-system record for ANDYL OS.
;;; It is the foundational system configuration from which all deployment
;;; variants (server, workstation, etc.) inherit.
;;;
;;; ANDYL OS is an immutable, server-oriented Linux distribution:
;;;   - Root filesystem: ext4, mounted read-only (golden image)
;;;   - Mutable data: ZFS datapool under /var (created by Ignition on first boot)
;;;   - /etc: OverlayFS (lower=profile /etc from ext4, upper=/var/etc-overlay on ZFS)
;;;   - Init system: systemd (NOT Guix's default Shepherd)
;;;   - Boot loader: systemd-boot with UKI support
;;;   - Security: SELinux in enforcing mode
;;;
;;; This module does NOT use Guix's (gnu system) or (gnu services) because
;;; ANDYL OS uses systemd instead of Shepherd.  Instead, we define a custom
;;; operating-system-like record that describes the system configuration and
;;; is consumed by the image assembly module (andyl images ext4).
;;;
;;; See:
;;;   RFC-0001 (System Architecture)
;;;   Phase 4 (Immutable Base Image Assembly)

(define-module (andyl system base)
  #:use-module (guix packages)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages kernel)
  #:use-module (andyl packages firmware)
  #:use-module (andyl packages systemd)
  #:use-module (andyl packages dracut)
  #:use-module (andyl packages base)
  #:use-module (andyl packages zfs)
  #:use-module (andyl packages selinux)
  #:use-module (andyl packages selinux-policy)
  #:use-module (andyl packages networking)
  #:use-module (andyl packages audit)
  #:use-module (andyl config)
  #:export (andyl-operating-system
            andyl-operating-system?
            andyl-operating-system-host-name
            andyl-operating-system-kernel
            andyl-operating-system-kernel-arguments
            andyl-operating-system-firmware
            andyl-operating-system-initrd-generator
            andyl-operating-system-bootloader
            andyl-operating-system-file-systems
            andyl-operating-system-packages
            andyl-operating-system-services
            andyl-operating-system-extra-packages
            andyl-operating-system-extra-services

            andyl-file-system
            andyl-file-system?
            andyl-file-system-device
            andyl-file-system-mount-point
            andyl-file-system-type
            andyl-file-system-flags
            andyl-file-system-options

            andyl-bootloader-configuration
            andyl-bootloader-configuration?
            andyl-bootloader-configuration-bootloader
            andyl-bootloader-configuration-targets
            andyl-bootloader-configuration-timeout

            %andyl-base-kernel-arguments
            %andyl-base-file-systems
            %andyl-base-packages
            %andyl-base-services
            andyl-os-base))


;;;
;;; Records
;;;
;;; Since ANDYL OS uses systemd instead of Shepherd, we cannot use Guix's
;;; built-in (gnu system) operating-system record, which is tightly coupled
;;; to Shepherd and Guix services.  Instead, we define our own records that
;;; describe the system configuration in a way that the image assembly
;;; module can consume.
;;;

(define-record-type* <andyl-file-system>
  andyl-file-system make-andyl-file-system
  andyl-file-system?
  ;; Device specification: by-label, by-uuid, or device path.
  (device       andyl-file-system-device)
  ;; Where to mount this filesystem.
  (mount-point  andyl-file-system-mount-point)
  ;; Filesystem type: "ext4", "zfs", "overlay", "tmpfs", "vfat".
  (type         andyl-file-system-type)
  ;; Mount flags as a list of strings: "ro", "noatime", "nosuid", etc.
  (flags        andyl-file-system-flags
                (default '()))
  ;; Mount options string (passed to -o).
  (options      andyl-file-system-options
                (default #f)))


(define-record-type* <andyl-bootloader-configuration>
  andyl-bootloader-configuration make-andyl-bootloader-configuration
  andyl-bootloader-configuration?
  ;; Bootloader type: 'systemd-boot
  (bootloader   andyl-bootloader-configuration-bootloader
                (default 'systemd-boot))
  ;; List of EFI System Partition mount targets.
  (targets      andyl-bootloader-configuration-targets
                (default '("/boot/efi")))
  ;; Boot menu timeout in seconds.
  (timeout      andyl-bootloader-configuration-timeout
                (default 3)))


(define-record-type* <andyl-operating-system>
  andyl-operating-system make-andyl-operating-system
  andyl-operating-system?
  ;; System hostname (overridden by Ignition at deploy time).
  (host-name         andyl-operating-system-host-name
                     (default "andyl-os"))
  ;; Kernel package.
  (kernel            andyl-operating-system-kernel
                     (default andyl-kernel))
  ;; Kernel command-line arguments.
  (kernel-arguments  andyl-operating-system-kernel-arguments
                     (default %andyl-base-kernel-arguments))
  ;; Firmware package (CPU microcode, NIC firmware).
  (firmware          andyl-operating-system-firmware
                     (default andyl-firmware))
  ;; Initrd generator package (dracut, build-time only).
  (initrd-generator  andyl-operating-system-initrd-generator
                     (default andyl-dracut))
  ;; Bootloader configuration.
  (bootloader        andyl-operating-system-bootloader
                     (default (andyl-bootloader-configuration)))
  ;; Filesystem mount table.
  (file-systems      andyl-operating-system-file-systems
                     (default %andyl-base-file-systems))
  ;; Base system packages.
  (packages          andyl-operating-system-packages
                     (default %andyl-base-packages))
  ;; Systemd service unit file packages / service definitions.
  (services          andyl-operating-system-services
                     (default %andyl-base-services))
  ;; Additional packages beyond the base set (for variant configs).
  (extra-packages    andyl-operating-system-extra-packages
                     (default '()))
  ;; Additional services beyond the base set (for variant configs).
  (extra-services    andyl-operating-system-extra-services
                     (default '())))


;;;
;;; Kernel Arguments
;;;
;;; The kernel command line configures the boot behavior of ANDYL OS:
;;;   - root=LABEL=ANDYL-ROOT: find the root partition by label
;;;   - ro: mount root read-only (immutable golden image)
;;;   - quiet: suppress verbose boot messages
;;;   - console=ttyS0,...: serial console for headless servers
;;;   - security=selinux selinux=1: enable SELinux
;;;   - enforcing=0: permissive mode for initial development
;;;     (change to enforcing=1 for production)
;;;

(define %andyl-base-kernel-arguments
  (config-ref/list "boot.kernel-args.base"))


;;;
;;; Filesystem Layout
;;;
;;; The filesystem layout implements the immutable root + mutable /var design:
;;;
;;;   /           ext4 (ANDYL-ROOT, read-only from golden image)
;;;   /boot/efi   vfat (ESP, FAT32, contains systemd-boot + UKI)
;;;   /var        ZFS  (datapool/var, writable, created by Ignition)
;;;   /var/lib    ZFS  (datapool/var-lib, persistent app state)
;;;   /var/log    ZFS  (datapool/var-log, persistent logs)
;;;   /etc        overlay (lower=/sysroot/etc, upper=/var/etc-overlay)
;;;   /tmp        tmpfs (volatile)
;;;   /run        tmpfs (volatile)
;;;
;;; ZFS datasets are NOT defined here because they are created by Ignition
;;; on first boot, not at image build time.  The ZFS entries below serve
;;; as documentation of the expected runtime mount layout.
;;;

(define %andyl-base-file-systems
  (list
   ;; Root filesystem: ext4 golden image, mounted read-only.
   ;; The kernel mounts this via the root= command-line parameter.
   (andyl-file-system
    (device (string-append "LABEL=" (config-ref "boot.filesystem.root-label")))
    (mount-point "/")
    (type (config-ref "boot.filesystem.root-type"))
    (flags '("ro" "noatime")))

   ;; EFI System Partition: contains systemd-boot and UKI/boot entries.
   (andyl-file-system
    (device (string-append "LABEL=" (config-ref "boot.filesystem.esp-label")))
    (mount-point "/boot/efi")
    (type "vfat")
    (flags '("noatime" "nosuid" "nodev" "noexec"))
    (options "umask=0077"))

   ;; /var: writable mutable data area (ZFS dataset, created by Ignition).
   ;; This entry documents the runtime expectation; the ZFS dataset is
   ;; created and mounted by Ignition + systemd ZFS mount units.
   (andyl-file-system
    (device "datapool/var")
    (mount-point "/var")
    (type "zfs")
    (flags '("noatime")))

   ;; /var/lib: persistent application state (containers, kubelet, etcd).
   (andyl-file-system
    (device "datapool/var-lib")
    (mount-point "/var/lib")
    (type "zfs")
    (flags '("noatime")))

   ;; /var/log: persistent logs (systemd journal, audit).
   (andyl-file-system
    (device "datapool/var-log")
    (mount-point "/var/log")
    (type "zfs")
    (flags '("noatime")))

   ;; /etc: OverlayFS combining the immutable base /etc with a writable
   ;; upper layer on ZFS.  Mounted by a systemd mount unit defined in
   ;; (andyl services overlay).
   (andyl-file-system
    (device "overlay")
    (mount-point "/etc")
    (type "overlay")
    (options "lowerdir=/sysroot/etc,upperdir=/var/etc-overlay,workdir=/var/etc-overlay-work"))

   ;; /tmp: volatile tmpfs, cleared on every boot.
   (andyl-file-system
    (device "tmpfs")
    (mount-point "/tmp")
    (type "tmpfs")
    (flags '("nosuid" "nodev"))
    (options "mode=1777,size=50%"))

   ;; /run: volatile tmpfs for runtime state (PID files, sockets).
   (andyl-file-system
    (device "tmpfs")
    (mount-point "/run")
    (type "tmpfs")
    (flags '("nosuid" "nodev"))
    (options "mode=0755,size=25%"))))


;;;
;;; Base Packages
;;;
;;; The base package set includes everything needed for a minimal bootable
;;; ANDYL OS system.  It is intentionally minimal -- additional packages
;;; are added by variant configurations (server.scm) or system extensions
;;; (systemd-sysext).
;;;
;;; Categories:
;;;   1. Init system and core services (systemd)
;;;   2. Core userspace utilities (coreutils, bash, grep, sed, etc.)
;;;   3. Storage (ZFS tools and kernel modules)
;;;   4. Security (SELinux userspace, audit, policy)
;;;   5. Networking (openssh, curl, nftables, chrony)
;;;   6. Firmware (CPU microcode, NIC firmware)
;;;

(define %andyl-base-packages
  (list
   ;; === Init system and core services ===
   andyl-systemd                    ; PID 1, journald, networkd, resolved,
                                    ; timesyncd, udevd, tmpfiles.d, sysusers.d,
                                    ; systemd-boot, ukify

   ;; === Core userspace utilities ===
   andyl-coreutils                  ; ls, cp, mv, rm, cat, etc.
   andyl-bash                       ; Shell
   andyl-grep                       ; Pattern matching
   andyl-sed                        ; Stream editor
   andyl-findutils                  ; find, xargs
   andyl-gawk                       ; Text processing
   andyl-tar                        ; Archive utility
   andyl-gzip                       ; Compression
   andyl-diffutils                  ; File comparison
   andyl-util-linux                 ; mount, blkid, lsblk, etc.
   andyl-kmod                       ; modprobe, insmod, lsmod

   ;; === Storage: ZFS ===
   andyl-zfs-modules                ; ZFS kernel modules (zfs.ko, spl.ko)
   andyl-zfs-tools                  ; zpool, zfs, zdb, zed

   ;; === Security: SELinux ===
   andyl-libsepol                   ; Binary policy manipulation
   andyl-libselinux                 ; Userspace API
   andyl-libsemanage                ; Policy management
   andyl-policycoreutils            ; sestatus, restorecon, semodule, etc.
   andyl-selinux-policy-targeted    ; Upstream reference targeted policy
   andyl-container-selinux          ; Container runtime policy module
   andyl-selinux-policy             ; ANDYL OS custom policy modules

   ;; === Security: Audit ===
   andyl-audit                      ; auditd, ausearch, aureport, auditctl

   ;; === Networking ===
   andyl-openssh                    ; SSH client and server
   andyl-curl                       ; HTTP/HTTPS client
   andyl-nftables                   ; Modern firewall (nft)
   andyl-iptables                   ; Legacy firewall (Kubernetes compat)
   andyl-iproute2                   ; ip, ss, tc, bridge
   andyl-chrony                     ; NTP time synchronization

   ;; === Firmware ===
   andyl-firmware))                 ; CPU microcode, NIC firmware


;;;
;;; Base Services
;;;
;;; Services are represented as package names or identifiers that the
;;; image assembly module uses to generate systemd unit file symlinks
;;; and configuration.  Since ANDYL OS uses systemd (not Shepherd),
;;; service configuration is done through systemd unit files installed
;;; by the packages themselves and through additional unit files from
;;; the (andyl services *) modules.
;;;
;;; The base service set includes only the essential services for a
;;; bootable system.  Variant-specific services (e.g., SSH hardening,
;;; monitoring agents) are added by server.scm or other variants.
;;;

(define %andyl-base-services
  ;; List of service identifiers.  Each entry maps to a systemd unit
  ;; that must be enabled (symlinked into the appropriate .wants/ target).
  (list
   ;; === systemd core services (always active) ===
   "systemd-journald.service"       ; Structured logging
   "systemd-networkd.service"       ; Network management
   "systemd-resolved.service"       ; DNS resolution
   "systemd-timesyncd.service"      ; Basic NTP
   "systemd-udevd.service"         ; Device management
   "systemd-tmpfiles-setup.service" ; Volatile directory creation
   "systemd-sysusers.service"       ; System user/group creation
   "systemd-bless-boot.service"     ; Boot counting / auto-rollback

   ;; === SELinux ===
   ;; SELinux policy loading and enforcement (defined in andyl services selinux)
   "andyl-selinux-load.service"
   "andyl-selinux-relabel.service"

   ;; === Overlay /etc ===
   ;; OverlayFS mount for /etc (defined in andyl services overlay)
   "etc.mount"

   ;; === ZFS ===
   ;; ZFS pool import and dataset mounting (from andyl-zfs-tools package)
   "zfs-import-cache.service"
   "zfs-mount.service"
   "zfs.target"

   ;; === Audit ===
   "auditd.service"))


;;;
;;; Default Operating System
;;;
;;; andyl-os-base is the default system configuration with all base
;;; defaults applied.  Variant configurations (server, etc.) override
;;; specific fields.
;;;

(define andyl-os-base
  (andyl-operating-system))
