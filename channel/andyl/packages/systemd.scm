;;; ANDYL OS -- systemd and Init System Dependencies
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines systemd (the init system for ANDYL OS) and its
;;; essential dependencies: D-Bus, util-linux, and kmod.
;;;
;;; ANDYL OS uses systemd instead of Guix's default Shepherd init system.
;;; This is a deliberate architectural choice -- systemd provides battle-tested
;;; service management, boot counting (systemd-boot), network management
;;; (networkd/resolved), structured logging (journald), and broad ecosystem
;;; compatibility (Kubernetes, container runtimes, monitoring tools).
;;;
;;; See RFC-0001 section 6 ("systemd as PID 1") for the full rationale.
;;;
;;; Package dependency graph:
;;;
;;;   andyl-systemd
;;;     +-- andyl-dbus           (IPC message bus)
;;;     +-- andyl-util-linux     (mount, blkid, fdisk, etc.)
;;;     +-- andyl-kmod           (modprobe, insmod, rmmod)
;;;     +-- andyl-glibc          (C library)
;;;     +-- andyl-linux-headers  (kernel API headers)
;;;     +-- andyl-openssl        (TLS/crypto)
;;;     +-- andyl-zlib           (deflate compression)
;;;     +-- andyl-xz             (LZMA compression)
;;;     +-- andyl-zstd           (Zstandard compression)
;;;     +-- andyl-lz4            (fast compression)

(define-module (andyl packages systemd)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system meson)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages linux)
  #:use-module (andyl packages base)
  #:use-module (andyl packages compression)
  #:use-module (andyl packages tls)
  #:use-module (andyl config))


;;; =========================================================================
;;; D-Bus -- message bus system
;;; =========================================================================
;;;
;;; D-Bus provides a system message bus that systemd and other services
;;; use for inter-process communication.  systemd's logind, machined, and
;;; other components require D-Bus for their control APIs.

(define-public andyl-dbus
  (package
    (name "andyl-dbus")
    (version (config-version "init" "dbus"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://dbus.freedesktop.org/releases/dbus/dbus-"
                    version ".tar.xz"))
              (sha256
               ;; TODO: guix download https://dbus.freedesktop.org/releases/dbus/dbus-1.14.10.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-pkg-config))
    (inputs (list andyl-glibc))
    (arguments
     (list
      #:configure-flags
      #~(list "--disable-xml-docs"
              "--disable-doxygen-docs"
              "--disable-tests"
              ;; Use /var/run/dbus for the system socket
              "--with-system-socket=/var/run/dbus/system_bus_socket"
              "--with-systemdsystemunitdir=lib/systemd/system"
              "--with-systemduserunitdir=lib/systemd/user")
      #:tests? #f))
    (home-page "https://www.freedesktop.org/wiki/Software/dbus/")
    (synopsis "D-Bus message bus system for ANDYL OS")
    (description
     "D-Bus is a message bus system for inter-process communication (IPC).
It provides a system bus used by systemd components (logind, machined)
and other system services for exchanging messages and notifications.")
    (license (list license:gpl2+ license:afl2.1))))


;;; =========================================================================
;;; util-linux -- essential system utilities
;;; =========================================================================
;;;
;;; util-linux provides mount, umount, fdisk, blkid, lsblk, and many
;;; other essential low-level system utilities.  systemd depends on
;;; libblkid and libmount from this package.

(define-public andyl-util-linux
  (package
    (name "andyl-util-linux")
    (version (config-version "init" "util-linux"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://cdn.kernel.org/pub/linux/utils/util-linux/v"
                    (version-major+minor version)
                    "/util-linux-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download https://cdn.kernel.org/pub/linux/utils/util-linux/v2.40/util-linux-2.40.2.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-pkg-config))
    (inputs (list andyl-glibc andyl-zlib))
    (arguments
     (list
      #:configure-flags
      #~(list "--disable-static"
              ;; Disable components not needed for server use
              "--without-python"
              "--without-systemd"    ; avoid circular dependency
              "--disable-pylibmount"
              ;; Enable essential libraries that systemd needs
              "--enable-libblkid"
              "--enable-libmount"
              "--enable-libfdisk"
              "--enable-libuuid")
      #:tests? #f))
    (home-page "https://github.com/util-linux/util-linux")
    (synopsis "Essential system utilities for ANDYL OS")
    (description
     "util-linux provides essential low-level system utilities: mount,
umount, fdisk, blkid, lsblk, lscpu, lsns, and many others.  The libblkid
and libmount libraries from this package are required by systemd for
partition detection and filesystem mounting.")
    (license license:gpl2+)))


;;; =========================================================================
;;; kmod -- kernel module tools
;;; =========================================================================
;;;
;;; kmod provides the user-space tools for loading and managing Linux
;;; kernel modules: modprobe, insmod, rmmod, lsmod, modinfo, and depmod.
;;; systemd's module loading (modules-load.d, udev module rules) depends
;;; on libkmod from this package.

(define-public andyl-kmod
  (package
    (name "andyl-kmod")
    (version (config-version "init" "kmod"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://cdn.kernel.org/pub/linux/utils/kernel/kmod/kmod-"
                    version ".tar.xz"))
              (sha256
               ;; TODO: guix download https://cdn.kernel.org/pub/linux/utils/kernel/kmod/kmod-33.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs (list andyl-gcc andyl-pkg-config))
    (inputs (list andyl-glibc andyl-xz andyl-zlib andyl-zstd))
    (arguments
     (list
      #:configure-flags
      #~(list "--with-xz"       ; support xz-compressed modules
              "--with-zlib"     ; support gzip-compressed modules
              "--with-zstd"     ; support zstd-compressed modules
              "--with-openssl"  ; module signature verification
              "--disable-static")
      #:phases
      #~(modify-phases %standard-phases
          ;; Create compatibility symlinks: modprobe, insmod, rmmod,
          ;; lsmod, modinfo, depmod all point to the kmod binary
          (add-after 'install 'install-modprobe-links
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out (assoc-ref outputs "out"))
                     (sbin (string-append out "/sbin"))
                     (kmod (string-append out "/bin/kmod")))
                (mkdir-p sbin)
                (for-each
                 (lambda (tool)
                   (symlink kmod (string-append sbin "/" tool)))
                 '("modprobe" "insmod" "rmmod" "lsmod"
                   "modinfo" "depmod"))))))
      #:tests? #f))
    (home-page "https://git.kernel.org/pub/scm/utils/kernel/kmod/kmod.git")
    (synopsis "Kernel module tools for ANDYL OS")
    (description
     "kmod provides tools and a library (libkmod) for loading, unloading,
and managing Linux kernel modules.  Provides modprobe, insmod, rmmod,
lsmod, modinfo, and depmod.  Supports compressed modules (xz, gzip, zstd)
and module signature verification.  systemd uses libkmod for automatic
module loading via udev rules and modules-load.d configuration.")
    (license license:lgpl2.1+)))


;;; =========================================================================
;;; systemd -- system and service manager
;;; =========================================================================
;;;
;;; systemd is the init system (PID 1) for ANDYL OS.  It provides:
;;;   - Service management (systemctl, unit files)
;;;   - journald: structured binary logging
;;;   - networkd: predictable server network management
;;;   - resolved: DNS with DNSSEC and DNS-over-TLS
;;;   - timesyncd: lightweight NTP client
;;;   - tmpfiles.d: volatile directory/file creation on boot
;;;   - sysusers.d: system user/group creation on boot
;;;   - systemd-boot: UEFI boot manager with generation entries
;;;   - ukify: Unified Kernel Image generation
;;;   - udevd: device management and hotplug
;;;   - systemd-sysext: role-based system extensions
;;;   - systemd-repart: declarative partition management
;;;   - systemd-oomd: PSI-based OOM management
;;;   - systemd-cryptsetup: LUKS encrypted volume support
;;;   - systemd-bless-boot: boot counting for automatic rollback
;;;
;;; See RFC-0001 and phase-3-kernel-systemd.md for the full design.

(define-public andyl-systemd
  (package
    (name "andyl-systemd")
    (version (config-version "init" "systemd"))
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/systemd/systemd")
                    (commit (string-append "v" version))))
              (file-name (git-file-name name version))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/systemd/systemd/archive/v256.9.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system meson-build-system)

    (arguments
     (list
      #:configure-flags
      #~(list
         ;; === Core Components ===
         ;; SELinux mandatory access control (see RFC-0001 security)
         "-Dselinux=true"
         ;; Block device identification (required for udev/mount)
         "-Dblkid=true"
         ;; Kernel module loading support
         "-Dkmod=true"

         ;; === Network Stack ===
         ;; systemd-networkd for predictable server networking
         "-Dnetworkd=true"
         ;; systemd-resolved for DNS (DNSSEC, DNS-over-TLS)
         "-Dresolved=true"
         ;; systemd-timesyncd for NTP
         "-Dtimesyncd=true"

         ;; === Machine and Container Management ===
         ;; systemd-machined for container/VM registration
         "-Dmachined=true"

         ;; === Boot Management ===
         ;; systemd-boot UEFI boot manager (generation-based boot)
         "-Dbootloader=true"
         ;; ukify for Unified Kernel Image creation
         "-Dukify=true"
         ;; systemd-firstboot for initial machine setup
         "-Dfirstboot=true"
         ;; systemd-bless-boot for boot counting / auto-rollback
         "-Dbless-boot=true"

         ;; === Disk and Partition Management ===
         ;; systemd-repart for declarative partition management
         "-Drepart=true"
         ;; systemd-cryptsetup for LUKS volume support
         "-Dcryptsetup=true"

         ;; === System Extensions and OOM ===
         ;; systemd-sysext for role-based /usr overlays
         "-Dsysext=true"
         ;; systemd-oomd for PSI-based OOM management
         "-Doomd=true"

         ;; === Device Management ===
         ;; udevd for device enumeration and hotplug
         "-Dhwdb=true"

         ;; === Disabled Components ===
         ;; systemd-homed is for desktop user home management; not
         ;; needed on headless servers
         "-Dhomed=false"
         ;; userdb is tied to homed/LDAP desktop workflows
         "-Duserdb=false"
         ;; GUI-related features not needed on headless servers
         "-Dxkbcommon=false"

         ;; === Build Options ===
         ;; Point to our kernel headers
         (string-append "-Dkerneldir="
                        #$(this-package-input "andyl-linux-headers")
                        "/include"))

      #:tests? #f))

    (native-inputs
     (list andyl-gcc
           andyl-pkg-config
           andyl-gawk
           ;; TODO: andyl-python is needed for meson and various
           ;; systemd build scripts.  Add when python package is
           ;; defined (likely in a packages/python.scm module).
           ;; andyl-python
           ))

    (inputs
     (list andyl-glibc
           andyl-linux-headers
           andyl-openssl
           andyl-zlib
           andyl-xz
           andyl-zstd
           andyl-lz4
           andyl-dbus
           andyl-util-linux
           andyl-kmod))

    (home-page "https://systemd.io/")
    (synopsis "systemd -- system and service manager for ANDYL OS")
    (description
     "systemd is the init system (PID 1) and service manager for ANDYL OS.
Provides journald (structured logging), networkd (network management),
resolved (DNS), timesyncd (NTP), tmpfiles.d/sysusers.d (boot-time state
creation), systemd-boot (UEFI boot manager with generation entries),
ukify (Unified Kernel Image generation), udevd (device management),
systemd-sysext (role-based system extensions), and systemd-oomd
(PSI-based OOM management).  Configured for server use with SELinux
support enabled.  Built through the ANDYL OS bootstrap chain.")
    (license license:lgpl2.1+)))
