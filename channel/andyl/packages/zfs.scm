;;; ANDYL OS -- ZFS Packages (Kernel Modules, Userspace Tools, Snapshots)
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the OpenZFS packages for ANDYL OS:
;;;
;;;   andyl-zfs-modules       -- OpenZFS kernel modules (zfs.ko, spl.ko)
;;;   andyl-zfs-tools         -- Userspace tools (zpool, zfs, zdb, zed)
;;;   andyl-zfs-auto-snapshot -- Automatic ZFS snapshot management
;;;
;;; OpenZFS provides the ZFS filesystem for ANDYL OS mutable data storage.
;;; The root filesystem is ext4 (read-only), while ZFS is used for mutable
;;; datasets under /var: application state, container storage, logs, etc.
;;;
;;; ZFS is built out-of-tree against the custom ANDYL OS kernel.  The
;;; kernel package (andyl-linux) preserves Module.symvers and .config in
;;; its output for this purpose.
;;;
;;; Architecture:
;;;   - Root filesystem: ext4 (immutable, in the golden image)
;;;   - Data pool: ZFS (created by Ignition at first boot)
;;;   - ZFS datasets: /var/lib, /var/log, /var/cache, etc.
;;;
;;; See:
;;;   RFC-0001 sections 5, 8 (filesystem layout, /var as writable area)
;;;   Phase 3 sections 3.5, 3.6, 3.7 (ZFS modules, tools, depmod)
;;;
;;; Package dependency graph:
;;;
;;;   andyl-zfs-modules
;;;     +-- andyl-linux         (kernel build output for Module.symvers)
;;;     +-- andyl-linux-headers (kernel headers)
;;;
;;;   andyl-zfs-tools
;;;     +-- andyl-util-linux    (libblkid, libmount, libuuid)
;;;     +-- andyl-openssl       (crypto for ZFS encryption)
;;;     +-- andyl-zlib          (compression)
;;;     +-- andyl-lz4           (LZ4 compression)
;;;     +-- andyl-zstd          (Zstandard compression)
;;;
;;;   andyl-zfs-auto-snapshot
;;;     +-- andyl-bash          (shell interpreter)
;;;     +-- andyl-zfs-tools     (zfs command)

(define-module (andyl packages zfs)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system trivial)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages linux)
  #:use-module (andyl packages kernel)
  #:use-module (andyl packages base)
  #:use-module (andyl packages compression)
  #:use-module (andyl packages tls)
  #:use-module (andyl packages systemd)
  #:use-module (andyl config))


;;; =========================================================================
;;; OpenZFS version used for both kernel modules and userspace tools
;;;
;;; OpenZFS 2.3.x is required for compatibility with the 6.12 LTS kernel.
;;; OpenZFS 2.2.x supports up to kernel 6.11; 2.3.x adds 6.12+ support.
;;; See docs/brainstorm/02-kernel-and-system.md section 5.1.
;;; =========================================================================

(define %zfs-version (config-version "storage" "zfs"))

(define %zfs-source
  (origin
    (method url-fetch)
    (uri (string-append
          "https://github.com/openzfs/zfs/releases/download/zfs-"
          %zfs-version "/zfs-" %zfs-version ".tar.gz"))
    (sha256
     ;; TODO: Compute actual hash:
     ;;   guix download https://github.com/openzfs/zfs/releases/download/zfs-2.3.0/zfs-2.3.0.tar.gz
     (base32 "0000000000000000000000000000000000000000000000000000"))))


;;; =========================================================================
;;; OpenZFS Kernel Modules
;;; =========================================================================
;;;
;;; Builds the ZFS kernel modules (zfs.ko, spl.ko, etc.) against the
;;; ANDYL OS custom kernel.  These modules are built out-of-tree using
;;; --with-linux and --with-linux-obj pointing to the andyl-linux
;;; package's build artifacts (Module.symvers, .config).
;;;
;;; The kernel modules are installed to lib/modules/<version>/extra/
;;; and must be merged with the kernel's own modules tree and processed
;;; by depmod before deployment (see phase 3.7).
;;;
;;; Only kernel modules are built here (--with-config=kernel).
;;; Userspace tools are built separately in andyl-zfs-tools.

(define-public andyl-zfs-modules
  (package
    (name "andyl-zfs-modules")
    (version %zfs-version)
    (source %zfs-source)
    (build-system gnu-build-system)
    (arguments
     (list
      #:configure-flags
      #~(list
         ;; Build only kernel modules, not userspace tools
         "--with-config=kernel"

         ;; Point to the ANDYL OS kernel source and build output.
         ;; andyl-linux installs Module.symvers and .config under
         ;; lib/modules/<version>/build/ for out-of-tree module builds.
         (string-append "--with-linux="
                        #$(this-package-input "andyl-linux")
                        "/lib/modules/"
                        #$(package-version andyl-linux)
                        "/build")
         (string-append "--with-linux-obj="
                        #$(this-package-input "andyl-linux")
                        "/lib/modules/"
                        #$(package-version andyl-linux)
                        "/build")

         ;; Enable systemd integration for ZFS mount/import services
         "--enable-systemd"
         (string-append "--with-systemdunitdir="
                        (assoc-ref %outputs "out")
                        "/lib/systemd/system")
         (string-append "--with-systemdpresetdir="
                        (assoc-ref %outputs "out")
                        "/lib/systemd/system-preset"))

      #:phases
      #~(modify-phases %standard-phases
          ;; Install modules to our output path rather than the
          ;; kernel's module directory
          (add-after 'install 'fix-module-path
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                ;; Ensure the module directory structure exists
                ;; under our output path
                #t))))

      #:tests? #f))

    (native-inputs
     (list andyl-gcc
           andyl-pkg-config))

    (inputs
     (list andyl-linux
           andyl-linux-headers
           andyl-glibc))

    (home-page "https://openzfs.org/")
    (synopsis "OpenZFS kernel modules for ANDYL OS")
    (description
     "OpenZFS kernel modules (zfs.ko, spl.ko, and related modules) built
against the ANDYL OS custom Linux kernel.  These modules provide the
ZFS filesystem used for mutable data storage under /var.  The root
filesystem uses ext4; ZFS is used for data pools created by Ignition
at first boot.")
    (license license:cddl1.0)))


;;; =========================================================================
;;; OpenZFS Userspace Tools
;;; =========================================================================
;;;
;;; Builds the ZFS userspace tools: zpool, zfs, zdb, zed, mount.zfs,
;;; and related utilities.  These tools manage ZFS pools and datasets
;;; at runtime.
;;;
;;; Key commands:
;;;   zpool   -- Pool management (create, destroy, status, scrub, import)
;;;   zfs     -- Dataset management (create, destroy, snapshot, send/recv)
;;;   zdb     -- ZFS debugger (pool/dataset inspection)
;;;   zed     -- ZFS event daemon (reacts to pool/disk events)
;;;
;;; Only userspace tools are built here (--with-config=user).
;;; Kernel modules are built separately in andyl-zfs-modules.

(define-public andyl-zfs-tools
  (package
    (name "andyl-zfs-tools")
    (version %zfs-version)
    (source %zfs-source)
    (build-system gnu-build-system)
    (arguments
     (list
      #:configure-flags
      #~(list
         ;; Build only userspace tools, not kernel modules
         "--with-config=user"

         ;; Enable systemd integration (unit files for zfs-import, zfs-mount)
         "--enable-systemd"
         (string-append "--with-systemdunitdir="
                        (assoc-ref %outputs "out")
                        "/lib/systemd/system")
         (string-append "--with-systemdpresetdir="
                        (assoc-ref %outputs "out")
                        "/lib/systemd/system-preset")

         ;; Mount helper installation path
         (string-append "--with-mounthelperdir="
                        (assoc-ref %outputs "out") "/sbin"))

      #:tests? #f))

    (native-inputs
     (list andyl-gcc
           andyl-pkg-config))

    (inputs
     (list andyl-glibc
           andyl-linux-headers
           andyl-util-linux      ; libblkid, libmount, libuuid
           andyl-openssl         ; crypto for ZFS native encryption
           andyl-zlib            ; deflate compression
           andyl-lz4             ; LZ4 compression
           andyl-zstd))          ; Zstandard compression

    (home-page "https://openzfs.org/")
    (synopsis "OpenZFS userspace tools for ANDYL OS")
    (description
     "OpenZFS userspace tools for managing ZFS pools and datasets:
zpool (pool management), zfs (dataset management), zdb (debugger),
zed (event daemon), and mount.zfs (mount helper).  These tools manage
the mutable data pool created by Ignition at first boot, providing
features like snapshots, compression, checksumming, and native
encryption.")
    (license license:cddl1.0)))


;;; =========================================================================
;;; ZFS Auto-Snapshot -- automatic periodic snapshot management
;;; =========================================================================
;;;
;;; zfs-auto-snapshot is a simple shell script that creates and rotates
;;; ZFS snapshots on a configurable schedule.  It is typically run from
;;; systemd timers to provide:
;;;
;;;   - Frequent snapshots (every 15 minutes, keep 4)
;;;   - Hourly snapshots (keep 24)
;;;   - Daily snapshots (keep 31)
;;;   - Weekly snapshots (keep 8)
;;;   - Monthly snapshots (keep 12)
;;;
;;; This provides a lightweight backup mechanism for mutable data under
;;; /var without requiring external backup infrastructure.

(define-public andyl-zfs-auto-snapshot
  (package
    (name "andyl-zfs-auto-snapshot")
    (version (config-version "storage" "zfs-auto-snapshot"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/zfsonlinux/zfs-auto-snapshot"
                    "/archive/upstream/" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/zfsonlinux/zfs-auto-snapshot/archive/upstream/1.2.4.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system trivial-build-system)
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((source (assoc-ref %build-inputs "source"))
                 (out    (assoc-ref %outputs "out"))
                 (bindir (string-append out "/sbin"))
                 (docdir (string-append out "/share/doc/"
                                        #$(package-name this-package))))

            ;; Unpack source
            (invoke "tar" "xf" source)
            (chdir (string-append "zfs-auto-snapshot-upstream-"
                                  #$(package-version this-package)))

            ;; Install the main script
            (mkdir-p bindir)
            (copy-file "src/zfs-auto-snapshot.sh"
                       (string-append bindir "/zfs-auto-snapshot"))
            (chmod (string-append bindir "/zfs-auto-snapshot") #o755)

            ;; Patch the shebang to use our bash
            (substitute* (string-append bindir "/zfs-auto-snapshot")
              (("#!/bin/sh")
               (string-append "#!"
                              (assoc-ref %build-inputs "andyl-bash")
                              "/bin/bash")))

            ;; Install documentation
            (mkdir-p docdir)
            (for-each
             (lambda (f)
               (when (file-exists? f)
                 (install-file f docdir)))
             '("README" "README.md" "LICENSE"))))))

    (inputs
     (list andyl-bash))

    (home-page "https://github.com/zfsonlinux/zfs-auto-snapshot")
    (synopsis "Automatic ZFS snapshot management for ANDYL OS")
    (description
     "zfs-auto-snapshot creates and rotates ZFS snapshots on a
configurable schedule using systemd timers.  Provides frequent (15-min),
hourly, daily, weekly, and monthly snapshot retention policies for
lightweight point-in-time recovery of mutable data under /var.")
    (license license:gpl2+)))
