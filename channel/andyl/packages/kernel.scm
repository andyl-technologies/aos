;;; ANDYL OS -- Custom Linux Kernel Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the Linux kernel package for ANDYL OS, built from
;;; vanilla kernel.org sources (NOT linux-libre) because we require firmware
;;; loading support for server hardware.
;;;
;;; The kernel uses a defconfig + fragment overlay strategy: start from the
;;; x86_64 defconfig and merge modular config fragments from the
;;; kernel-config/ directory.  Each fragment covers one concern (base,
;;; storage, networking, virtualization, security, drivers).
;;;
;;; Config fragments are in channel/andyl/packages/kernel-config/:
;;;   base.config              -- Cgroups v2, namespaces, overlayfs, block layer, EFI
;;;   storage.config           -- ZFS prereqs, NVMe, AHCI, crypto modules
;;;   networking.config        -- eBPF, netfilter, bridging, tracing
;;;   virtualization.config    -- KVM, vhost, IOMMU, VFIO, huge pages
;;;   security.config          -- SELinux, audit, IMA/EVM, seccomp, lockdown
;;;   drivers-vm.config        -- Virtio drivers
;;;   drivers-cloud.config     -- AWS/GCP/Azure drivers
;;;   drivers-baremetal.config -- Server NIC and storage controller drivers

(define-module (andyl packages kernel)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix utils)
  #:use-module (guix gexp)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages linux)
  #:use-module (andyl config))

;;;
;;; Kernel config fragments
;;;
;;; Each fragment is a separate file in kernel-config/.  They are merged
;;; in order during the configure phase using the kernel's own
;;; scripts/kconfig/merge_config.sh tool.
;;;

(define %andyl-kernel-config-fragments
  (list
   (local-file "kernel-config/base.config")
   (local-file "kernel-config/storage.config")
   (local-file "kernel-config/networking.config")
   (local-file "kernel-config/virtualization.config")
   (local-file "kernel-config/security.config")
   (local-file "kernel-config/drivers-vm.config")
   (local-file "kernel-config/drivers-cloud.config")
   (local-file "kernel-config/drivers-baremetal.config")))

;;;
;;; Linux Kernel 6.12.x LTS
;;;
;;; The configure phase starts from defconfig, then merges all config
;;; fragments, then runs olddefconfig to resolve dependencies.
;;;
;;; The build produces: bzImage, modules, and headers for out-of-tree
;;; module builds (ZFS).  Module.symvers and .config are preserved in
;;; the build directory so ZFS can build against this kernel.
;;;

(define-public andyl-kernel
  (package
    (name "andyl-kernel")
    (version (config-version "kernel" "linux"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-"
                    version ".tar.xz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.11.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (arguments
     (list
      #:tests? #f

      #:phases
      #~(modify-phases %standard-phases

          ;; Replace configure with defconfig + fragment merge.
          ;; 1. Start from x86_64 defconfig
          ;; 2. Merge each config fragment in order
          ;; 3. Run olddefconfig to resolve dependencies
          (replace 'configure
            (lambda* (#:key inputs #:allow-other-keys)
              ;; Start with the default x86_64 config
              (invoke "make" "ARCH=x86" "defconfig")

              ;; Merge each config fragment using the kernel's merge tool
              (for-each
               (lambda (fragment)
                 (invoke "scripts/kconfig/merge_config.sh"
                         "-m" ".config" fragment))
               '(#$@%andyl-kernel-config-fragments))

              ;; Resolve any dependency conflicts from the merge
              (invoke "make" "ARCH=x86" "olddefconfig")))

          ;; Build bzImage and kernel modules
          (replace 'build
            (lambda _
              (invoke "make" "ARCH=x86"
                      (string-append
                       "-j" (number->string (parallel-job-count)))
                      "bzImage" "modules")))

          ;; Install kernel image, System.map, modules, and preserve
          ;; build artifacts for out-of-tree module builds (ZFS)
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out     (assoc-ref outputs "out"))
                     (bootdir (string-append out "/boot"))
                     (version #$(package-version this-package)))

                ;; Install bzImage
                (mkdir-p bootdir)
                (install-file "arch/x86/boot/bzImage" bootdir)
                (rename-file (string-append bootdir "/bzImage")
                             (string-append bootdir "/vmlinuz-" version))

                ;; Install System.map
                (install-file "System.map" bootdir)
                (rename-file (string-append bootdir "/System.map")
                             (string-append bootdir "/System.map-" version))

                ;; Install kernel modules
                (invoke "make" "modules_install"
                        (string-append "INSTALL_MOD_PATH=" out))

                ;; Install headers for out-of-tree module builds
                (invoke "make" "headers_install"
                        (string-append "INSTALL_HDR_PATH=" out "/usr"))

                ;; Preserve Module.symvers and .config for out-of-tree
                ;; builds (ZFS needs these to build kernel modules)
                (let ((builddir (string-append out "/lib/modules/"
                                               version "/build")))
                  (mkdir-p builddir)
                  (for-each
                   (lambda (file)
                     (when (file-exists? file)
                       (install-file file builddir)))
                   '("Module.symvers"
                     ".config"
                     "Makefile"
                     "scripts/basic/fixdep")))))))))

    (native-inputs
     (list andyl-gcc
           ;; Additional native inputs needed for the kernel build.
           ;; TODO: Add these packages once defined in the ANDYL channel:
           ;;   andyl-perl andyl-flex andyl-bison andyl-elfutils
           ;;   andyl-bc andyl-openssl andyl-kmod
           ))

    (home-page "https://kernel.org/")
    (synopsis "ANDYL OS custom Linux kernel (6.12 LTS, server-optimized)")
    (description
     "Custom Linux kernel built from vanilla kernel.org sources with
server-optimized configuration fragments.  Includes cgroups v2 with all
controllers, all namespace types, SELinux as default LSM, OverlayFS with
full extensions, EFI stub for systemd-boot/UKI, virtio drivers (built-in
for cloud/VM boot), full eBPF stack with BTF, KVM virtualization, and
ZFS prerequisites.  Drivers for AWS, GCP, Azure, and bare metal server
hardware are included as modules.

This is NOT linux-libre; firmware loading support is required for server
hardware.  Config fragments are maintained as separate files for
reviewability and composability.")
    (license license:gpl2)))
