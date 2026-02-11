;;; ANDYL OS -- dracut Initrd Generator Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the dracut initramfs generator for ANDYL OS.
;;; dracut is used at IMAGE BUILD TIME ONLY -- it is NOT installed on
;;; deployed machines.  It generates a systemd-based initrd that:
;;;
;;;   1. Starts systemd as PID 1 in the initrd
;;;   2. Runs udevd for device enumeration
;;;   3. Mounts the ext4 root filesystem (read-only)
;;;   4. Runs Ignition on first boot (creates ZFS data pool, writes /etc overlay)
;;;   5. Performs switch-root to the real rootfs
;;;
;;; The initrd does NOT include ZFS support -- the root filesystem is ext4.
;;; ZFS modules are loaded after boot by systemd to mount the mutable data
;;; pool (/var, /var/lib, /var/log).
;;;
;;; CPU microcode is handled separately: an early-cpio microcode archive
;;; is prepended to the main initrd (or embedded in a UKI).
;;;
;;; dracut invocation at image build time:
;;;
;;;   dracut --force --kver 6.12.x \
;;;     --add "systemd" \
;;;     --no-hostonly \
;;;     --no-early-microcode \
;;;     /boot/initramfs-6.12.x.img
;;;
;;; See phase-3-kernel-systemd.md sections 3.9-3.10 and
;;; brainstorm/02-kernel-and-system.md section 4.2.

(define-module (andyl packages dracut)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages base)
  #:use-module (andyl packages systemd)
  #:use-module (andyl config))


;;; =========================================================================
;;; dracut -- initramfs infrastructure
;;; =========================================================================
;;;
;;; dracut is a modular initramfs generator.  It assembles an initrd image
;;; from "dracut modules" -- each module contributes scripts, binaries,
;;; and configuration for a specific function (e.g., systemd, udev, network,
;;; dm, lvm, luks, etc.).
;;;
;;; For ANDYL OS, the key dracut modules are:
;;;   - systemd:       systemd as PID 1 in the initrd
;;;   - systemd-udevd: device enumeration
;;;   - base:          core initrd infrastructure
;;;   - fs-lib:        filesystem mounting helpers
;;;
;;; dracut is a BUILD-TIME tool.  It runs on the CI/build machine to produce
;;; the initrd that goes into the golden image.  It is NOT needed at runtime
;;; on deployed machines (the initrd is pre-built and immutable).

(define-public andyl-dracut
  (package
    (name "andyl-dracut")
    (version (config-version "init" "dracut"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/dracut-ng/dracut-ng/releases/download/"
                    version "/dracut-" version ".tar.xz"))
              (sha256
               ;; TODO: guix download https://github.com/dracut-ng/dracut-ng/releases/download/103/dracut-103.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)

    (arguments
     (list
      #:configure-flags
      #~(list
         ;; Install prefix
         (string-append "--prefix=" #$output)

         ;; systemd directory for dracut to find unit files and binaries
         (string-append "--systemdsystemunitdir="
                        #$output "/lib/systemd/system")

         ;; Use bash from our toolchain
         (string-append "--bashdir="
                        #$(this-package-input "andyl-bash") "/bin"))

      #:phases
      #~(modify-phases %standard-phases
          ;; dracut uses a simple Makefile, not autoconf
          (delete 'configure)

          (replace 'build
            (lambda* (#:key inputs #:allow-other-keys)
              ;; dracut is primarily shell scripts and configuration;
              ;; the "build" step compiles dracut-install (a helper
              ;; binary for copying files into the initrd)
              (invoke "make"
                      (string-append "prefix=" #$output)
                      (string-append "systemdsystemunitdir="
                                     #$output "/lib/systemd/system"))))

          (replace 'install
            (lambda* (#:key inputs outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "make" "install"
                        (string-append "prefix=" out)
                        (string-append "systemdsystemunitdir="
                                       out "/lib/systemd/system")
                        (string-append "bashdir="
                                       out "/share/bash-completion/completions"))

                ;; Install ANDYL OS-specific dracut configuration that
                ;; selects the systemd-based initrd profile
                (let ((confdir (string-append out "/etc/dracut.conf.d")))
                  (mkdir-p confdir)
                  (call-with-output-file
                      (string-append confdir "/andyl-os.conf")
                    (lambda (port)
                      (display
                       (string-append
                        "# ANDYL OS dracut configuration\n"
                        "# Generated by andyl-dracut package\n"
                        "#\n"
                        "# Use systemd as PID 1 in the initrd\n"
                        "add_dracutmodules+=\" systemd \"\n"
                        "\n"
                        "# Build a generic initrd (not tailored to build host)\n"
                        "hostonly=\"no\"\n"
                        "\n"
                        "# Do not include early microcode -- it is prepended\n"
                        "# separately or embedded in the UKI\n"
                        "early_microcode=\"no\"\n"
                        "\n"
                        "# Root filesystem is ext4 (ZFS is NOT needed in initrd;\n"
                        "# ZFS modules are loaded after boot for /var data pool)\n"
                        "omit_dracutmodules+=\" zfs btrfs lvm dm \"\n"
                        "\n"
                        "# Compression: zstd for good ratio and fast decompression\n"
                        "compress=\"zstd\"\n")
                       port)))))))

      #:tests? #f))

    (native-inputs (list andyl-gcc andyl-pkg-config))
    (inputs
     (list andyl-glibc
           andyl-bash
           andyl-coreutils
           andyl-kmod
           andyl-systemd))

    (home-page "https://github.com/dracut-ng/dracut-ng")
    (synopsis "dracut initramfs generator for ANDYL OS")
    (description
     "dracut is a modular initramfs generator used at image build time to
create systemd-based initrd images for ANDYL OS.  The generated initrd
uses systemd as PID 1, runs udevd for device enumeration, mounts the
read-only ext4 root filesystem, and supports Ignition for first-boot
provisioning.  ZFS is NOT included in the initrd (root is ext4); ZFS
modules are loaded after boot for the mutable data pool.  CPU microcode
is prepended as a separate early-cpio archive or embedded in a UKI.
This package is a build-time dependency only -- it is not installed on
deployed machines.")
    (license license:gpl2+)))
