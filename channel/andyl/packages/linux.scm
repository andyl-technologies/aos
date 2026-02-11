;;; ANDYL OS -- Linux Kernel Headers Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the Linux kernel headers package.  Kernel headers
;;; provide the user-space API for system calls, ioctl constants, and
;;; kernel data structures.  They are required by glibc at build time.
;;;
;;; We use the 6.12.x LTS kernel series for its longer support runway
;;; and modern features (improved eBPF, io_uring, cgroup v2).
;;;
;;; Note: This module defines ONLY the kernel headers (the user-space API).
;;; The full kernel build (vmlinuz, modules) is a separate concern handled
;;; in a later phase.

(define-module (andyl packages linux)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl config))

;;;
;;; Linux Kernel Headers (6.12.x LTS)
;;;
;;; glibc needs these headers at build time for syscall numbers, data
;;; structure definitions, and ioctl constants.  The headers are "sanitized"
;;; by the kernel build system to expose only the stable user-space API.
;;;
;;; The headers are also a propagated input of glibc, meaning any package
;;; that depends on glibc automatically gets access to kernel headers.
;;;

(define-public andyl-linux-headers
  (package
    (name "andyl-linux-headers")
    (version (config-version "toolchain" "linux-headers"))
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
    (native-inputs
     (list andyl-gcc))
    (arguments
     (list
      #:phases
      #~(modify-phases %standard-phases
          ;; No configure step for kernel headers
          (replace 'configure
            (lambda _ #t))

          ;; "make headers" extracts the sanitized user-space API headers
          (replace 'build
            (lambda _
              ;; Determine the kernel ARCH from the build system.
              ;; x86_64 -> "x86", aarch64 -> "arm64"
              (let ((arch (match (or (getenv "TARGET_ARCH")
                                    (%current-system))
                           ((? (lambda (s)
                                 (string-contains s "x86_64"))
                               _) "x86")
                           ((? (lambda (s)
                                 (string-contains s "aarch64"))
                               _) "arm64")
                           (_ "x86"))))
                (invoke "make"
                        (string-append "ARCH=" arch)
                        "headers"))))

          ;; Install sanitized headers to output
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out (assoc-ref outputs "out"))
                     (arch (match (or (getenv "TARGET_ARCH")
                                     (%current-system))
                             ((? (lambda (s)
                                   (string-contains s "x86_64"))
                                 _) "x86")
                             ((? (lambda (s)
                                   (string-contains s "aarch64"))
                                 _) "arm64")
                             (_ "x86"))))
                ;; Install headers to $out/include
                (invoke "make" "headers_install"
                        (string-append "INSTALL_HDR_PATH=" out)
                        (string-append "ARCH=" arch))

                ;; Remove .install marker files left by headers_install.
                ;; These are not needed and would pollute the output.
                (for-each delete-file
                          (find-files (string-append out "/include")
                                     "\\.install$"))))))

      ;; No tests for kernel headers
      #:tests? #f))
    (home-page "https://kernel.org/")
    (synopsis "Linux kernel headers (user-space API) for ANDYL OS")
    (description
     "Sanitized Linux 6.12.x LTS kernel headers providing the stable
user-space API for system calls, ioctl constants, and kernel data
structures.  Required by glibc at build time and propagated to all
packages that link against glibc.")
    (license license:gpl2)))
