;;; ANDYL OS -- Container Runtime Packages (containerd, runc)
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the container runtime packages for ANDYL OS:
;;;
;;;   andyl-containerd  -- Container runtime (CRI implementation)
;;;   andyl-runc        -- OCI container runtime
;;;
;;; containerd provides the Container Runtime Interface (CRI) that kubelet
;;; uses to manage container lifecycles.  runc is the OCI runtime that
;;; actually creates and runs containers using Linux kernel features
;;; (namespaces, cgroups, seccomp).
;;;
;;; Both packages are built with the Go build system.  Binary hashes are
;;; placeholders until first build.
;;;
;;; See:
;;;   RFC-0007 section 2 (Container Runtime Interface)
;;;   Phase 7 sections 7.1, 7.2 (containerd Package, runc Package)
;;;
;;; Package dependency graph:
;;;
;;;   andyl-containerd
;;;     +-- go (build-time)
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;
;;;   andyl-runc
;;;     +-- go (build-time)
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;     +-- andyl-libseccomp (seccomp filtering)

(define-module (andyl packages containerd)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system go)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages linux)
  #:use-module (andyl packages selinux)
  #:use-module (andyl config))


;;; =========================================================================
;;; containerd -- container runtime (CRI implementation)
;;; =========================================================================
;;;
;;; containerd provides the Container Runtime Interface (CRI) that kubelet
;;; uses to manage container lifecycles.  It handles image pulling, container
;;; creation/destruction, and snapshot management.
;;;
;;; Key binaries:
;;;   containerd                -- Main daemon
;;;   containerd-shim-runc-v2   -- Shim process for container isolation
;;;   ctr                       -- Low-level containerd CLI (debugging)
;;;
;;; containerd communicates with kubelet via a gRPC socket at
;;; /run/containerd/containerd.sock and delegates container execution
;;; to runc via the containerd-shim.
;;;
;;; See: RFC-0007 section 2 (Container Runtime Interface)

(define-public andyl-containerd
  (package
    (name "andyl-containerd")
    (version (config-version "kubernetes" "containerd"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/containerd/containerd/archive/refs/tags/v"
                    version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/containerd/containerd/archive/refs/tags/v1.7.24.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "github.com/containerd/containerd"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          ;; containerd uses a Makefile rather than standard go build
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (with-directory-excursion
                  (string-append "src/" import-path)
                (invoke "make" "binaries"
                        (string-append "DESTDIR=" (assoc-ref %outputs "out"))
                        "GO_BUILD_FLAGS=-trimpath"))))

          (replace 'install
            (lambda* (#:key import-path outputs #:allow-other-keys)
              (let ((bindir (string-append (assoc-ref outputs "out") "/bin")))
                (with-directory-excursion
                    (string-append "src/" import-path)
                  (mkdir-p bindir)
                  (for-each
                   (lambda (binary)
                     (let ((src (string-append "bin/" binary)))
                       (when (file-exists? src)
                         (install-file src bindir))))
                   '("containerd"
                     "containerd-shim-runc-v2"
                     "ctr"))))))

          ;; Skip check phase (requires running containerd daemon)
          (delete 'check))))

    (native-inputs
     (list andyl-gcc
           andyl-pkg-config))

    (inputs
     (list andyl-glibc
           andyl-linux-headers))

    (home-page "https://containerd.io/")
    (synopsis "Container runtime for ANDYL OS Kubernetes nodes")
    (description
     "containerd is an industry-standard container runtime providing the
Container Runtime Interface (CRI) for Kubernetes.  It manages the complete
container lifecycle: image transfer and storage, container execution and
supervision, snapshot management, and low-level storage.  On ANDYL OS,
containerd serves as the CRI backend for kubelet and uses runc as the
OCI runtime.  Configured with systemd cgroup driver and ZFS or overlayfs
snapshotter depending on the storage layout.")
    (license license:asl2.0)))


;;; =========================================================================
;;; runc -- OCI container runtime
;;; =========================================================================
;;;
;;; runc is the reference implementation of the OCI (Open Container
;;; Initiative) runtime specification.  It creates and runs containers
;;; using Linux namespaces, cgroups, seccomp, and other kernel features.
;;;
;;; runc is invoked by the containerd-shim to create individual container
;;; processes.  It is never called directly by kubelet.
;;;
;;; Security features:
;;;   - Namespace isolation (PID, NET, MNT, UTS, IPC, USER)
;;;   - cgroup v2 resource limits
;;;   - seccomp syscall filtering
;;;   - SELinux process labeling
;;;   - AppArmor profiles (not used on ANDYL OS; SELinux is used instead)
;;;
;;; See: RFC-0007 section 2 (Container Runtime Interface)

(define-public andyl-runc
  (package
    (name "andyl-runc")
    (version (config-version "kubernetes" "runc"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/opencontainers/runc/archive/refs/tags/v"
                    version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/opencontainers/runc/archive/refs/tags/v1.2.4.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "github.com/opencontainers/runc"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          ;; runc uses a Makefile for building
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (with-directory-excursion
                  (string-append "src/" import-path)
                ;; Build with seccomp support for syscall filtering
                (invoke "make" "runc"
                        "BUILDTAGS=seccomp"
                        "GO_BUILD_FLAGS=-trimpath"))))

          (replace 'install
            (lambda* (#:key import-path outputs #:allow-other-keys)
              (let ((bindir (string-append (assoc-ref outputs "out") "/sbin")))
                (with-directory-excursion
                    (string-append "src/" import-path)
                  (mkdir-p bindir)
                  (install-file "runc" bindir)))))

          (delete 'check))))

    (native-inputs
     (list andyl-gcc
           andyl-pkg-config))

    (inputs
     (list andyl-glibc
           andyl-linux-headers
           andyl-libseccomp))          ; seccomp syscall filtering

    (home-page "https://github.com/opencontainers/runc")
    (synopsis "OCI container runtime for ANDYL OS")
    (description
     "runc is the reference OCI (Open Container Initiative) runtime that
creates and runs containers using Linux kernel features: namespaces for
isolation, cgroups v2 for resource limits, seccomp for syscall filtering,
and SELinux for mandatory access control.  On ANDYL OS, runc is invoked
by the containerd-shim to create individual container processes.  Built
with seccomp support for defense-in-depth.")
    (license license:asl2.0)))
