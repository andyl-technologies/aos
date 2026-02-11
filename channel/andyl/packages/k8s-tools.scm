;;; ANDYL OS -- Kubernetes Supporting Tools
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines supporting tool packages required by Kubernetes
;;; nodes on ANDYL OS:
;;;
;;;   andyl-ethtool          -- NIC configuration and diagnostics
;;;   andyl-socat            -- Port forwarding support (kubectl port-forward)
;;;   andyl-conntrack-tools  -- Connection tracking utilities
;;;   andyl-ipvsadm          -- IPVS management (for kube-proxy IPVS mode)
;;;   andyl-nerdctl          -- containerd-native Docker-compatible CLI
;;;   andyl-helm             -- Kubernetes package manager
;;;
;;; These tools complement the core Kubernetes packages (kubelet, kubectl,
;;; kubeadm) and container runtime (containerd, runc) to provide a
;;; fully functional Kubernetes node.
;;;
;;; See:
;;;   RFC-0007 section 1 (Role-Based Package Sets)
;;;   Phase 7 section 7.5 (Supporting Tools)
;;;
;;; Package dependency graph:
;;;
;;;   andyl-ethtool
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;
;;;   andyl-socat
;;;     +-- andyl-glibc
;;;     +-- andyl-openssl
;;;
;;;   andyl-conntrack-tools
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;     +-- andyl-libmnl
;;;     +-- andyl-libnftnl
;;;
;;;   andyl-ipvsadm
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;
;;;   andyl-nerdctl
;;;     +-- go (build-time)
;;;     +-- andyl-glibc
;;;
;;;   andyl-helm
;;;     +-- go (build-time)
;;;     +-- andyl-glibc

(define-module (andyl packages k8s-tools)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system go)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages linux)
  #:use-module (andyl packages base)
  #:use-module (andyl packages tls)
  #:use-module (andyl packages networking)
  #:use-module (andyl config))


;;; =========================================================================
;;; ethtool -- NIC configuration and diagnostics
;;; =========================================================================
;;;
;;; ethtool provides commands for querying and configuring network
;;; interface hardware settings: link speed, duplex mode, ring buffers,
;;; offload features, and driver info.
;;;
;;; Required by Kubernetes for:
;;;   - CNI plugins that inspect NIC capabilities
;;;   - Network troubleshooting on nodes
;;;   - Cilium eBPF XDP mode (checks NIC driver support)

(define-public andyl-ethtool
  (package
    (name "andyl-ethtool")
    (version (config-version "kubernetes" "ethtool"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://cdn.kernel.org/pub/software/network/ethtool/"
                    "ethtool-" version ".tar.xz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://cdn.kernel.org/pub/software/network/ethtool/ethtool-6.11.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc
           andyl-pkg-config))
    (inputs
     (list andyl-glibc
           andyl-linux-headers
           andyl-libmnl))             ; netlink communication
    (arguments
     (list
      #:tests? #f))
    (home-page "https://www.kernel.org/pub/software/network/ethtool/")
    (synopsis "NIC configuration and diagnostics for ANDYL OS")
    (description
     "ethtool queries and configures network interface hardware settings
including link speed, duplex mode, ring buffers, offload features, and
driver information.  Required by Kubernetes CNI plugins for NIC
capability inspection and by Cilium for XDP mode detection.")
    (license license:gpl2)))


;;; =========================================================================
;;; socat -- multipurpose relay for bidirectional data transfer
;;; =========================================================================
;;;
;;; socat (SOcket CAT) establishes two bidirectional byte streams and
;;; transfers data between them.  It is required by Kubernetes for:
;;;
;;;   - `kubectl port-forward` (kubelet uses socat internally to set up
;;;     port forwarding between the host and container network namespaces)
;;;
;;; Without socat, `kubectl port-forward` will fail with an error.

(define-public andyl-socat
  (package
    (name "andyl-socat")
    (version (config-version "kubernetes" "socat"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "http://www.dest-unreach.org/socat/download/"
                    "socat-" version ".tar.bz2"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download http://www.dest-unreach.org/socat/download/socat-1.8.0.1.tar.bz2
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc))
    (inputs
     (list andyl-glibc
           andyl-openssl))            ; TLS support for socat
    (arguments
     (list
      #:tests? #f))
    (home-page "http://www.dest-unreach.org/socat/")
    (synopsis "Multipurpose relay for ANDYL OS")
    (description
     "socat (SOcket CAT) establishes two bidirectional byte streams and
transfers data between them.  Supports TCP, UDP, Unix sockets, TLS,
and many other address types.  Required by Kubernetes for kubectl
port-forward functionality.")
    (license license:gpl2)))


;;; =========================================================================
;;; conntrack-tools -- connection tracking utilities
;;; =========================================================================
;;;
;;; conntrack-tools provides userspace utilities for interacting with
;;; the Linux kernel connection tracking system (nf_conntrack).
;;;
;;; Required by Kubernetes for:
;;;   - kube-proxy connection tracking table management
;;;   - CNI plugins that manage NAT entries
;;;   - Debugging network connectivity issues between pods and services
;;;
;;; Key commands:
;;;   conntrack  -- Query and manage the conntrack table
;;;   conntrackd -- Connection tracking synchronization daemon (HA)

(define-public andyl-conntrack-tools
  (package
    (name "andyl-conntrack-tools")
    (version (config-version "kubernetes" "conntrack-tools"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://www.netfilter.org/projects/conntrack-tools/files/"
                    "conntrack-tools-" version ".tar.xz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-1.4.8.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc
           andyl-pkg-config
           andyl-bison))
    (inputs
     (list andyl-glibc
           andyl-linux-headers
           andyl-libmnl              ; netlink communication
           andyl-libnftnl))          ; netfilter library
    (arguments
     (list
      #:tests? #f))
    (home-page "https://www.netfilter.org/projects/conntrack-tools/")
    (synopsis "Connection tracking utilities for ANDYL OS")
    (description
     "conntrack-tools provides userspace utilities for managing the Linux
kernel connection tracking table (nf_conntrack).  Includes conntrack
for querying and manipulating connection entries and conntrackd for
connection state synchronization in HA setups.  Required by Kubernetes
kube-proxy and CNI plugins for NAT and connection state management.")
    (license license:gpl2+)))


;;; =========================================================================
;;; ipvsadm -- IPVS management tool
;;; =========================================================================
;;;
;;; ipvsadm manages the Linux IP Virtual Server (IPVS) load balancing
;;; table in the kernel.  It is required by Kubernetes when kube-proxy
;;; runs in IPVS mode.
;;;
;;; IPVS mode provides better performance than iptables mode for service
;;; load balancing:
;;;   - O(1) lookup for service-to-endpoint mapping (vs O(N) for iptables)
;;;   - Support for multiple scheduling algorithms (rr, wrr, lc, wlc, sh)
;;;   - Better scalability for large numbers of services
;;;
;;; Even when using Cilium (which replaces kube-proxy), ipvsadm is useful
;;; for debugging and verifying IPVS state.

(define-public andyl-ipvsadm
  (package
    (name "andyl-ipvsadm")
    (version (config-version "kubernetes" "ipvsadm"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://cdn.kernel.org/pub/linux/utils/kernel/ipvsadm/"
                    "ipvsadm-" version ".tar.xz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://cdn.kernel.org/pub/linux/utils/kernel/ipvsadm/ipvsadm-1.31.tar.xz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system gnu-build-system)
    (native-inputs
     (list andyl-gcc
           andyl-pkg-config))
    (inputs
     (list andyl-glibc
           andyl-linux-headers
           andyl-libnftnl))          ; netfilter library
    (arguments
     (list
      ;; ipvsadm uses a simple Makefile, not autoconf
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)
          (replace 'build
            (lambda* (#:key outputs #:allow-other-keys)
              (invoke "make"
                      (string-append "SBIN=" (assoc-ref outputs "out") "/sbin")
                      (string-append "MAN=" (assoc-ref outputs "out") "/share/man"))))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((sbin (string-append (assoc-ref outputs "out") "/sbin")))
                (mkdir-p sbin)
                (install-file "ipvsadm" sbin)))))
      #:tests? #f))
    (home-page "https://www.linuxvirtualserver.org/software/ipvs.html")
    (synopsis "IPVS management tool for ANDYL OS")
    (description
     "ipvsadm manages the Linux IP Virtual Server (IPVS) kernel load
balancing table.  Used by Kubernetes kube-proxy in IPVS mode for
service-to-endpoint load balancing with O(1) lookup performance.
Supports round-robin, weighted round-robin, least connections, and
source hashing scheduling algorithms.")
    (license license:gpl2)))


;;; =========================================================================
;;; nerdctl -- containerd-native Docker-compatible CLI
;;; =========================================================================
;;;
;;; nerdctl is a Docker-compatible CLI for containerd.  It provides a
;;; familiar interface for operators who are accustomed to Docker commands
;;; but want to work directly with containerd.
;;;
;;; Common commands:
;;;   nerdctl run      -- Run a container
;;;   nerdctl images   -- List images
;;;   nerdctl pull     -- Pull an image
;;;   nerdctl build    -- Build a container image (with BuildKit)
;;;   nerdctl logs     -- View container logs
;;;
;;; On ANDYL OS, nerdctl is included for debugging and ad-hoc container
;;; operations.  Production workloads run through kubelet/containerd CRI.

(define-public andyl-nerdctl
  (package
    (name "andyl-nerdctl")
    (version (config-version "kubernetes" "nerdctl"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/containerd/nerdctl/archive/refs/tags/v"
                    version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/containerd/nerdctl/archive/refs/tags/v1.7.7.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "github.com/containerd/nerdctl"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (with-directory-excursion
                  (string-append "src/" import-path)
                (invoke "go" "build"
                        "-trimpath"
                        "-o" "bin/nerdctl"
                        "./cmd/nerdctl"))))

          (replace 'install
            (lambda* (#:key import-path outputs #:allow-other-keys)
              (let ((bindir (string-append (assoc-ref outputs "out") "/bin")))
                (with-directory-excursion
                    (string-append "src/" import-path)
                  (mkdir-p bindir)
                  (install-file "bin/nerdctl" bindir)))))

          (delete 'check))))

    (native-inputs
     (list andyl-gcc))

    (inputs
     (list andyl-glibc))

    (home-page "https://github.com/containerd/nerdctl")
    (synopsis "Docker-compatible CLI for containerd on ANDYL OS")
    (description
     "nerdctl is a Docker-compatible CLI for containerd, providing familiar
commands (run, images, pull, build, logs) for operators accustomed to
Docker.  On ANDYL OS, nerdctl is included for debugging and ad-hoc
container operations.  Production workloads run through the kubelet
and containerd CRI interface.")
    (license license:asl2.0)))


;;; =========================================================================
;;; Helm -- Kubernetes package manager
;;; =========================================================================
;;;
;;; Helm is the package manager for Kubernetes, managing application
;;; deployments as "charts" (versioned bundles of Kubernetes manifests
;;; with templated values).
;;;
;;; On ANDYL OS, Helm is the primary mechanism for deploying runtime
;;; plugins that are NOT baked into the golden image:
;;;
;;;   - CNI plugins (Cilium, Calico, Flannel)
;;;   - CSI drivers (Rook-Ceph, OpenEBS, Longhorn)
;;;   - Device plugins (NVIDIA GPU, Intel FPGA)
;;;   - Monitoring stacks (Prometheus, Grafana)
;;;   - Ingress controllers (Nginx, Envoy)
;;;
;;; See: RFC-0007 section 3 (Pluggable CNI Architecture)

(define-public andyl-helm
  (package
    (name "andyl-helm")
    (version (config-version "kubernetes" "helm"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/helm/helm/archive/refs/tags/v"
                    version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/helm/helm/archive/refs/tags/v3.16.4.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "helm.sh/helm/v3"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (with-directory-excursion
                  (string-append "src/" import-path)
                (invoke "make" "build"
                        "GO_BUILD_FLAGS=-trimpath"))))

          (replace 'install
            (lambda* (#:key import-path outputs #:allow-other-keys)
              (let ((bindir (string-append (assoc-ref outputs "out") "/bin")))
                (with-directory-excursion
                    (string-append "src/" import-path)
                  (mkdir-p bindir)
                  (install-file "bin/helm" bindir)))))

          (delete 'check))))

    (native-inputs
     (list andyl-gcc))

    (inputs
     (list andyl-glibc))

    (home-page "https://helm.sh/")
    (synopsis "Kubernetes package manager for ANDYL OS")
    (description
     "Helm is the package manager for Kubernetes, deploying applications
as versioned charts (bundles of templated Kubernetes manifests).  On
ANDYL OS, Helm is the primary mechanism for deploying runtime plugins:
CNI implementations (Cilium, Calico), CSI drivers, device plugins,
monitoring stacks, and ingress controllers.  This decouples plugin
lifecycle from OS image lifecycle, allowing plugin upgrades without
rebuilding the golden image.")
    (license license:asl2.0)))
