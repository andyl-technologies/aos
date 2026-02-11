;;; ANDYL OS -- CNI Plugins Package
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the standard CNI (Container Network Interface)
;;; plugins package for ANDYL OS:
;;;
;;;   andyl-cni-plugins  -- Standard CNI plugin binaries
;;;
;;; ANDYL OS ships these plugins in the base K8s image at /opt/cni/bin/
;;; to provide the foundation that higher-level CNI implementations
;;; (Cilium, Calico, Flannel) build upon.  The base image does NOT
;;; include any CNI configuration -- that is written at runtime by the
;;; deployed CNI plugin.
;;;
;;; Plugins included:
;;;   bridge      -- Create a bridge and add host/container veth pairs
;;;   loopback    -- Set up the loopback interface in containers
;;;   host-local  -- IPAM: allocate IPs from a local range
;;;   portmap     -- Map ports from the host to the container
;;;   firewall    -- Add iptables/nftables rules for container traffic
;;;   tuning      -- Tune sysctl parameters for container interfaces
;;;   bandwidth   -- Rate-limit container traffic
;;;   ptp         -- Point-to-point veth pair for containers
;;;   macvlan     -- Assign MAC addresses to containers
;;;   ipvlan      -- IP-based VLAN for containers
;;;
;;; See:
;;;   RFC-0007 section 3 (Pluggable CNI Architecture)
;;;   Phase 7 section 7.4 (CNI Plugins Package)
;;;
;;; Package dependency graph:
;;;
;;;   andyl-cni-plugins
;;;     +-- go (build-time)
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers

(define-module (andyl packages cni)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system go)
  #:use-module (guix utils)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (andyl packages gcc)
  #:use-module (andyl packages glibc)
  #:use-module (andyl packages linux)
  #:use-module (andyl config))


;;; =========================================================================
;;; CNI Plugins -- standard Container Network Interface plugins
;;; =========================================================================
;;;
;;; The standard CNI plugins provide the basic network plumbing used by
;;; container runtimes and CNI implementations.  These are the "reference"
;;; plugins maintained by the containernetworking project.
;;;
;;; ANDYL OS ships these in the base image at /opt/cni/bin/ to provide
;;; the foundation that higher-level CNI implementations (Cilium, Calico,
;;; Flannel) build upon.  The base image does NOT include any CNI
;;; configuration -- that is written at runtime by the deployed CNI plugin.
;;;
;;; The plugin categories are:
;;;
;;;   Main plugins (create network interfaces):
;;;     bridge, loopback, ptp, macvlan, ipvlan
;;;
;;;   IPAM plugins (allocate IP addresses):
;;;     host-local
;;;
;;;   Meta plugins (augment other plugins):
;;;     portmap, firewall, tuning, bandwidth
;;;
;;; See: RFC-0007 section 3 (Pluggable CNI Architecture)

(define-public andyl-cni-plugins
  (package
    (name "andyl-cni-plugins")
    (version (config-version "kubernetes" "cni-plugins"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/containernetworking/plugins"
                    "/archive/refs/tags/v" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/containernetworking/plugins/archive/refs/tags/v1.6.1.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "github.com/containernetworking/plugins"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          ;; Build the standard CNI plugins needed for K8s
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (with-directory-excursion
                  (string-append "src/" import-path)
                ;; Build individual plugins across all categories
                (for-each
                 (lambda (plugin)
                   (invoke "go" "build"
                           "-trimpath"
                           "-o" (string-append "bin/"
                                               (basename plugin))
                           (string-append "./plugins/" plugin)))
                 ;; Main plugins: create network interfaces
                 '("main/bridge"
                   "main/loopback"
                   "main/ptp"
                   "main/macvlan"
                   "main/ipvlan"
                   ;; IPAM plugins: allocate IP addresses
                   "ipam/host-local"
                   ;; Meta plugins: augment other plugins
                   "meta/portmap"
                   "meta/firewall"
                   "meta/tuning"
                   "meta/bandwidth")))))

          (replace 'install
            (lambda* (#:key import-path outputs #:allow-other-keys)
              (let ((cnidir (string-append (assoc-ref outputs "out")
                                           "/opt/cni/bin")))
                (with-directory-excursion
                    (string-append "src/" import-path)
                  (mkdir-p cnidir)
                  (for-each
                   (lambda (plugin)
                     (let ((src (string-append "bin/" plugin)))
                       (when (file-exists? src)
                         (install-file src cnidir))))
                   '("bridge" "loopback" "ptp" "macvlan" "ipvlan"
                     "host-local"
                     "portmap" "firewall" "tuning" "bandwidth"))))))

          (delete 'check))))

    (native-inputs
     (list andyl-gcc
           andyl-pkg-config))

    (inputs
     (list andyl-glibc
           andyl-linux-headers))

    (home-page "https://github.com/containernetworking/plugins")
    (synopsis "Standard CNI plugins for ANDYL OS Kubernetes nodes")
    (description
     "Standard CNI (Container Network Interface) plugin binaries providing
basic network plumbing for containers.  Includes main plugins (bridge,
loopback, ptp, macvlan, ipvlan), IPAM plugins (host-local), and meta
plugins (portmap, firewall, tuning, bandwidth).  Installed to
/opt/cni/bin/ in the ANDYL OS K8s image.  Higher-level CNI
implementations (Cilium, Calico, Flannel) are deployed at runtime via
Helm and build upon these standard plugins.")
    (license license:asl2.0)))
