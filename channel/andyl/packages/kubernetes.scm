;;; ANDYL OS -- Kubernetes Core Packages
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the core Kubernetes packages for ANDYL OS:
;;;
;;;   andyl-kubelet  -- Kubernetes node agent
;;;   andyl-kubeadm  -- Cluster bootstrapping tool
;;;   andyl-kubectl  -- Kubernetes CLI tool
;;;   andyl-crictl   -- CRI debugging and inspection tool
;;;
;;; All packages are built with the Go build system from the Kubernetes
;;; and cri-tools GitHub repositories.  Binary hashes are placeholders
;;; until first build.
;;;
;;; kubelet, kubeadm, and kubectl share a release version to ensure
;;; compatibility.  The version skew policy requires all node components
;;; to be within one minor version of the API server.
;;;
;;; See:
;;;   RFC-0007 (Kubernetes Production Support)
;;;   Phase 7 section 7.3 (Kubernetes Packages)
;;;
;;; Package dependency graph:
;;;
;;;   andyl-kubelet, andyl-kubeadm, andyl-kubectl
;;;     +-- go (build-time)
;;;     +-- andyl-glibc
;;;     +-- andyl-linux-headers
;;;
;;;   andyl-crictl
;;;     +-- go (build-time)
;;;     +-- andyl-glibc

(define-module (andyl packages kubernetes)
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
;;; Kubernetes version
;;;
;;; Kubernetes components (kubelet, kubeadm, kubectl) each pull their
;;; version from config/versions.toml via config-version.  The version
;;; skew policy requires all node components to be within one minor
;;; version of the API server.
;;; =========================================================================


;;; =========================================================================
;;; kubelet -- Kubernetes node agent
;;; =========================================================================
;;;
;;; kubelet is the primary Kubernetes node agent.  It watches the API server
;;; for pod assignments to its node and ensures the desired containers are
;;; running via the CRI (containerd).
;;;
;;; On ANDYL OS, kubelet is configured with:
;;;   - containerRuntimeEndpoint: unix:///run/containerd/containerd.sock
;;;   - cgroupDriver: systemd
;;;   - root-dir: /var/lib/kubelet (mutable storage)
;;;   - protectKernelDefaults: true (verify sysctl settings)
;;;
;;; kubelet configuration is delivered via Ignition to
;;; /var/lib/kubelet/config.yaml and is NOT baked into the golden image.
;;;
;;; See: RFC-0007 section 4 (Kubelet on an Immutable OS)

(define-public andyl-kubelet
  (package
    (name "andyl-kubelet")
    (version (config-version "kubernetes" "kubelet"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/kubernetes/kubernetes"
                    "/archive/refs/tags/v" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/kubernetes/kubernetes/archive/refs/tags/v1.31.4.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "k8s.io/kubernetes"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (with-directory-excursion
                  (string-append "src/" import-path)
                (invoke "make" "WHAT=cmd/kubelet"
                        "GOFLAGS=-trimpath"))))

          (replace 'install
            (lambda* (#:key import-path outputs #:allow-other-keys)
              (let ((bindir (string-append (assoc-ref outputs "out") "/bin")))
                (with-directory-excursion
                    (string-append "src/" import-path)
                  (mkdir-p bindir)
                  (install-file "_output/bin/kubelet" bindir)))))

          (delete 'check))))

    (native-inputs
     (list andyl-gcc))

    (inputs
     (list andyl-glibc
           andyl-linux-headers))

    (home-page "https://kubernetes.io/")
    (synopsis "Kubernetes node agent for ANDYL OS")
    (description
     "kubelet is the Kubernetes node agent that ensures containers described
in PodSpecs are running and healthy.  On ANDYL OS, kubelet uses containerd
as the CRI runtime, systemd as the cgroup driver, and stores all mutable
state under /var/lib/kubelet.  Configuration is delivered per-machine via
Ignition, enabling identical golden images with per-node identity.")
    (license license:asl2.0)))


;;; =========================================================================
;;; kubeadm -- cluster bootstrapping tool
;;; =========================================================================
;;;
;;; kubeadm bootstraps a Kubernetes cluster by generating certificates,
;;; creating static pod manifests for control plane components, and
;;; configuring kubelet.
;;;
;;; On ANDYL OS:
;;;   - kubeadm is included in control plane image variants
;;;   - `kubeadm init` generates certs and static pod manifests
;;;   - `kubeadm join` adds worker nodes to the cluster
;;;   - Static pod manifests are written to /etc/kubernetes/manifests
;;;     (on the /etc overlay, writable)
;;;
;;; See: RFC-0007 section 5 (Static Pods for Control Plane)

(define-public andyl-kubeadm
  (package
    (name "andyl-kubeadm")
    (version (config-version "kubernetes" "kubeadm"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/kubernetes/kubernetes"
                    "/archive/refs/tags/v" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/kubernetes/kubernetes/archive/refs/tags/v1.31.4.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "k8s.io/kubernetes"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (with-directory-excursion
                  (string-append "src/" import-path)
                (invoke "make" "WHAT=cmd/kubeadm"
                        "GOFLAGS=-trimpath"))))

          (replace 'install
            (lambda* (#:key import-path outputs #:allow-other-keys)
              (let ((bindir (string-append (assoc-ref outputs "out") "/bin")))
                (with-directory-excursion
                    (string-append "src/" import-path)
                  (mkdir-p bindir)
                  (install-file "_output/bin/kubeadm" bindir)))))

          (delete 'check))))

    (native-inputs
     (list andyl-gcc))

    (inputs
     (list andyl-glibc
           andyl-linux-headers))

    (home-page "https://kubernetes.io/docs/reference/setup-tools/kubeadm/")
    (synopsis "Kubernetes cluster bootstrapping tool for ANDYL OS")
    (description
     "kubeadm bootstraps Kubernetes clusters by generating TLS certificates,
creating static pod manifests for control plane components (API server,
scheduler, controller manager, etcd), and configuring kubelet.  On ANDYL
OS, kubeadm writes static pod manifests to /etc/kubernetes/manifests on
the /etc overlay.  Used for initial cluster creation and worker node
joining.")
    (license license:asl2.0)))


;;; =========================================================================
;;; kubectl -- Kubernetes CLI tool
;;; =========================================================================
;;;
;;; kubectl is the command-line tool for interacting with Kubernetes
;;; clusters.  It is included on ANDYL OS nodes for on-node debugging
;;; and administration.
;;;
;;; Common operations:
;;;   kubectl get pods     -- List running pods
;;;   kubectl describe     -- Show detailed resource info
;;;   kubectl logs         -- Fetch pod logs
;;;   kubectl exec         -- Execute commands in a container
;;;   kubectl apply        -- Apply resource manifests
;;;   kubectl drain        -- Safely evict pods from a node

(define-public andyl-kubectl
  (package
    (name "andyl-kubectl")
    (version (config-version "kubernetes" "kubectl"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/kubernetes/kubernetes"
                    "/archive/refs/tags/v" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/kubernetes/kubernetes/archive/refs/tags/v1.31.4.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "k8s.io/kubernetes"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (with-directory-excursion
                  (string-append "src/" import-path)
                (invoke "make" "WHAT=cmd/kubectl"
                        "GOFLAGS=-trimpath"))))

          (replace 'install
            (lambda* (#:key import-path outputs #:allow-other-keys)
              (let ((bindir (string-append (assoc-ref outputs "out") "/bin")))
                (with-directory-excursion
                    (string-append "src/" import-path)
                  (mkdir-p bindir)
                  (install-file "_output/bin/kubectl" bindir)))))

          (delete 'check))))

    (native-inputs
     (list andyl-gcc))

    (inputs
     (list andyl-glibc))

    (home-page "https://kubernetes.io/docs/reference/kubectl/")
    (synopsis "Kubernetes CLI tool for ANDYL OS")
    (description
     "kubectl is the command-line interface for the Kubernetes API server.
Included on ANDYL OS nodes for on-node debugging and administration.
Provides commands for managing pods, services, deployments, and other
Kubernetes resources.  Also used by the kubelet-node-labels oneshot
service to apply node labels and taints after cluster join.")
    (license license:asl2.0)))


;;; =========================================================================
;;; crictl -- CRI CLI debugging tool
;;; =========================================================================
;;;
;;; crictl is a command-line tool for inspecting and debugging the Container
;;; Runtime Interface (CRI).  It communicates with containerd via the same
;;; gRPC socket that kubelet uses.
;;;
;;; Common commands:
;;;   crictl info     -- Display runtime and image service info
;;;   crictl ps       -- List running containers
;;;   crictl images   -- List images
;;;   crictl logs     -- Fetch container logs
;;;   crictl inspect  -- Inspect a container
;;;
;;; See: Phase 7 section 7.3 (Kubernetes Packages)

(define-public andyl-crictl
  (package
    (name "andyl-crictl")
    (version (config-version "kubernetes" "crictl"))
    (source (origin
              (method url-fetch)
              (uri (string-append
                    "https://github.com/kubernetes-sigs/cri-tools"
                    "/archive/refs/tags/v" version ".tar.gz"))
              (sha256
               ;; TODO: Compute actual hash:
               ;;   guix download https://github.com/kubernetes-sigs/cri-tools/archive/refs/tags/v1.31.1.tar.gz
               (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system go-build-system)
    (arguments
     (list
      #:import-path "github.com/kubernetes-sigs/cri-tools"
      #:install-source? #f

      #:phases
      #~(modify-phases %standard-phases
          (replace 'build
            (lambda* (#:key import-path #:allow-other-keys)
              (with-directory-excursion
                  (string-append "src/" import-path)
                (invoke "make" "binaries"
                        "GO_BUILD_FLAGS=-trimpath"))))

          (replace 'install
            (lambda* (#:key import-path outputs #:allow-other-keys)
              (let ((bindir (string-append (assoc-ref outputs "out") "/bin")))
                (with-directory-excursion
                    (string-append "src/" import-path)
                  (mkdir-p bindir)
                  (install-file "build/bin/crictl" bindir)))))

          (delete 'check))))

    (native-inputs
     (list andyl-gcc))

    (inputs
     (list andyl-glibc))

    (home-page "https://github.com/kubernetes-sigs/cri-tools")
    (synopsis "CRI CLI debugging tool for ANDYL OS")
    (description
     "crictl is a command-line tool for inspecting and debugging Kubernetes
container runtimes via the Container Runtime Interface (CRI) gRPC API.
Provides commands for listing containers and images, fetching logs,
inspecting container state, and querying runtime info.  Communicates
with containerd via /run/containerd/containerd.sock.")
    (license license:asl2.0)))
