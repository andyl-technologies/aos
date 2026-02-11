;;; ANDYL OS -- kubelet Service Definition
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the systemd service unit, sysctl settings, and
;;; supporting system configuration for the Kubernetes kubelet on ANDYL OS:
;;;
;;;   kubelet.service          -- Kubernetes node agent systemd service
;;;   K8s sysctl settings      -- IP forwarding, bridge-nf-call, conntrack
;;;   K8s tmpfiles.d entries   -- kubelet runtime directories on /var
;;;
;;; kubelet is the primary Kubernetes node agent.  It watches the API server
;;; for pod assignments and ensures containers are running via the CRI
;;; (containerd).
;;;
;;; Service ordering:
;;;   1. containerd starts and creates gRPC socket
;;;   2. kubelet starts after containerd
;;;   3. kubelet registers node with API server
;;;   4. CNI plugin deployed at runtime makes node Ready
;;;
;;; All mutable kubelet state lives on /var:
;;;   /var/lib/kubelet     -- Kubelet state, pod volumes, device plugins
;;;   /var/log/pods        -- Pod log files
;;;   /var/log/containers  -- Container log symlinks
;;;
;;; See:
;;;   RFC-0007 section 4 (Kubelet on an Immutable OS)
;;;   Phase 7 section 7.7 (kubelet Configuration)

(define-module (andyl services kubelet)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl config)
  #:export (%andyl-kubelet-service-unit
            %andyl-k8s-sysctl-settings
            %andyl-kubelet-tmpfiles
            andyl-kubelet-units))


;;;
;;; Sysctl Settings for Kubernetes
;;;
;;; These kernel parameters are required for Kubernetes networking to
;;; function correctly.  They override the default server sysctl settings
;;; (which disable IP forwarding) because Kubernetes requires forwarding
;;; for pod-to-pod and pod-to-service traffic.
;;;
;;; kubelet with protectKernelDefaults=true verifies these settings at
;;; startup and refuses to start if they are incorrect.
;;;
;;; See: RFC-0007 section 4 (protectKernelDefaults implications)
;;;

(define %andyl-k8s-sysctl-settings
  (let ((settings (config-ref/alist "kubernetes.sysctl")))
    (string-append
     "# ANDYL OS Kubernetes -- required sysctl settings\n"
     "# Generated from config/kubernetes.toml\n"
     "# Applied by systemd-sysctl.service from /etc/sysctl.d/\n\n"
     (string-join
      (map (lambda (pair)
             (string-append (car pair) " = " (cdr pair)))
           settings)
      "\n")
     "\n")))


;;;
;;; tmpfiles.d -- Runtime Directory Creation for kubelet
;;;
;;; Creates the mutable directories that kubelet requires.
;;; These directories live on /var (ZFS) and persist across reboots.
;;;

(define %andyl-kubelet-tmpfiles
  "\
# ANDYL OS kubelet -- runtime directories
# Created by systemd-tmpfiles-setup.service at boot.
# See: RFC-0007 section 4 (Mutable paths kubelet requires)

# kubelet state: pod volumes, checkpoints, device plugin sockets.
d /var/lib/kubelet 0750 root root -
d /var/lib/kubelet/pods 0750 root root -
d /var/lib/kubelet/pki 0700 root root -

# CSI plugin extension points
# CSI drivers register their gRPC sockets here at runtime.
d /var/lib/kubelet/plugins 0750 root root -
d /var/lib/kubelet/plugins_registry 0750 root root -

# Device plugin extension point
# GPU, FPGA, SR-IOV, and other device plugins register here.
d /var/lib/kubelet/device-plugins 0750 root root -

# Seccomp profiles (custom profiles delivered via Ignition or ConfigMap)
d /var/lib/kubelet/seccomp 0750 root root -
d /var/lib/kubelet/seccomp/profiles 0750 root root -

# Pod and container logs
d /var/log/pods 0755 root root -
d /var/log/containers 0755 root root -
d /var/log/kubernetes 0755 root root -

# Static pod manifest directory (control plane nodes)
d /etc/kubernetes 0755 root root -
d /etc/kubernetes/manifests 0755 root root -
")


;;;
;;; kubelet systemd service unit
;;;
;;; kubelet is the Kubernetes node agent.  It watches the API server for
;;; pod assignments and ensures containers are running via containerd.
;;;
;;; Configuration is delivered via Ignition to /var/lib/kubelet/config.yaml
;;; (not baked into the image).  The service unit references this path.
;;;
;;; Accounting flags (CPUAccounting, MemoryAccounting, IOAccounting)
;;; enable systemd cgroup accounting, which kubelet uses for resource
;;; tracking and enforcement.
;;;
;;; See: RFC-0007 section 4 (kubelet systemd unit)
;;;

(define %andyl-kubelet-service-unit
  (let ((config-path  (config-ref "kubernetes.kubelet.config-path" "/var/lib/kubelet/config.yaml"))
        (kubeconfig   (config-ref "kubernetes.kubelet.kubeconfig-path" "/var/lib/kubelet/kubeconfig"))
        (bootstrap    (config-ref "kubernetes.kubelet.bootstrap-kubeconfig-path" "/var/lib/kubelet/bootstrap-kubeconfig"))
        (cert-dir     (config-ref "kubernetes.kubelet.cert-dir" "/var/lib/kubelet/pki"))
        (root-dir     (config-ref "kubernetes.kubelet.root-dir" "/var/lib/kubelet"))
        (cri-endpoint (config-ref "kubernetes.kubelet.cri-endpoint" "unix:///run/containerd/containerd.sock"))
        (verbosity    (config-ref "kubernetes.kubelet.verbosity" 2)))
    (string-append
     "[Unit]\n"
     "Description=Kubernetes Kubelet\n"
     "Documentation=https://kubernetes.io/docs/\n"
     "After=containerd.service\n"
     "Requires=containerd.service\n\n"
     "[Service]\n"
     "ExecStart=/gnu/store/placeholder-kubelet/bin/kubelet \\\n"
     "  --config=" config-path " \\\n"
     "  --kubeconfig=" kubeconfig " \\\n"
     "  --bootstrap-kubeconfig=" bootstrap " \\\n"
     "  --cert-dir=" cert-dir " \\\n"
     "  --root-dir=" root-dir " \\\n"
     "  --container-runtime-endpoint=" cri-endpoint " \\\n"
     "  --node-labels=node.andyl.internal/os=andyl-os \\\n"
     "  --register-with-taints=\"\" \\\n"
     "  --v=" (number->string verbosity) "\n\n"
     "Restart=always\n"
     "RestartSec=10\n"
     "StartLimitInterval=0\n"
     "KillMode=process\n\n"
     "CPUAccounting=true\n"
     "MemoryAccounting=true\n"
     "IOAccounting=true\n\n"
     "[Install]\n"
     "WantedBy=multi-user.target\n")))


;;;
;;; Collected unit files
;;;
;;; Returns an association list of (filename . content) pairs for all
;;; kubelet-related systemd units, sysctl settings, and tmpfiles.d
;;; configuration.
;;;

(define (andyl-kubelet-units)
  "Return an alist of (filename . content) pairs for all systemd unit
files and configuration for the Kubernetes kubelet."
  (list
   ;; kubelet service unit
   (cons "lib/systemd/system/kubelet.service"
         %andyl-kubelet-service-unit)

   ;; sysctl settings for Kubernetes networking
   (cons "lib/sysctl.d/90-andyl-kubernetes.conf"
         %andyl-k8s-sysctl-settings)

   ;; tmpfiles.d for kubelet runtime directory creation
   (cons "lib/tmpfiles.d/andyl-kubelet.conf"
         %andyl-kubelet-tmpfiles)))
