;;; ANDYL OS -- Kubernetes Worker Node System Configuration
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the Kubernetes worker node system configuration
;;; for ANDYL OS:
;;;
;;;   andyl-os-k8s-worker  -- Kubernetes worker node operating system
;;;
;;; The worker inherits from the server configuration (andyl system server)
;;; and adds:
;;;
;;;   - Container runtime: containerd + runc
;;;   - Node agent: kubelet
;;;   - CLI tools: kubectl, crictl, helm, nerdctl
;;;   - Standard CNI plugins: bridge, loopback, host-local, portmap, etc.
;;;   - Supporting tools: ethtool, socat, conntrack-tools, ipvsadm
;;;   - systemd services: containerd.service, kubelet.service
;;;   - K8s-specific sysctl settings (IP forwarding, bridge-nf-call)
;;;   - K8s-specific kernel modules (br_netfilter, overlay, ip_vs)
;;;   - Container storage on ZFS (datapool/containerd)
;;;   - Pluggable extension points for CNI, CSI, and device plugins
;;;
;;; Design principles:
;;;   - CNI/CSI/device plugins are deployed at runtime (not baked in)
;;;   - All mutable state lives on /var (ZFS)
;;;   - Configuration is delivered per-machine via Ignition
;;;   - The golden image is identical for all nodes of the same role
;;;
;;; See:
;;;   RFC-0007 section 1 (Role-Based Package Sets)
;;;   Phase 7 section 7.9 (K8s Worker Image Variant)

(define-module (andyl system k8s-worker)
  #:use-module (guix packages)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl system base)
  #:use-module (andyl system server)
  #:use-module (andyl config)
  #:use-module (andyl packages containerd)
  #:use-module (andyl packages kubernetes)
  #:use-module (andyl packages cni)
  #:use-module (andyl packages k8s-tools)
  #:export (andyl-os-k8s-worker
            %andyl-k8s-worker-packages
            %andyl-k8s-worker-services
            %andyl-k8s-worker-file-systems
            %andyl-k8s-worker-nftables-config))


;;;
;;; Kubernetes Worker Packages
;;;
;;; The worker package set includes everything needed to run pods on a
;;; Kubernetes node.  All binaries reside in content-addressed store
;;; paths under /gnu/store and are read-only at runtime.
;;;
;;; Package categories:
;;;   1. Container runtime (containerd, runc)
;;;   2. Kubernetes node agent (kubelet)
;;;   3. CLI and debugging tools (kubectl, crictl, helm, nerdctl)
;;;   4. Standard CNI plugins (bridge, loopback, host-local, portmap, etc.)
;;;   5. Supporting tools (ethtool, socat, conntrack-tools, ipvsadm)
;;;
;;; Base networking tools (iptables, iproute2, nftables) are already
;;; included in the server package set.
;;;

(define %andyl-k8s-worker-packages
  (list
   ;; === Container Runtime ===
   andyl-containerd                  ; CRI implementation (gRPC daemon)
   andyl-runc                        ; OCI runtime (creates containers)

   ;; === Kubernetes Node Agent ===
   andyl-kubelet                     ; Watches API server, manages pods

   ;; === CLI and Debugging Tools ===
   andyl-kubectl                     ; Kubernetes CLI (on-node debugging)
   andyl-crictl                      ; CRI debugging (inspect containers)
   andyl-helm                        ; Package manager (deploy CNI, CSI, etc.)
   andyl-nerdctl                     ; Docker-compatible CLI for containerd

   ;; === Standard CNI Plugins ===
   ;; Installed to /opt/cni/bin.  These provide the foundation for
   ;; higher-level CNI implementations (Cilium, Calico, Flannel).
   ;; The base image does NOT include any specific CNI configuration.
   andyl-cni-plugins                 ; bridge, loopback, host-local, portmap, etc.

   ;; === Supporting Tools ===
   andyl-ethtool                     ; NIC diagnostics
   andyl-socat                       ; Port forwarding (kubectl port-forward)
   andyl-conntrack-tools             ; Connection tracking management
   andyl-ipvsadm))                   ; IPVS management (kube-proxy IPVS mode)


;;;
;;; Kubernetes Worker Services
;;;
;;; systemd services enabled on worker nodes beyond the server set.
;;;

(define %andyl-k8s-worker-services
  (list
   ;; containerd: CRI runtime, must start before kubelet
   "containerd.service"

   ;; kubelet: Kubernetes node agent, starts after containerd
   "kubelet.service"))


;;;
;;; Kubernetes Worker Filesystem Entries
;;;
;;; Additional ZFS datasets for Kubernetes mutable state.
;;; These document the expected runtime layout; actual datasets are
;;; created by Ignition on first boot.
;;;

(define %andyl-k8s-worker-file-systems
  (list
   ;; containerd storage: container images, snapshots, and metadata.
   ;; On ZFS, created by Ignition with optimized properties:
   ;;   recordsize=128K (matches container layer size)
   ;;   compression=zstd (good ratio for container layers)
   ;;   atime=off (container layers don't need access time tracking)
   (andyl-file-system
    (device "datapool/containerd")
    (mount-point "/var/lib/containerd")
    (type "zfs")
    (flags '("noatime")))))


;;;
;;; Kubernetes Worker nftables Configuration
;;;
;;; Extends the server firewall with Kubernetes-specific rules.
;;; Opens ports for kubelet and allows forwarded traffic for containers.
;;;
;;; Ports:
;;;   10250  -- kubelet API (HTTPS, used by API server)
;;;   10256  -- kube-proxy health check (or Cilium health check)
;;;   30000-32767 -- NodePort service range
;;;
;;; The forward chain is set to accept because CNI plugins (Cilium,
;;; Calico) manage forwarding rules dynamically.
;;;

(define %andyl-k8s-worker-nftables-config
  (let ((ssh-port     (config-ref "security.ssh.port" 22))
        (worker-tcp   (config-ref/list "kubernetes.firewall.worker-tcp"))
        (worker-udp   (config-ref/list "kubernetes.firewall.worker-udp"))
        (nodeport     (config-ref "kubernetes.firewall.nodeport-range" "30000-32767"))
        (cilium-tcp   (config-ref/list "kubernetes.firewall.cilium-tcp"))
        (fwd-policy   (config-ref "kubernetes.firewall.forward-policy" "accept")))
    (string-append
     "#!/usr/sbin/nft -f\n"
     "# ANDYL OS Kubernetes Worker Node Firewall Configuration\n"
     "# Generated from config/kubernetes.toml and config/security.toml\n\n"
     "flush ruleset\n\n"
     "table inet filter {\n"
     "    chain input {\n"
     "        type filter hook input priority filter; policy drop;\n\n"
     "        # Allow loopback traffic\n"
     "        iif lo accept\n\n"
     "        # Allow established and related connections\n"
     "        ct state established,related accept\n\n"
     "        # Drop invalid packets\n"
     "        ct state invalid drop\n\n"
     "        # Allow ICMP (ping, path MTU discovery)\n"
     "        ip protocol icmp accept\n"
     "        ip6 nexthdr icmpv6 accept\n\n"
     "        # Allow SSH\n"
     "        tcp dport " (number->string ssh-port) " accept\n\n"
     "        # Kubernetes worker TCP ports\n"
     "        tcp dport { " (format-port-list worker-tcp) " } accept\n\n"
     "        # Kubernetes NodePort service range\n"
     "        tcp dport " nodeport " accept\n"
     "        udp dport " nodeport " accept\n\n"
     "        # Kubernetes worker UDP ports (VXLAN, etc.)\n"
     "        udp dport { " (format-port-list worker-udp) " } accept\n\n"
     "        # Cilium: health check and Hubble\n"
     "        tcp dport { " (format-port-list cilium-tcp) " } accept\n\n"
     "        # Log dropped packets (rate-limited)\n"
     "        limit rate 5/minute burst 5 packets log prefix \"nftables-drop: \" level info\n"
     "    }\n\n"
     "    chain forward {\n"
     "        type filter hook forward priority filter; policy " fwd-policy ";\n"
     "    }\n\n"
     "    chain output {\n"
     "        type filter hook output priority filter; policy accept;\n"
     "    }\n"
     "}\n")))


;;;
;;; Kubernetes Worker Operating System
;;;
;;; The worker configuration inherits from the server and adds:
;;;   - Kubernetes packages (containerd, kubelet, kubectl, etc.)
;;;   - Kubernetes services (containerd.service, kubelet.service)
;;;   - Supporting tools (ethtool, socat, conntrack-tools, ipvsadm)
;;;

(define andyl-os-k8s-worker
  (andyl-operating-system
   (host-name "k8s-worker")          ;; Overridden by Ignition per-machine
   (kernel-arguments %andyl-server-kernel-arguments)
   (extra-packages %andyl-k8s-worker-packages)
   (extra-services (append %andyl-k8s-worker-services
                           %andyl-server-services))))
