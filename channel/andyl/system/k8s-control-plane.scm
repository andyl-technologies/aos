;;; ANDYL OS -- Kubernetes Control Plane System Configuration
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the Kubernetes control plane system configuration
;;; for ANDYL OS:
;;;
;;;   andyl-os-k8s-control-plane  -- Kubernetes control plane operating system
;;;
;;; The control plane extends the worker configuration with kubeadm for
;;; cluster bootstrapping.  Control plane components (API server, scheduler,
;;; controller manager, etcd) run as static pods managed by kubelet --
;;; they are pulled as container images rather than installed as host
;;; packages.
;;;
;;; Additional capabilities over the worker:
;;;   - kubeadm for cluster initialization and node joining
;;;   - Static pod manifest directory (/etc/kubernetes/manifests)
;;;   - Control plane firewall rules (API server, etcd, scheduler, etc.)
;;;
;;; See:
;;;   RFC-0007 sections 5, 6 (Static Pods, etcd)
;;;   Phase 7 section 7.10 (K8s Control Plane Image Variant)

(define-module (andyl system k8s-control-plane)
  #:use-module (guix packages)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl system base)
  #:use-module (andyl system server)
  #:use-module (andyl system k8s-worker)
  #:use-module (andyl config)
  #:use-module (andyl packages kubernetes)
  #:export (andyl-os-k8s-control-plane
            %andyl-k8s-control-plane-packages
            %andyl-k8s-control-plane-nftables-config))


;;;
;;; Control Plane Packages
;;;
;;; The control plane adds kubeadm for cluster bootstrapping to the
;;; worker package set.
;;;
;;; Control plane components (API server, scheduler, controller manager,
;;; etcd) run as static pods managed by kubelet.  They are pulled as
;;; container images, so they do NOT appear as host packages.
;;;

(define %andyl-k8s-control-plane-packages
  (append
   (list
    andyl-kubeadm)                   ; Cluster bootstrap and lifecycle
   %andyl-k8s-worker-packages))


;;;
;;; Control Plane nftables Configuration
;;;
;;; Extends the worker firewall with control plane-specific ports.
;;;
;;; Additional ports:
;;;   6443   -- Kubernetes API server (HTTPS)
;;;   2379   -- etcd client port
;;;   2380   -- etcd peer port
;;;   10257  -- kube-controller-manager health
;;;   10259  -- kube-scheduler health
;;;

(define %andyl-k8s-control-plane-nftables-config
  (let ((ssh-port     (config-ref "security.ssh.port" 22))
        (cp-tcp       (config-ref/list "kubernetes.firewall.control-plane-tcp"))
        (worker-tcp   (config-ref/list "kubernetes.firewall.worker-tcp"))
        (worker-udp   (config-ref/list "kubernetes.firewall.worker-udp"))
        (nodeport     (config-ref "kubernetes.firewall.nodeport-range" "30000-32767"))
        (cilium-tcp   (config-ref/list "kubernetes.firewall.cilium-tcp"))
        (fwd-policy   (config-ref "kubernetes.firewall.forward-policy" "accept")))
    (string-append
     "#!/usr/sbin/nft -f\n"
     "# ANDYL OS Kubernetes Control Plane Firewall Configuration\n"
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
     "        # Control plane TCP ports\n"
     "        tcp dport { " (format-port-list cp-tcp) " } accept\n\n"
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
;;; Kubernetes Control Plane Operating System
;;;
;;; Extends the worker with kubeadm for cluster bootstrapping.
;;; Control plane components (API server, scheduler, controller manager,
;;; etcd) run as static pods -- they are container images pulled by
;;; kubelet, not host-level packages.
;;;

(define andyl-os-k8s-control-plane
  (andyl-operating-system
   (host-name "k8s-cp")             ;; Overridden by Ignition per-machine
   (kernel-arguments %andyl-server-kernel-arguments)
   (extra-packages %andyl-k8s-control-plane-packages)
   (extra-services (append %andyl-k8s-worker-services
                           %andyl-server-services))))
