;;; ANDYL OS -- containerd Service Definition
;;; Copyright (C) 2024 ANDYL OS Contributors
;;;
;;; This module defines the systemd service unit, configuration, and
;;; supporting system configuration for the containerd container runtime
;;; on ANDYL OS:
;;;
;;;   containerd.service       -- Container runtime systemd service
;;;   config.toml              -- containerd configuration (CRI, snapshotter)
;;;   Kernel modules           -- overlay, br_netfilter, etc.
;;;   tmpfiles.d entries       -- Runtime directories on /var
;;;
;;; containerd provides the Container Runtime Interface (CRI) that kubelet
;;; uses to manage container lifecycles.  It communicates with kubelet via
;;; a gRPC socket at /run/containerd/containerd.sock.
;;;
;;; Service ordering:
;;;   1. Kernel modules loaded (overlay, br_netfilter)
;;;   2. tmpfiles.d creates directories on /var
;;;   3. containerd starts and creates gRPC socket
;;;   4. kubelet starts after containerd
;;;
;;; See:
;;;   RFC-0007 section 2 (Container Runtime Interface)
;;;   Phase 7 section 7.6 (containerd Configuration)

(define-module (andyl services containerd)
  #:use-module (guix records)
  #:use-module (guix gexp)
  #:use-module (andyl config)
  #:export (%andyl-containerd-service-unit
            %andyl-containerd-config-toml
            %andyl-containerd-tmpfiles
            %andyl-containerd-modules-load
            andyl-containerd-units))


;;;
;;; Kernel Modules for Container Runtime
;;;
;;; These kernel modules must be loaded before containerd can function.
;;; Loaded early in boot via systemd-modules-load.
;;;
;;;   overlay       -- OverlayFS for container image layers
;;;   br_netfilter  -- Bridge netfilter for container networking
;;;   vxlan         -- VXLAN tunneling for overlay CNI plugins
;;;   nf_conntrack  -- Connection tracking for NAT
;;;   ip_vs*        -- IPVS for kube-proxy IPVS mode
;;;

(define %andyl-containerd-modules-load
  (let ((modules (config-ref/list "kubernetes.modules.load")))
    (string-append
     "# ANDYL OS -- kernel modules for container runtime and Kubernetes networking\n"
     "# Generated from config/kubernetes.toml\n"
     "# Loaded by systemd-modules-load.service at boot.\n\n"
     (string-join modules "\n")
     "\n")))


;;;
;;; tmpfiles.d -- Runtime Directory Creation for containerd
;;;
;;; Creates the mutable directories that containerd requires.
;;; These directories live on /var (ZFS) and persist across reboots.
;;;

(define %andyl-containerd-tmpfiles
  "\
# ANDYL OS containerd -- runtime directories
# Created by systemd-tmpfiles-setup.service at boot.
# See: RFC-0007 section 2 (Path mapping for immutable OS)

# containerd state: container images, snapshots, and metadata.
# On ZFS, this should be its own dataset (datapool/containerd)
# created by Ignition with appropriate recordsize and compression.
d /var/lib/containerd 0711 root root -

# containerd opt directory for additional plugins
d /var/lib/containerd/opt 0711 root root -

# CNI plugin directories
# /opt/cni/bin is populated by the andyl-cni-plugins package and may
# be written to by CNI init containers (e.g., Cilium).
d /opt/cni/bin 0755 root root -

# CNI configuration directory -- EMPTY in base image.
# The deployed CNI plugin writes its config here at runtime.
d /etc/cni/net.d 0755 root root -

# containerd configuration and registry certificate directory
d /etc/containerd 0755 root root -
d /etc/containerd/certs.d 0755 root root -
")


;;;
;;; containerd configuration (config.toml)
;;;
;;; This is the containerd CRI configuration baked into the golden image.
;;; Per-machine overrides are applied via Ignition to the /etc overlay.
;;;
;;; Key settings:
;;;   - SystemdCgroup=true: matches kubelet cgroupDriver setting
;;;   - Snapshotter=overlayfs: default for ext4; use "zfs" for ZFS layout
;;;   - CNI bin_dir=/opt/cni/bin: standard CNI plugin binaries
;;;   - CNI conf_dir=/etc/cni/net.d: written at runtime by deployed CNI
;;;
;;; See: RFC-0007 section 2 (Container Runtime Interface)
;;;

(define %andyl-containerd-config-toml
  (let ((root        (config-ref "kubernetes.containerd.root" "/var/lib/containerd"))
        (state       (config-ref "kubernetes.containerd.state" "/run/containerd"))
        (oom-score   (config-ref "kubernetes.containerd.oom-score" -999))
        (socket      (config-ref "kubernetes.containerd.socket" "/run/containerd/containerd.sock"))
        (metrics     (config-ref "kubernetes.containerd.metrics-address" "127.0.0.1:1338"))
        (pause-image (config-ref "kubernetes.containerd.pause-image" "registry.k8s.io/pause:3.10"))
        (max-log     (config-ref "kubernetes.containerd.max-container-log-line-size" 16384))
        (snapshotter (config-ref "kubernetes.containerd.snapshotter" "overlayfs"))
        (cni-bin     (config-ref "kubernetes.containerd.cni-bin-dir" "/opt/cni/bin"))
        (cni-conf    (config-ref "kubernetes.containerd.cni-conf-dir" "/etc/cni/net.d")))
    (string-append
     "# ANDYL OS containerd configuration\n"
     "# Generated from config/kubernetes.toml\n"
     "# /etc/containerd/config.toml\n\n"
     "version = 2\n\n"
     "root = \"" root "\"\n"
     "state = \"" state "\"\n"
     "oom_score = " (number->string oom-score) "\n\n"
     "[grpc]\n"
     "  address = \"" socket "\"\n"
     "  uid = 0\n"
     "  gid = 0\n"
     "  max_recv_message_size = 16777216\n"
     "  max_send_message_size = 16777216\n\n"
     "[debug]\n"
     "  address = \"\"\n"
     "  level = \"info\"\n\n"
     "[metrics]\n"
     "  address = \"" metrics "\"\n"
     "  grpc_histogram = false\n\n"
     "[plugins]\n"
     "  [plugins.\"io.containerd.grpc.v1.cri\"]\n"
     "    sandbox_image = \"" pause-image "\"\n"
     "    max_container_log_line_size = " (number->string max-log) "\n\n"
     "    [plugins.\"io.containerd.grpc.v1.cri\".containerd]\n"
     "      snapshotter = \"" snapshotter "\"\n"
     "      default_runtime_name = \"runc\"\n\n"
     "      [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes]\n"
     "        [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\n"
     "          runtime_type = \"io.containerd.runc.v2\"\n"
     "          [plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc.options]\n"
     "            SystemdCgroup = true\n"
     "            BinaryName = \"/gnu/store/placeholder-runc/sbin/runc\"\n\n"
     "    [plugins.\"io.containerd.grpc.v1.cri\".cni]\n"
     "      bin_dir = \"" cni-bin "\"\n"
     "      conf_dir = \"" cni-conf "\"\n\n"
     "    [plugins.\"io.containerd.grpc.v1.cri\".registry]\n"
     "      config_path = \"/etc/containerd/certs.d\"\n\n"
     "  [plugins.\"io.containerd.internal.v1.opt\"]\n"
     "    path = \"" root "/opt\"\n")))


;;;
;;; containerd systemd service unit
;;;
;;; Key configuration:
;;;   Delegate=yes  -- Delegates cgroup management to containerd.
;;;   KillMode=process  -- Only kill main process, not container shims.
;;;   OOMScoreAdjust=-999  -- Protect containerd from OOM killer.
;;;
;;; See: RFC-0007 section 2 (systemd unit file)
;;;

(define %andyl-containerd-service-unit
  (let ((oom-score (config-ref "kubernetes.containerd.oom-score" -999)))
    (string-append
     "[Unit]\n"
     "Description=containerd container runtime\n"
     "Documentation=https://containerd.io\n"
     "After=network.target local-fs.target\n"
     "After=systemd-modules-load.service\n"
     "Before=kubelet.service\n\n"
     "[Service]\n"
     "ExecStartPre=-/sbin/modprobe overlay\n"
     "ExecStart=/gnu/store/placeholder-containerd/bin/containerd \\\n"
     "  --config=/etc/containerd/config.toml\n"
     "Restart=always\n"
     "RestartSec=5\n\n"
     "Delegate=yes\n"
     "KillMode=process\n"
     "OOMScoreAdjust=" (number->string oom-score) "\n\n"
     "LimitNOFILE=1048576\n"
     "LimitNPROC=infinity\n"
     "LimitCORE=infinity\n"
     "TasksMax=infinity\n\n"
     "[Install]\n"
     "WantedBy=multi-user.target\n")))


;;;
;;; Collected unit files
;;;
;;; Returns an association list of (filename . content) pairs for all
;;; containerd-related systemd units, config files, modules-load.d, and
;;; tmpfiles.d configuration.
;;;

(define (andyl-containerd-units)
  "Return an alist of (filename . content) pairs for all systemd unit
files and configuration for the containerd container runtime."
  (list
   ;; containerd service unit
   (cons "lib/systemd/system/containerd.service"
         %andyl-containerd-service-unit)

   ;; Kernel modules for container runtime and networking
   (cons "lib/modules-load.d/andyl-containerd.conf"
         %andyl-containerd-modules-load)

   ;; tmpfiles.d for runtime directory creation
   (cons "lib/tmpfiles.d/andyl-containerd.conf"
         %andyl-containerd-tmpfiles)))
