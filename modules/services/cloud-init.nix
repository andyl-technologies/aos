##! modules/services/cloud-init.nix — Shell-based cloud-init for golden image
##!
##! Processes JSON userdata from a NoCloud seed directory to configure the
##! system at first boot. Uses jq for JSON parsing (no Python dependency).
##!
##! Four systemd service stages execute in order:
##!   1. cloud-init-local  (before network) — hostname, networkd configs
##!   2. cloud-init-network (after network)  — role detection, role marker
##!   3. cloud-init-config  (after network)  — users, SSH keys, firewall, k8s config
##!   4. cloud-init-final   (after config)   — start activated services, boot-finished marker
##!
##! Userdata format (JSON):
##!   {
##!     "hostname": "web-1",
##!     "role": "server",
##!     "networking": { "interfaces": { "eth0": { "address": "10.0.0.5/24", "gateway": "10.0.0.1", "dns": "10.0.0.1" } } },
##!     "users": [ { "name": "deploy", "uid": 1000, "groups": ["wheel"], "ssh_authorized_keys": ["ssh-ed25519 ..."] } ],
##!     "firewall": { "allowed_tcp": [22, 80, 443], "allowed_udp": [], "forward_policy": "drop" },
##!     "kubernetes": {
##!       "server_url": "https://10.0.0.10:6443",
##!       "token_file": "/etc/rancher/k3s/agent-token",
##!       "cluster_init": false,
##!       "tls_san": [],
##!       "cluster_cidr": "10.244.0.0/16",
##!       "service_cidr": "10.96.0.0/12",
##!       "disable_kube_proxy": true,
##!       "node_labels": {},
##!       "node_taints": [],
##!       "registry_mirrors": {},
##!       "containerd": { "snapshotter": "overlayfs" }
##!     },
##!     "services": { "chrony": true, "fail2ban": true }
##!   }
{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.aos.services.cloudInit;

  jqBin = "${pkgs.jq}/bin/jq";
  seedDir = "/var/lib/cloud/seed/nocloud";
  userDataFile = "${seedDir}/user-data";
  stateDir = "/var/lib/cloud/state";

  # -------------------------------------------------------------------------
  # Stage scripts — embedded in /etc/aos/cloud-init/
  # -------------------------------------------------------------------------

  # Stage 1: local (before network)
  # Sets hostname and writes networkd config files.
  localScript = ''
    #!/bin/sh
    set -eu
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    USERDATA="${userDataFile}"
    STATE="${stateDir}"
    JQ="${jqBin}"
    mkdir -p "$STATE"

    if [ ! -f "$USERDATA" ]; then
      echo "cloud-init-local: no userdata found, using defaults"
      echo "aos" > /etc/hostname
      echo "done" > "$STATE/local-done"
      exit 0
    fi

    # Hostname
    HOSTNAME=$($JQ -r '.hostname // "aos"' < "$USERDATA")
    echo "$HOSTNAME" > /etc/hostname
    echo "cloud-init-local: hostname=$HOSTNAME"

    # Networking — write systemd-networkd .network files
    # Check if networking.interfaces exists and is non-empty
    HAS_INTERFACES=$($JQ -r 'if .networking.interfaces and (.networking.interfaces | length > 0) then "yes" else "no" end' < "$USERDATA")
    if [ "$HAS_INTERFACES" = "yes" ]; then
      mkdir -p /etc/systemd/network
      # Remove default DHCP config if static interfaces are specified
      rm -f /etc/systemd/network/80-dhcp.network

      $JQ -r '.networking.interfaces | to_entries[] | .key' < "$USERDATA" | while IFS= read -r IFACE; do
        ADDR=$($JQ -r ".networking.interfaces[\"$IFACE\"].address // empty" < "$USERDATA")
        GW=$($JQ -r ".networking.interfaces[\"$IFACE\"].gateway // empty" < "$USERDATA")
        DNS=$($JQ -r ".networking.interfaces[\"$IFACE\"].dns // empty" < "$USERDATA")

        NETFILE="/etc/systemd/network/10-$IFACE.network"
        printf '[Match]\nName=%s\n\n[Network]\n' "$IFACE" > "$NETFILE"
        if [ -n "$ADDR" ]; then
          printf 'Address=%s\n' "$ADDR" >> "$NETFILE"
          if [ -n "$GW" ]; then
            printf 'Gateway=%s\n' "$GW" >> "$NETFILE"
          fi
          if [ -n "$DNS" ]; then
            printf 'DNS=%s\n' "$DNS" >> "$NETFILE"
          fi
        else
          printf 'DHCP=yes\n' >> "$NETFILE"
        fi
        echo "cloud-init-local: wrote $NETFILE"
      done
    fi

    echo "done" > "$STATE/local-done"
    echo "cloud-init-local: complete"
  '';

  # Stage 2: network (after network-online)
  # Detects role and writes role marker.
  networkScript = ''
    #!/bin/sh
    set -eu
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    USERDATA="${userDataFile}"
    STATE="${stateDir}"
    JQ="${jqBin}"
    mkdir -p "$STATE"

    if [ ! -f "$USERDATA" ]; then
      echo "server" > "$STATE/active-role"
      echo "cloud-init-network: no userdata, default role=server"
      echo "done" > "$STATE/network-done"
      exit 0
    fi

    ROLE=$($JQ -r '.role // "server"' < "$USERDATA")
    echo "$ROLE" > "$STATE/active-role"
    echo "cloud-init-network: role=$ROLE"
    echo "done" > "$STATE/network-done"
  '';

  # Stage 3: config (after network stage)
  # Users/groups, SSH keys, firewall rules, k8s config, kernel prereqs.
  configScript = ''
    #!/bin/sh
    set -eu
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    USERDATA="${userDataFile}"
    STATE="${stateDir}"
    JQ="${jqBin}"
    mkdir -p "$STATE"

    if [ ! -f "$USERDATA" ]; then
      echo "done" > "$STATE/config-done"
      exit 0
    fi

    ROLE=$(cat "$STATE/active-role" 2>/dev/null || echo "server")

    # --- Users ---
    HAS_USERS=$($JQ -r 'if .users and (.users | length > 0) then "yes" else "no" end' < "$USERDATA")
    if [ "$HAS_USERS" = "yes" ]; then
      $JQ -c '.users[]' < "$USERDATA" | while IFS= read -r UDATA; do
        UNAME=$(printf '%s' "$UDATA" | $JQ -r '.name')
        UUID=$(printf '%s' "$UDATA" | $JQ -r '.uid // empty')
        UGROUPS=$(printf '%s' "$UDATA" | $JQ -r '.groups // [] | join(",")')

        # Add group entries
        printf '%s' "$UDATA" | $JQ -r '.groups // [] | .[]' | while IFS= read -r GRP; do
          # Check if group exists without grep (not in guest)
          GRP_EXISTS=0
          while IFS=: read -r g _rest; do
            if [ "$g" = "$GRP" ]; then GRP_EXISTS=1; break; fi
          done < /etc/group
          if [ "$GRP_EXISTS" = "0" ]; then
            printf '%s:x::%s\n' "$GRP" "$UNAME" >> /etc/group
          fi
        done

        # Add user to passwd if not exists (no grep in guest)
        UNAME_EXISTS=0
        while IFS=: read -r u _rest; do
          if [ "$u" = "$UNAME" ]; then UNAME_EXISTS=1; break; fi
        done < /etc/passwd
        if [ "$UNAME_EXISTS" = "0" ]; then
          UHOME="/home/$UNAME"
          if [ -n "$UUID" ]; then
            printf '%s:x:%s:%s::%s:/bin/sh\n' "$UNAME" "$UUID" "$UUID" "$UHOME" >> /etc/passwd
            printf '%s:x:%s:\n' "$UNAME" "$UUID" >> /etc/group
          else
            printf '%s:x:1000:1000::%s:/bin/sh\n' "$UNAME" "$UHOME" >> /etc/passwd
          fi
          printf '%s:!:1::::::\n' "$UNAME" >> /etc/shadow
          mkdir -p "$UHOME"
          echo "cloud-init-config: added user $UNAME"
        fi

        # SSH authorized keys
        HAS_KEYS=$(printf '%s' "$UDATA" | $JQ -r 'if .ssh_authorized_keys and (.ssh_authorized_keys | length > 0) then "yes" else "no" end')
        if [ "$HAS_KEYS" = "yes" ]; then
          KEYDIR="/etc/ssh/authorized_keys"
          mkdir -p "$KEYDIR"
          printf '%s' "$UDATA" | $JQ -r '.ssh_authorized_keys[]' > "$KEYDIR/$UNAME"
          chmod 644 "$KEYDIR/$UNAME"
          echo "cloud-init-config: wrote SSH keys for $UNAME"
        fi
      done
    fi

    # --- Firewall ---
    HAS_FW=$($JQ -r 'if .firewall then "yes" else "no" end' < "$USERDATA")
    if [ "$HAS_FW" = "yes" ]; then
      FW_TCP=$($JQ -r '.firewall.allowed_tcp // [22] | map(tostring) | join(", ")' < "$USERDATA")
      FW_UDP=$($JQ -r '.firewall.allowed_udp // [] | map(tostring) | join(", ")' < "$USERDATA")
      FW_FWD=$($JQ -r '.firewall.forward_policy // "drop"' < "$USERDATA")

      NFT_FILE="/etc/nftables.conf"
      cat > "$NFT_FILE" << NFTEOF
    flush ruleset

    table inet filter {
      chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
    NFTEOF

      if [ -n "$FW_TCP" ]; then
        printf '    tcp dport { %s } accept\n' "$FW_TCP" >> "$NFT_FILE"
      fi
      if [ -n "$FW_UDP" ]; then
        printf '    udp dport { %s } accept\n' "$FW_UDP" >> "$NFT_FILE"
      fi

      # Role-specific ports
      case "$ROLE" in
        k8s-worker)
          printf '    tcp dport { 10250, 30000-32767 } accept comment "K8s worker"\n' >> "$NFT_FILE"
          printf '    udp dport { 8472, 51871 } accept comment "VXLAN+WireGuard"\n' >> "$NFT_FILE"
          printf '    tcp dport { 4240, 4244, 4245 } accept comment "Cilium"\n' >> "$NFT_FILE"
          ;;
        k8s-control-plane)
          printf '    tcp dport { 10250, 30000-32767 } accept comment "K8s worker"\n' >> "$NFT_FILE"
          printf '    udp dport { 8472, 51871 } accept comment "VXLAN+WireGuard"\n' >> "$NFT_FILE"
          printf '    tcp dport { 4240, 4244, 4245 } accept comment "Cilium"\n' >> "$NFT_FILE"
          printf '    tcp dport { 6443, 2379, 2380, 10257, 10259 } accept comment "Control plane"\n' >> "$NFT_FILE"
          ;;
      esac

      cat >> "$NFT_FILE" << NFTEOF2
        log prefix "nft-drop: " flags all counter drop
      }
      chain forward {
        type filter hook forward priority 0; policy $FW_FWD;
        ct state established,related accept
        ct state invalid drop
      }
      chain output {
        type filter hook output priority 0; policy accept;
      }
    }
    NFTEOF2
      echo "cloud-init-config: wrote $NFT_FILE"
    fi

    # --- Kubernetes prerequisites (worker and control-plane roles) ---
    case "$ROLE" in
      k8s-worker|k8s-control-plane)
        # Kernel modules for k8s networking
        mkdir -p /etc/modules-load.d
        cat > /etc/modules-load.d/k8s.conf << 'MODEOF'
    br_netfilter
    overlay
    vxlan
    MODEOF

        # Sysctl for k8s networking
        mkdir -p /etc/sysctl.d
        cat > /etc/sysctl.d/90-k8s.conf << 'SYSCTLEOF'
    net.ipv4.ip_forward = 1
    net.bridge.bridge-nf-call-iptables = 1
    net.bridge.bridge-nf-call-ip6tables = 1
    SYSCTLEOF

        echo "cloud-init-config: wrote k8s kernel prereqs"

        # --- Containerd config ---
        HAS_CONTAINERD=$($JQ -r 'if .kubernetes.containerd then "yes" else "no" end' < "$USERDATA")
        SNAP="overlayfs"
        if [ "$HAS_CONTAINERD" = "yes" ]; then
          SNAP=$($JQ -r '.kubernetes.containerd.snapshotter // "overlayfs"' < "$USERDATA")
        fi

        mkdir -p /etc/containerd
        cat > /etc/containerd/config.toml << CTDEOF
    version = 2
    root = "/var/lib/containerd"
    state = "/run/containerd"

    [grpc]
      address = "/run/containerd/containerd.sock"

    [plugins]
      [plugins."io.containerd.grpc.v1.cri"]
        sandbox_image = "registry.k8s.io/pause:3.10"
        [plugins."io.containerd.grpc.v1.cri".containerd]
          snapshotter = "$SNAP"
          default_runtime_name = "runc"
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes]
            [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
              runtime_type = "io.containerd.runc.v2"
              [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
                SystemdCgroup = true
        [plugins."io.containerd.grpc.v1.cri".cni]
          bin_dir = "/opt/cni/bin"
          conf_dir = "/etc/cni/net.d"
    CTDEOF

        # Registry mirrors
        HAS_MIRRORS=$($JQ -r 'if .kubernetes.registry_mirrors and (.kubernetes.registry_mirrors | length > 0) then "yes" else "no" end' < "$USERDATA")
        if [ "$HAS_MIRRORS" = "yes" ]; then
          $JQ -r '.kubernetes.registry_mirrors | to_entries[] | "\(.key) \(.value)"' < "$USERDATA" | while IFS=' ' read -r REG MIRROR; do
            cat >> /etc/containerd/config.toml << MIREOF
        [plugins."io.containerd.grpc.v1.cri".registry.mirrors."$REG"]
          endpoint = ["$MIRROR"]
    MIREOF
          done
        fi

        echo "cloud-init-config: wrote containerd config"

        # --- K3s config ---
        mkdir -p /etc/rancher/k3s
        ;;
    esac

    # K3s server config (control-plane)
    if [ "$ROLE" = "k8s-control-plane" ]; then
      K3S_CFG="/etc/rancher/k3s/config.yaml"
      : > "$K3S_CFG"

      CLUSTER_INIT=$($JQ -r '.kubernetes.cluster_init // false' < "$USERDATA")
      if [ "$CLUSTER_INIT" = "true" ]; then
        printf 'cluster-init: true\n' >> "$K3S_CFG"
      fi

      SERVER_URL=$($JQ -r '.kubernetes.server_url // empty' < "$USERDATA")
      if [ -n "$SERVER_URL" ]; then
        printf 'server: %s\n' "$SERVER_URL" >> "$K3S_CFG"
      fi

      TOKEN_FILE=$($JQ -r '.kubernetes.token_file // empty' < "$USERDATA")
      if [ -n "$TOKEN_FILE" ]; then
        printf 'token-file: %s\n' "$TOKEN_FILE" >> "$K3S_CFG"
      fi

      DISABLE_KP=$($JQ -r '.kubernetes.disable_kube_proxy // false' < "$USERDATA")
      if [ "$DISABLE_KP" = "true" ]; then
        printf 'disable-kube-proxy: true\n' >> "$K3S_CFG"
      fi

      CLUSTER_CIDR=$($JQ -r '.kubernetes.cluster_cidr // empty' < "$USERDATA")
      if [ -n "$CLUSTER_CIDR" ]; then
        printf 'cluster-cidr: %s\n' "$CLUSTER_CIDR" >> "$K3S_CFG"
      fi

      SERVICE_CIDR=$($JQ -r '.kubernetes.service_cidr // empty' < "$USERDATA")
      if [ -n "$SERVICE_CIDR" ]; then
        printf 'service-cidr: %s\n' "$SERVICE_CIDR" >> "$K3S_CFG"
      fi

      # TLS SANs
      HAS_SANS=$($JQ -r 'if .kubernetes.tls_san and (.kubernetes.tls_san | length > 0) then "yes" else "no" end' < "$USERDATA")
      if [ "$HAS_SANS" = "yes" ]; then
        printf 'tls-san:\n' >> "$K3S_CFG"
        $JQ -r '.kubernetes.tls_san[]' < "$USERDATA" | while IFS= read -r SAN; do
          printf '  - %s\n' "$SAN" >> "$K3S_CFG"
        done
      fi

      # Node labels
      HAS_LABELS=$($JQ -r 'if .kubernetes.node_labels and (.kubernetes.node_labels | length > 0) then "yes" else "no" end' < "$USERDATA")
      if [ "$HAS_LABELS" = "yes" ]; then
        printf 'node-label:\n' >> "$K3S_CFG"
        $JQ -r '.kubernetes.node_labels | to_entries[] | "  - \(.key)=\(.value)"' < "$USERDATA" >> "$K3S_CFG"
      fi

      echo "cloud-init-config: wrote k3s server config"
    fi

    # K3s agent config (worker)
    if [ "$ROLE" = "k8s-worker" ]; then
      K3S_CFG="/etc/rancher/k3s/config.yaml"
      : > "$K3S_CFG"

      SERVER_URL=$($JQ -r '.kubernetes.server_url // empty' < "$USERDATA")
      if [ -n "$SERVER_URL" ]; then
        printf 'server: %s\n' "$SERVER_URL" >> "$K3S_CFG"
      fi

      TOKEN_FILE=$($JQ -r '.kubernetes.token_file // empty' < "$USERDATA")
      if [ -n "$TOKEN_FILE" ]; then
        printf 'token-file: %s\n' "$TOKEN_FILE" >> "$K3S_CFG"
      fi

      # Node labels
      HAS_LABELS=$($JQ -r 'if .kubernetes.node_labels and (.kubernetes.node_labels | length > 0) then "yes" else "no" end' < "$USERDATA")
      if [ "$HAS_LABELS" = "yes" ]; then
        printf 'node-label:\n' >> "$K3S_CFG"
        $JQ -r '.kubernetes.node_labels | to_entries[] | "  - \(.key)=\(.value)"' < "$USERDATA" >> "$K3S_CFG"
      fi

      # K3s agent unit file (not started — just written)
      mkdir -p /etc/systemd/system
      cat > /etc/systemd/system/k3s-agent.service << 'K3SEOF'
    [Unit]
    Description=K3s Agent
    After=network-online.target containerd.service
    Wants=network-online.target containerd.service

    [Service]
    Type=notify
    ExecStart=/usr/bin/k3s agent --config /etc/rancher/k3s/config.yaml
    Restart=always
    RestartSec=5s
    KillMode=process
    LimitNOFILE=1048576
    LimitNPROC=infinity
    LimitCORE=infinity
    TasksMax=infinity

    [Install]
    WantedBy=multi-user.target
    K3SEOF
      echo "cloud-init-config: wrote k3s agent config and unit"
    fi

    echo "done" > "$STATE/config-done"
    echo "cloud-init-config: complete"
  '';

  # Stage 4: final (after config)
  # Reloads nftables if changed, writes boot-finished marker.
  finalScript = ''
    #!/bin/sh
    set -eu
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    USERDATA="${userDataFile}"
    STATE="${stateDir}"
    JQ="${jqBin}"
    mkdir -p "$STATE"

    ROLE=$(cat "$STATE/active-role" 2>/dev/null || echo "server")

    # Reload nftables if cloud-init wrote a new config
    if [ -f "$STATE/config-done" ]; then
      HAS_FW="no"
      if [ -f "$USERDATA" ]; then
        HAS_FW=$($JQ -r 'if .firewall then "yes" else "no" end' < "$USERDATA")
      fi
      # Also reload for k8s roles (which write role-specific rules)
      case "$ROLE" in
        k8s-worker|k8s-control-plane)
          HAS_FW="yes"
          ;;
      esac

      if [ "$HAS_FW" = "yes" ] && [ -f /etc/nftables.conf ]; then
        if command -v nft >/dev/null 2>&1; then
          nft -f /etc/nftables.conf && echo "cloud-init-final: reloaded nftables" || echo "cloud-init-final: nftables reload failed (non-fatal)"
        fi
      fi
    fi

    # Write boot-finished marker
    echo "done" > "$STATE/boot-finished"
    echo "cloud-init-final: boot-finished"
  '';
in {
  options.aos.services.cloudInit = {
    ## Enable the cloud-init service for runtime configuration.
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Enable cloud-init for runtime system configuration. Reads JSON
        userdata from the NoCloud seed directory and configures hostname,
        networking, users, firewall, and Kubernetes settings at boot.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [pkgs.jq];

    # Stage scripts in /etc/aos/cloud-init/
    # Note: build module doesn't support mode, so ExecStart uses /bin/sh explicitly.
    environment.etc."aos/cloud-init/local.sh" = {
      text = localScript;
    };
    environment.etc."aos/cloud-init/network.sh" = {
      text = networkScript;
    };
    environment.etc."aos/cloud-init/config.sh" = {
      text = configScript;
    };
    environment.etc."aos/cloud-init/final.sh" = {
      text = finalScript;
    };

    # Ensure cloud state directories exist.
    environment.etc."tmpfiles.d/aos-cloud-init.conf" = {
      text = ''
        d ${stateDir} 0755 root root -
        d ${seedDir} 0755 root root -
        d /etc/rancher/k3s 0755 root root -
      '';
    };

    # Stage 1: cloud-init-local (before networking)
    systemd.services."cloud-init-local" = {
      description = "Cloud-Init Local Stage (hostname, network config)";
      wantedBy = ["multi-user.target"];
      before = [
        "systemd-networkd.service"
        "cloud-init-network.service"
      ];
      after = ["local-fs.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "/bin/sh /etc/aos/cloud-init/local.sh";
      };
    };

    # Stage 2: cloud-init-network (role detection)
    systemd.services."cloud-init-network" = {
      description = "Cloud-Init Network Stage (role detection)";
      wantedBy = ["multi-user.target"];
      after = [
        "cloud-init-local.service"
        "network-online.target"
      ];
      wants = ["network-online.target"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "/bin/sh /etc/aos/cloud-init/network.sh";
      };
    };

    # Stage 3: cloud-init-config (users, ssh keys, firewall, k8s)
    systemd.services."cloud-init-config" = {
      description = "Cloud-Init Config Stage (users, firewall, k8s config)";
      wantedBy = ["multi-user.target"];
      after = ["cloud-init-network.service"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "/bin/sh /etc/aos/cloud-init/config.sh";
      };
    };

    # Stage 4: cloud-init-final (reload services, boot-finished)
    systemd.services."cloud-init-final" = {
      description = "Cloud-Init Final Stage (service reload, boot marker)";
      wantedBy = ["multi-user.target"];
      after = ["cloud-init-config.service"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "/bin/sh /etc/aos/cloud-init/final.sh";
      };
    };
  };
}
