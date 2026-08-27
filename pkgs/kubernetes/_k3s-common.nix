{
  lib,
  pkgs,
}: let
  k3sModprobe = pkgs.writeShellScriptBin "modprobe" ''
    set -eu

    handled=false
    for arg in "$@"; do
      case "$arg" in
        -*)
          ;;
        nft-expr-counter)
          handled=true
          ;;
        *)
          handled=false
          break
          ;;
      esac
    done
    if [ "$handled" = true ]; then
      exit 0
    fi

    exec ${pkgs.kmod}/sbin/modprobe "$@"
  '';
in {
  runtimePath = [
    pkgs.k3s
    pkgs.containerd # provides containerd-shim-runc-v2
    pkgs.runc
    pkgs.cni-plugins # bridge, host-local, portmap, loopback
    pkgs.iptables # kube-proxy iptables mode + kube-router netpol
    pkgs.ipset # k3s netpol controller
    pkgs.conntrack-tools
    pkgs.socat
    pkgs.ethtool
    pkgs.iproute2
    pkgs.util-linux # mount/umount/findmnt
    # Linux 6.18 folds the nft counter expression into nf_tables core, but
    # kube-proxy still probes its historical loadable alias.
    k3sModprobe
    pkgs.kmod # modprobe/lsmod
    pkgs.coreutils
  ];
  # Note: `pkgs.nftables` is intentionally NOT here. It's the
  # host-firewall tool (consumed by `nftables.service` from
  # `modules/security/firewall.nix`); k3s itself only needs
  # `iptables`. Including nftables would also make k3s's
  # iptables-availability probe potentially auto-detect nftables
  # mode in some k3s versions — best avoided.

  kernelModules = [
    "br_netfilter"
    "vxlan" # flannel default (VXLAN) backend
    "ip_set" # k3s netpol controller
  ];

  # Forwarding + bridge call-iptables. `bridge.bridge-nf-call-*`
  # only exist once br_netfilter is loaded; the stock
  # systemd-sysctl.service is ordered After=systemd-modules-load.service,
  # so as long as br_netfilter is in the module list above it loads
  # first and these keys are writable when systemd-sysctl runs.
  sysctls = {
    "net.ipv4.ip_forward" = "1";
    "net.ipv6.conf.all.forwarding" = "1";
    "net.bridge.bridge-nf-call-iptables" = "1";
    "net.bridge.bridge-nf-call-ip6tables" = "1";
  };

  preflightService = role: required: let
    enabledCheck = pkgs.writeShellScriptBin "k3s-${role}-enabled" ''
      set -eu

      [ "''${K3S_ENABLED:-false}" = true ]
    '';
    checks =
      lib.concatMapStringsSep "\n" (varName: ''
        : "''${${varName}:?[k3s-preflight] ${role}: ${varName} must be set in /etc/aos/packages/${role}/k3s.env}"
      '')
      required;
  in {
    description = "Pre-flight checks for ${role}";

    # `wantedBy` + `before` schedule preflight first under
    # `multi-user.target`; the matching `requisite` /
    # `after = [...preflight.service]` sit on the role's
    # `k3s.service` (declared inline per role, since k3s.service
    # itself diverges between roles in `ExecStart` and ports).
    wantedBy = ["multi-user.target"];
    before = ["k3s.service"];

    unitConfig = {
      # No env file → unit goes to "skipped (Condition not met)"
      # instead of running the script. `is-active` then reports
      # "inactive", and k3s.service's `Requisite=` refuses to
      # start. Net effect: a stock image with no operator-supplied
      # k3s.env stays in `inactive (dead)` cleanly — no script
      # invocation, no scary journal stack trace, no restart loop.
      ConditionPathExists = "/etc/aos/packages/${role}/k3s.env";
    };

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      EnvironmentFile = "/etc/aos/packages/${role}/k3s.env";
      ExecCondition = "${enabledCheck}/bin/k3s-${role}-enabled";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };

    script = ''
      set -eu

      ${checks}

      echo "[k3s-preflight] ${role}: required env present, k3s may start"
    '';
  };

  launcher = role: command:
    pkgs.writeShellScriptBin "k3s-${role}-start" ''
      set -eu

      : "''${CREDENTIALS_DIRECTORY:?[k3s] ${role}: token credential was not loaded}"
      token_file="$CREDENTIALS_DIRECTORY/token"
      if [ ! -r "$token_file" ]; then
        echo "[k3s] ${role}: token credential is not readable" >&2
        exit 1
      fi

      export K3S_TOKEN_FILE="$token_file"
      exec ${pkgs.k3s}/bin/k3s ${command} "$@"
    '';
}
