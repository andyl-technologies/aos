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
  # host-firewall tool consumed by the selected network-ruleset provider;
  # k3s itself only needs
  # `iptables`. Including nftables would also make k3s's
  # iptables-availability probe potentially auto-detect nftables
  # mode in some k3s versions — best avoided.

  launcher = role: command:
    pkgs.writeShellScriptBin "k3s-${role}-start" ''
      set -eu

      # The package check uses this side-effect-free path to prove that this
      # exact production launcher executes its retained k3s payload.
      if [ "''${1:-}" = verify-payload ]; then
        [ "$#" -eq 2 ]
        [ "$2" = ${lib.escapeShellArg "${pkgs.k3s}/bin/k3s"} ]
        "$2" --version >/dev/null
        printf '%s\n' k3s-payload-ok
        exit 0
      fi

      if [ "$#" -ne 2 ]; then
        echo "[k3s] ${role}: expected configuration and token credential paths" >&2
        exit 64
      fi
      configuration=$1
      token_file=$2
      shift 2
      if [ ! -r "$configuration" ]; then
        echo "[k3s] ${role}: configuration is not readable" >&2
        exit 1
      fi
      if [ ! -r "$token_file" ]; then
        echo "[k3s] ${role}: token credential is not readable" >&2
        exit 1
      fi

      export K3S_TOKEN_FILE="$token_file"

      exec ${pkgs.k3s}/bin/k3s ${command} --config "$configuration" "$@"
    '';
}
