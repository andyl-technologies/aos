##! modules/roles/kubernetes/k3s-worker.nix — k3s agent (worker).
##!
##! `k3s agent`: kubelet + kube-proxy + flannel daemon + containerd,
##! no control-plane components.
##!
##! Required env-file vars: K3S_TOKEN, K3S_URL.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.roles.k3s-worker;
  common = import ../../../pkgs/kubernetes/_k3s-common.nix {inherit lib pkgs;};
  required = ["K3S_TOKEN" "K3S_URL"];
in {
  config = lib.mkMerge [
    {
      aos.roles.k3s-worker = {
        # Kernel + firewall config — set unconditionally so they ride
        # the role's ignitionConfig (bundled on hosts where
        # `bundle = true`) and take effect at runtime only when the
        # fragment is merged into the host's ignition config.
        kernel.modules = common.kernelModules;
        kernel.sysctl = common.sysctls;

        # Pod-to-pod traffic on a worker traverses the forward chain
        # (kube-proxy iptables mode + flannel's vxlan device), so the
        # role opens forwarding. Caveat: this assumes kube-proxy is in
        # iptables mode (the default). IPVS mode does NOT install
        # equivalent filter-chain rules — if a future role enables
        # IPVS, we'd need to revisit.
        #
        # 10250: kubelet (apiserver's `kubectl logs` / `kubectl exec`
        #        reverse channel).
        # 8472/udp: flannel VXLAN — only between nodes on the same L2.
        #
        # Not opened by default (uncomment if your deployment actually
        # uses them):
        #   - 10256/tcp: kube-proxy healthz endpoint, sometimes probed
        #                by external load balancers.
        #   - 51820/udp: flannel WireGuard backend (only with
        #                `flannel-backend=wireguard-native`).
        firewall.allowedTCP = [10250];
        firewall.allowedUDP = [8472];
        firewall.forwardPolicy = "accept";

        # See `_k3s-common.nix`'s `preflightService` for the full
        # unit shape and rationale.
        systemd.services.k3s-preflight =
          common.preflightService "k3s-worker" required;

        systemd.services.k3s = {
          description = "Lightweight Kubernetes (agent / worker)";
          wantedBy = ["multi-user.target"];
          after = ["network-online.target" "k3s-preflight.service"];
          wants = ["network-online.target"];
          requisite = ["k3s-preflight.service"];
          path = common.runtimePath;
          serviceConfig = {
            Type = "notify";
            EnvironmentFile = "/etc/rancher/k3s/k3s.env";
            ExecStart = "${pkgs.k3s}/bin/k3s agent";
            KillMode = "process";
            Delegate = "yes";
            LimitNOFILE = "1048576";
            LimitNPROC = "infinity";
            LimitCORE = "infinity";
            TasksMax = "infinity";
            TimeoutStartSec = "infinity";
            Restart = "always";
            RestartSec = "5s";
          };
        };
      };
    }

    (lib.mkIf cfg.bundle {
      environment.systemPackages = common.runtimePath;
    })
  ];
}
