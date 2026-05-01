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
  common = import ./_k3s-common.nix {inherit lib pkgs;};
  required = ["K3S_TOKEN" "K3S_URL"];
in {
  config = lib.mkMerge [
    {
      aos.roles.k3s-worker = {
        # See `_k3s-common.nix`'s `preflightService` for the full
        # unit shape and rationale.
        systemd.services.k3s-preflight =
          common.preflightService "k3s-worker" required;

        systemd.services.k3s = {
          description = "Lightweight Kubernetes (agent / worker)";
          enabled = true;
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

    (lib.mkIf cfg.enable {
      aos.kernel.modules = common.kernelModules;
      aos.kernel.sysctl = common.sysctls;

      # Pod-to-pod traffic on a worker traverses the forward chain
      # (kube-proxy iptables mode + flannel's vxlan device). Switch
      # the default forward policy from drop to accept; kube-proxy's
      # own iptables chains in the `filter` table provide selective
      # blocking on top of that. Caveat: this assumes kube-proxy is
      # in iptables mode (the default). IPVS mode does NOT install
      # equivalent filter-chain rules — if a future role enables
      # IPVS, we'd need to revisit.
      #
      # Plain assignment, NOT `lib.mkForce`: the option's default
      # in `modules/security/firewall.nix` is set in the mkOption
      # declaration (option-level priority), so a normal role-level
      # assignment already wins over it. Using `mkForce` here would
      # also mask any future site-local operator override, which we
      # don't want.
      aos.firewall.forwardPolicy = "accept";

      # 10250: kubelet (apiserver's `kubectl logs` / `kubectl exec`
      #        reverse channel).
      # 8472/udp: flannel VXLAN — only between nodes on the same L2.
      #
      # Not opened by default (uncomment if your deployment
      # actually uses them):
      #   - 10256/tcp: kube-proxy healthz endpoint, sometimes
      #                probed by external load balancers.
      #   - 51820/udp: flannel WireGuard backend (only with
      #                `flannel-backend=wireguard-native`).
      aos.firewall.allowedTCP = [10250];
      aos.firewall.allowedUDP = [8472];

      environment.systemPackages = common.runtimePath;
    })
  ];
}
