##! modules/roles/kubernetes/k3s-combined.nix — k3s server +
##! agent in one process (single-node or all-in-one cluster).
##!
##! `k3s server` (no --disable-agent) → API server + scheduler +
##! controller-manager + datastore + kubelet + kube-proxy +
##! flannel daemon, all on this host.
##!
##! Required env-file vars: K3S_TOKEN. Optional: K3S_URL (HA join).
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.roles.k3s-combined;
  common = import ./_k3s-common.nix {inherit lib pkgs;};
  required = ["K3S_TOKEN"];
in {
  config = lib.mkMerge [
    {
      aos.roles.k3s-combined = {
        systemd.services.k3s-preflight =
          common.preflightService "k3s-combined" required;

        systemd.services.k3s = {
          description = "Lightweight Kubernetes (combined: server + agent)";
          enabled = true;
          wantedBy = ["multi-user.target"];
          after = ["network-online.target" "k3s-preflight.service"];
          wants = ["network-online.target"];
          requisite = ["k3s-preflight.service"];
          path = common.runtimePath;
          serviceConfig = {
            Type = "notify";
            EnvironmentFile = "/etc/rancher/k3s/k3s.env";
            ExecStart = "${pkgs.k3s}/bin/k3s server";
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

      # See the rationale in k3s-worker.nix for the forwardPolicy
      # choice and the IPVS-mode caveat. Plain assignment, no
      # mkForce.
      aos.firewall.forwardPolicy = "accept";

      # Union of the control-plane and worker port lists.
      aos.firewall.allowedTCP = [6443 10250];
      aos.firewall.allowedUDP = [8472];

      environment.systemPackages = common.runtimePath;
    })
  ];
}
