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
  common = import ../../../pkgs/kubernetes/_k3s-common.nix {inherit lib pkgs;};
  required = ["K3S_TOKEN"];
in {
  config = lib.mkMerge [
    {
      aos.roles.k3s-combined = {
        # Kernel + firewall config — set unconditionally so they ride
        # the role's ignitionConfig (bundled on hosts where
        # `bundle = true`) and take effect at runtime only when the
        # fragment is merged into the host's ignition config.
        kernel.modules = common.kernelModules;
        kernel.sysctl = common.sysctls;

        # See the rationale in k3s-worker.nix for the forwardPolicy
        # choice and the IPVS-mode caveat. Union of the control-plane
        # and worker port lists.
        firewall.allowedTCP = [6443 10250];
        firewall.allowedUDP = [8472];
        firewall.forwardPolicy = "accept";

        systemd.services.k3s-preflight =
          common.preflightService "k3s-combined" required;

        systemd.services.k3s = {
          description = "Lightweight Kubernetes (combined: server + agent)";
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

    (lib.mkIf cfg.bundle {
      environment.systemPackages = common.runtimePath;
    })
  ];
}
