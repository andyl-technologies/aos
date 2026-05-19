##! modules/roles/kubernetes/k3s-control-plane.nix — k3s control plane.
##!
##! `k3s server --disable-agent`: API server + scheduler +
##! controller-manager + (embedded) etcd or SQLite, no kubelet.
##!
##! Host-specific values come from /etc/rancher/k3s/k3s.env, which
##! the operator's ignition userdata writes via `storage.files`.
##! Required keys: K3S_TOKEN. Optional: K3S_URL (HA join),
##! K3S_NODE_NAME, K3S_NODE_IP.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.roles.k3s-control-plane;
  common = import ./_k3s-common.nix {inherit lib pkgs;};
  required = ["K3S_TOKEN"];
in {
  config = lib.mkMerge [
    {
      aos.roles.k3s-control-plane = {
        # Kernel + firewall config — set unconditionally so they ride
        # the role's ignitionConfig and take effect at runtime only
        # when this role's ignition config is merged into the host's.
        kernel.modules = common.kernelModules;
        kernel.sysctl = common.sysctls;

        # Pod traffic does NOT traverse a control-plane-only node, so
        # `forwardPolicy` stays at its "drop" default. We DO need
        # 6443/TCP open for the API server.
        #
        # Not opened by default (uncomment if your deployment actually
        # uses them):
        #   - 9345/tcp:      k3s server's supervisor port, required
        #                    for HA join when additional servers point
        #                    at this one via `--server` / `K3S_URL`.
        #   - 2379-2380/tcp: etcd peer + client — only exposed between
        #                    control-plane members in HA-with-embedded-
        #                    etcd mode.
        firewall.allowedTCP = [6443];

        # The whole preflight unit (description, ordering, condition,
        # EnvironmentFile, script body) lives in `_k3s-common.nix`
        # — see `preflightService` there for the rationale. We pass
        # in the role name (used in the unit description and error
        # messages) and the env-file keys this role requires.
        systemd.services.k3s-preflight =
          common.preflightService "k3s-control-plane" required;

        systemd.services.k3s = {
          description = "Lightweight Kubernetes (control plane, no agent)";
          enabled = true;
          wantedBy = ["multi-user.target"];
          after = ["network-online.target" "k3s-preflight.service"];
          wants = ["network-online.target"];
          # Requisite (not Requires): if k3s-preflight is not active,
          # don't attempt to start it from here — just fail
          # k3s.service immediately. Pairs with the `Before=` on
          # the preflight unit so multi-user.target schedules
          # them in the right order.
          requisite = ["k3s-preflight.service"];
          path = common.runtimePath;
          serviceConfig = {
            Type = "notify";
            EnvironmentFile = "/etc/rancher/k3s/k3s.env";
            ExecStart = "${pkgs.k3s}/bin/k3s server --disable-agent";
            KillMode = "process";
            Delegate = "yes";
            # Mirrors upstream's k3s.service comment: "Having
            # non-zero Limit*s causes performance problems due to
            # accounting overhead in the kernel. We recommend
            # using cgroups to do container-local accounting."
            # The infinity values here are the upstream defaults;
            # don't ratchet them down without understanding the
            # accounting trade-off.
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
      # All the binaries the unit references plus aos-friendly
      # operator tools.
      environment.systemPackages = common.runtimePath;
    })
  ];
}
