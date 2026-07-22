##! modules/systemd/graph.nix — systemd unit-graph templates for generation zero
##!
##! Bakes the static surface of the on-host config unit graph into the image:
##! the `aos-pkg-fetch@.service` / `aos-pkg-install@.service` templates and the
##! `aos-fetch` / `aos-config-render` / `aos-config` targets. At runtime
##! `aos-graph-compile.service` (`apm __graph-compile`) writes only the tiny
##! per-instance dropins + `.wants/` symlinks under `/run/systemd/system`, then
##! `daemon-reload`s and starts `aos-config.target` (orchestration.md,
##! build-spec §"Systemd unit-graph compiler").
##!
##! This is the package orchestration path and is emitted
##! for every AOS system.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.config.unitGraph;
  apm = "${pkgs.aos}/bin/apm";
in {
  options.aos.config.unitGraph = {
    manifest = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos/manifest.json";
      description = "The eval-produced data contract the compiler reads.";
    };

    graph = lib.mkOption {
      type = lib.types.str;
      default = "/run/aos/graph.json";
      description = "The eval-produced cross-package DAG the compiler reads.";
    };
  };

  config = {
    systemd.services = {
      # ---- aos-pkg-fetch@.service (template) -------------------------------
      # Network-only; carries NO config edges (downloads are order-independent,
      # build-spec §3). Bounded retry budget so a permanently-bad package
      # degrades rather than spins forever (recovery ladder rung 1).
      "aos-pkg-fetch@" = {
        description = "Fetch AOS package closure %i";
        wantedBy = [];
        wants = ["network-online.target"];
        after = ["network-online.target"];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${apm} fetch %i";
          Restart = "on-failure";
          RestartSec = "5s";
          StartLimitIntervalSec = "120s";
          StartLimitBurst = 5;
          TimeoutStartSec = "180s";
          PrivateTmp = true;
          ProtectSystem = "strict";
          ReadWritePaths = ["/nix" "/run/aos"];
          NoNewPrivileges = true;
        };
      };

      # ---- aos-pkg-install@.service (template) -----------------------------
      # Render is local (validate against signed expose.config, stage the
      # artifact). NO Restart=: a render failure is a permanent config error,
      # not a transient. Per-instance edges (config After=/Wants= + the
      # After=aos-pkg-fetch@%i.service self-edge) are added by the generated
      # dropin; the static body declares neither.
      "aos-pkg-install@" = {
        description = "Render AOS package config %i";
        wantedBy = [];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${apm} render-one %i";
          TimeoutStartSec = "60s";
          PrivateTmp = true;
          NoNewPrivileges = true;
        };
      };

      # ---- aos-graph-compile.service ---------------------------------------
      # Parse manifest.json + graph.json → write /run/systemd/system dropins +
      # .wants → daemon-reload → start --no-block aos-config.target. A missing
      # manifest makes this a clean no-op (the box stays on the gen-0 seed).
      aos-graph-compile = {
        description = "Compile the AOS config eval output into a systemd unit graph";
        wantedBy = ["multi-user.target"];
        after = ["aos-eval.service"];
        wants = ["aos-eval.service"];
        unitConfig.ConditionPathExists = cfg.manifest;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${apm} __graph-compile --manifest ${cfg.manifest} --graph ${cfg.graph}";
        };
      };
    };

    # ---- the three passive targets (static) --------------------------------
    # No static Wants= on any instance — the instance set is unknown at image
    # build time. All target→instance edges are runtime `.wants/` symlinks, and
    # `Wants=` only (one failed instance never fails its target, build-spec §3).
    systemd.targets = {
      aos-fetch = {
        description = "AOS package fetch wing";
        wantedBy = [];
      };
      aos-config-render = {
        description = "AOS package render wing";
        after = ["aos-fetch.target"];
        wantedBy = [];
      };
      aos-config = {
        description = "AOS on-host config applied";
        after = ["aos-config-render.target"];
        wants = ["aos-config-render.target" "aos-fetch.target"];
        wantedBy = [];
      };
    };
  };
}
