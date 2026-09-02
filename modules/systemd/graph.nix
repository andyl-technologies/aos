##! modules/systemd/graph.nix — systemd unit-graph templates for generation zero
##!
##! Bakes the static surface of the on-host config unit graph into the image:
##! the `aos-pkg-fetch@.service` / `aos-pkg-install@.service` templates and the
##! `aos-fetch` / `aos-config-render` / `aos-config` targets. At runtime
##! `aos-graph-compile.service` (`aos-package-runtime __graph-compile`) writes
##! only the tiny
##! per-instance dropins + `.wants/` symlinks under `/run/systemd/system`, then
##! `daemon-reload`s, awaits `aos-activate.service`, and publishes
##! `aos-config.target` (orchestration.md,
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
  packageRuntime = "${pkgs.aos}/bin/aos-package-runtime";
  attestationQuoteArg =
    lib.optionalString config.aos.boot.secureBoot.measuredBoot.enable
    "--require-attestation-quote";
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
        unitConfig = {
          StartLimitIntervalSec = "120s";
          StartLimitBurst = 5;
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${packageRuntime} fetch %i";
          Restart = "on-failure";
          RestartSec = "5s";
          TimeoutStartSec = "180s";
          PrivateTmp = true;
          ProtectSystem = "strict";
          ReadWritePaths = ["/nix" "/run/aos" "/var/lib/apm"];
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
          ExecStart = "${packageRuntime} render-one %i";
          TimeoutStartSec = "60s";
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          ReadWritePaths = ["/run/aos"];
          NoNewPrivileges = true;
          UMask = "0077";
        };
      };

      # ---- aos-graph-compile.service ---------------------------------------
      # Parse manifest.json + graph.json → write /run/systemd/system dropins +
      # .wants → daemon-reload → await activation → publish
      # aos-config.target. A missing manifest makes this a clean no-op (the box
      # stays on the generation-zero seed).
      aos-graph-compile = {
        description = "Compile the AOS config eval output into a systemd unit graph";
        wantedBy = ["multi-user.target"];
        before = ["aos-preset.service" "multi-user.target"];
        after = ["aos-eval.service"];
        wants = ["aos-eval.service"];
        unitConfig = {
          ConditionPathExists = cfg.manifest;
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = "${packageRuntime} __graph-compile --manifest ${cfg.manifest} --graph ${cfg.graph}";
          PrivateTmp = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          ReadWritePaths = ["/run/aos" "/run/systemd/system"];
          NoNewPrivileges = true;
          UMask = "0077";
        };
      };

      # ---- aos-activate.service -------------------------------------------
      # The target pulls this in only after the soft fetch/render wing. A
      # missing marker never makes the wing hard-fail: the commit command
      # re-projects the manifest onto the successful subset, records the
      # dropped closure, then invokes the toplevel's atomic activation script.
      aos-activate = {
        description = "Commit the evaluated AOS host configuration";
        wantedBy = [];
        wants = ["aos-config-render.target" "aos-fetch.target"];
        after = [
          "aos-config-render.target"
          "aos-fetch.target"
          "aos-seed-profiles.service"
        ];
        before = ["aos-preset.service"];
        unitConfig = {
          ConditionPathExists = cfg.manifest;
          StartLimitIntervalSec = "30s";
          StartLimitBurst = 3;
        };
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          Restart = "on-failure";
          RestartSec = "2s";
          RestartPreventExitStatus = "4";
          TimeoutStartSec = "180s";
        };
        script = ''
          set +e
          ${packageRuntime} __activate-config \
            --manifest ${cfg.manifest} \
            --graph ${cfg.graph} \
            --module-abi ${toString config.aos.system.moduleAbi} ${attestationQuoteArg}
          rc=$?
          set -e
          if [ "$rc" -eq 4 ]; then
            echo "aos-activate: /etc swap is indeterminate; entering rescue mode" >&2
            ${pkgs.systemd}/bin/systemctl --no-block isolate rescue.target
          fi
          if [ "$rc" -eq 6 ]; then
            # The transaction committed after dropping unavailable package
            # projections. Keep the degraded outcome in activation.json while
            # allowing the ordering service and aos-config.target to settle.
            echo "aos-activate: committed a degraded host configuration" >&2
            exit 0
          fi
          exit "$rc"
        '';
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
        after = ["aos-activate.service"];
        requires = ["aos-activate.service"];
        wantedBy = [];
      };
    };
  };
}
