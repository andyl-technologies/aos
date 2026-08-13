{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostReadiness",
  taskIds ? ["T-GHC-3"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  };

  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  model = import ./_crucible-model-source.nix {inherit lib;};
  trigger = import ./_crucible-trigger-source.nix {inherit lib;};
  readinessTest = builtins.readFile ../../crates/crucible/tests/guest_host_readiness.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-3 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostReadiness`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "guest-host phase4 task range";
        needle = "Guest↔host channel + optional agent";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "fixed icount ready point";
        needle = "ReadyPoint::FixedIcount";
      }
      {
        label = "network idle ready point";
        needle = "ReadyPoint::NetworkIdle";
      }
      {
        label = "console marker ready point";
        needle = "ReadyPoint::ConsoleMarker";
      }
      {
        label = "ready point material hash input";
        needle = "fn ready_point_material(ready_point: &ReadyPoint) -> String";
      }
      {
        label = "network idle zero-window validation error";
        needle = "ReadyPointNetworkIdleWindowZero";
      }
      {
        label = "network idle no-link validation error";
        needle = "ReadyPointNetworkIdleWithoutLinks";
      }
      {
        label = "console marker empty validation error";
        needle = "ReadyPointConsoleMarkerEmpty";
      }
    ]
    ++ failuresFor "crates/crucible/src/trigger.rs" trigger [
      {
        label = "ready point resolver";
        needle = "pub fn resolve_ready_point";
      }
      {
        label = "ready point resolution type";
        needle = "pub struct ReadyPointResolution";
      }
      {
        label = "ready point resolution kind";
        needle = "pub enum ReadyPointResolutionKind";
      }
      {
        label = "ready point resolution errors";
        needle = "pub enum ReadyPointResolutionError";
      }
      {
        label = "fixed icount resolution";
        needle = "ReadyPointResolutionKind::FixedIcount";
      }
      {
        label = "network idle resolution";
        needle = "resolve_network_idle_ready_point";
      }
      {
        label = "console marker resolution";
        needle = "resolve_console_marker_ready_point";
      }
      {
        label = "icount to virtual conversion";
        needle = "to_virtual(shift)";
      }
      {
        label = "virtual to icount conversion";
        needle = "to_icount_ceil(shift)";
      }
      {
        label = "agent signal rejection";
        needle = "AgentSignalRequiresWhiteBoxChannel";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "ready point resolver export";
        needle = "resolve_ready_point";
      }
      {
        label = "ready point resolution export";
        needle = "ReadyPointResolution";
      }
      {
        label = "ready point resolution error export";
        needle = "ReadyPointResolutionError";
      }
      {
        label = "ready point resolution kind export";
        needle = "ReadyPointResolutionKind";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_host_readiness.rs" readinessTest [
      {
        label = "fixed icount test";
        needle = "fixed_icount_readiness_resolves_to_deterministic_icount_and_virtual_time";
      }
      {
        label = "shifted black-box coherent boundary test";
        needle = "shifted_black_box_readiness_reports_one_coherent_icount_boundary";
      }
      {
        label = "console marker test";
        needle = "console_marker_readiness_resolves_from_host_side_output_stream";
      }
      {
        label = "same-time console canonicalization test";
        needle = "console_marker_readiness_canonicalizes_same_time_chunks";
      }
      {
        label = "console marker frontier test";
        needle = "console_marker_readiness_ignores_observations_after_frontier";
      }
      {
        label = "network idle test";
        needle = "network_idle_readiness_resolves_first_quiescent_link_window";
      }
      {
        label = "same-tick network activity test";
        needle = "network_idle_readiness_treats_same_tick_activity_as_not_idle";
      }
      {
        label = "validation rejection test";
        needle = "readiness_validation_rejects_nondeterministic_or_degenerate_parameters";
      }
      {
        label = "agent signal rejection test";
        needle = "agent_signal_readiness_is_not_black_box_resolvable";
      }
      {
        label = "network idle not reached assertion";
        needle = "NetworkIdleWindowNotReached";
      }
      {
        label = "network idle zero-window assertion";
        needle = "ReadyPointNetworkIdleWindowZero";
      }
      {
        label = "network idle no-link assertion";
        needle = "ReadyPointNetworkIdleWithoutLinks";
      }
      {
        label = "console marker empty assertion";
        needle = "ReadyPointConsoleMarkerEmpty";
      }
      {
        label = "console marker split stream";
        needle = "b\"boot rea\"";
      }
      {
        label = "deterministic observed frontier";
        needle = "resolve_ready_point(&world, &node(\"server\"), time(21), &observations)";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 readiness import";
        needle = "guestHostReadiness = import ./phase4-guest-host-readiness.nix";
      }
      {
        label = "phase4 readiness attr path";
        needle = "checks.crucible.phase4.guestHostReadiness";
      }
      {
        label = "phase4 readiness task id";
        needle = "taskIds = [\"T-GHC-3\"]";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/guest_host_readiness.rs" readinessTest [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "unfinished todo";
        needle = "todo!";
      }
      {
        label = "unfinished unimplemented";
        needle = "unimplemented!";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host readiness check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-readiness";
      version = "0";
      src = crucibleSrc;
      buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed];
      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
            set -eu
            export CARGO_HOME="$TMPDIR/cargo-home"
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            mkdir -p "$CARGO_HOME" .cargo
            if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
              sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
                > .cargo/config.toml
            else
              printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
                > .cargo/config.toml
            fi
          '';
        }
        {
          name = "run-guest-host-readiness";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-readiness-target" \
              -p crucible \
              --test guest_host_readiness \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            readiness_heuristics=fixed-icount,first-network-idle,console-marker
            resolved_point=virtual-time-plus-icount
            nondeterministic_readiness=rejected
            RESULT
          '';
        }
      ];
    }
