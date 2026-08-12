{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.guestHostEmitterAbsence",
  taskIds ? ["T-GHC-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  absenceTest = builtins.readFile ../../crates/crucible/tests/guest_host_emitter_absence.rs;
  guestHostDoc = builtins.readFile ../../docs/rfcs/0010-crucible/16-guest-host-channel.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  phaseGate = builtins.readFile ./phase4-guest-host-emitter-absence.nix;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/16-guest-host-channel.md" guestHostDoc [
      {
        label = "T-GHC-11 completion note";
        needle = "Completed by `checks.crucible.phase4.guestHostEmitterAbsence`";
      }
      {
        label = "emitter absence implementation note";
        needle = "`guest_host_emitter_absence`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "guest-host phase4 task range";
        needle = "Guest↔host channel + optional agent";
      }
    ]
    ++ failuresFor "crates/crucible/tests/guest_host_emitter_absence.rs" absenceTest [
      {
        label = "absence determinism test";
        needle = "emitter_absence_preserves_black_box_determinism_faults_coverage_and_io";
      }
      {
        label = "white-box disabled assertion";
        needle = "WhiteBoxPolicy::Disabled";
      }
      {
        label = "enabled unused control";
        needle = "WhiteBoxPolicy::Enabled";
      }
      {
        label = "cross-policy behavior comparison";
        needle = "enabled_unused.behavior_material()";
      }
      {
        label = "no kernel guest content";
        needle = "node.kernel.is_none()";
      }
      {
        label = "no root image guest content";
        needle = "node.root_image.is_none()";
      }
      {
        label = "no initrd guest content";
        needle = "node.initrd.is_none()";
      }
      {
        label = "coverage remains black-box";
        needle = "Predicate::coverage_point";
      }
      {
        label = "observable I/O remains black-box";
        needle = "Predicate::io_pattern";
      }
      {
        label = "event-log determinism comparison";
        needle = "compare_event_log_determinism";
      }
      {
        label = "coverage projection proof";
        needle = "event_log_coverage_projection";
      }
      {
        label = "backend fingerprint proof";
        needle = "backend_fingerprint_without_emitter";
      }
      {
        label = "real assertion checker";
        needle = "OfflineAssertionChecker::new()";
      }
      {
        label = "guest leaf rejection";
        needle = "ConditionLeaf::GuestMarker";
      }
      {
        label = "named leaf static rejection";
        needle = "Predicate::Named { .. } | Predicate::GuestMarker { .. } => true";
      }
      {
        label = "guest marker event absence";
        needle = "assert_no_guest_marker_entries";
      }
      {
        label = "test double backend";
        needle = "SimBackend::new()";
      }
      {
        label = "fault snapshot proof";
        needle = "active_fault_names";
      }
      {
        label = "black-box surface proof";
        needle = "observed_surface";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/guest_host_emitter_absence.rs" absenceTest [
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
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 emitter absence import";
        needle = "guestHostEmitterAbsence = import ./phase4-guest-host-emitter-absence.nix";
      }
      {
        label = "phase4 emitter absence attr path";
        needle = "checks.crucible.phase4.guestHostEmitterAbsence";
      }
      {
        label = "phase4 emitter absence task id";
        needle = "taskIds = [\"T-GHC-11\"]";
      }
    ]
    ++ failuresFor "tests/crucible/phase4-guest-host-emitter-absence.nix" phaseGate [
      {
        label = "phase gate runs absence test";
        needle = "--test guest_host_emitter_absence";
      }
      {
        label = "phase gate enables test double";
        needle = "--features test-double";
      }
    ];
in
  if failures != []
  then
    throw ''
      crucible phase4 guest-host emitter absence check failed:
      ${builtins.concatStringsSep "\n" failures}
    ''
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-guest-host-emitter-absence";
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
          name = "run-guest-host-emitter-absence";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-guest-host-emitter-absence-target" \
              -p crucible \
              --features test-double \
              --test guest_host_emitter_absence \
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
            no_guest_content=white-box-disabled,kernel-none,root-image-none,initrd-none
            preserved=determinism,faults,coverage,observable-io,backend-fingerprint
            canonical_gate_wiring=checks.crucible.phase4.guestHostChannelGateWiring
            RESULT
          '';
        }
      ];
    }
