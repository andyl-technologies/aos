{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.blackBoxFirstGuarantee",
  taskIds ? ["T-TRIG-19"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  blackBoxTest = builtins.readFile ../../crates/crucible/tests/black_box_first_guarantee.rs;
  triggerDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17a-conditions-and-triggers.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "T-TRIG-19 completion note";
        needle = "Completed by `checks.crucible.phase4.blackBoxFirstGuarantee`";
      }
      {
        label = "event graph replay gate complete";
        needle = "Completed by `checks.crucible.phase4.gates.replayOracle`";
      }
    ]
    ++ failuresFor "crates/crucible/tests/black_box_first_guarantee.rs" blackBoxTest [
      {
        label = "complete black-box scenario determinism test";
        needle = "complete_black_box_scenario_runs_deterministically_without_guest_marker";
      }
      {
        label = "black-box property violation failure test";
        needle = "black_box_property_violation_fails_deterministically_without_guest_marker";
      }
      {
        label = "guest-marker removal test";
        needle = "removing_guest_marker_conditions_leaves_functional_graph";
      }
      {
        label = "no guest-side fallback oracle";
        needle = "struct NoGuestSideLeaves";
      }
      {
        label = "guest-side fallback panics";
        needle = "black-box-first scenario must not depend on guest-side leaf fallback";
      }
      {
        label = "readiness console observation";
        needle = "Predicate::console_match";
      }
      {
        label = "readiness coverage observation";
        needle = "Predicate::coverage_point";
      }
      {
        label = "fault injection action";
        needle = "Action::inject_fault";
      }
      {
        label = "timer heal action";
        needle = "Action::heal_fault";
      }
      {
        label = "properties assertion state steering";
        needle = "Predicate::assertion_state";
      }
      {
        label = "network convergence observation";
        needle = "Predicate::network_match";
      }
      {
        label = "pass action";
        needle = "Action::pass";
      }
      {
        label = "fail action";
        needle = "Action::fail";
      }
      {
        label = "assertion-layer failure composition";
        needle = "AssertionRunVerdict::failed";
      }
      {
        label = "trigger failure verdict assertion";
        needle = "ComposedRunVerdictFailure::Trigger";
      }
      {
        label = "scenario component validation";
        needle = "ScenarioDefForm::from_components";
      }
      {
        label = "offline verdict replay";
        needle = "compose_run_verdict_from_event_log";
      }
      {
        label = "guest marker removal shape";
        needle = "Predicate::guest_marker(marker(\"ready\"))";
      }
      {
        label = "graph guest-marker scanner";
        needle = "fn graph_has_guest_marker";
      }
      {
        label = "properties guest-marker scanner";
        needle = "fn properties_have_guest_marker";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 exposes black-box-first guarantee check";
        needle = "blackBoxFirstGuarantee = import ./phase4-black-box-first-guarantee.nix";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/17a-conditions-and-triggers.md" triggerDoc [
      {
        label = "stale T-TRIG-19 remaining-work prose";
        needle = "remain T-TRIG-19";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/black_box_first_guarantee.rs" blackBoxTest [
      {
        label = "trigger action decision variant";
        needle = "Decision::Trigger";
      }
      {
        label = "host wall clock";
        needle = "std::time";
      }
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "pending implementation panic";
        needle = "implementation is pending";
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
  then throw "crucible phase4 black-box-first-guarantee check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-black-box-first-guarantee";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.rust
        pkgs.sed
      ];

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
            export CARGO_HOME="$TMPDIR/cargo"
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
          name = "run-black-box-first-guarantee";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-black-box-first-guarantee-target" \
              -p crucible \
              --test black_box_first_guarantee \
              -- --test-threads=1
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/nix-support"
            {
              echo "attr=${attrPath}"
              echo "tasks=${taskList}"
              echo "gate=phase4-black-box-first-guarantee"
              echo "any_guest=gate:any-guest"
              echo "black_box_first=implemented-T-TRIG-19"
              echo "complete_zero_guest_marker_scenario=true"
              echo "guest_marker_removal_functional=true"
              echo "deterministic_black_box_run=true"
              echo "offline_verdict_replay=true"
            } > "$out/nix-support/metadata"
          '';
        }
      ];
    }
