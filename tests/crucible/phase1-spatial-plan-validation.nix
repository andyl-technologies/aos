{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialPlanValidation",
  taskIds ? ["T-SPAT-20"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  model = import ./_crucible-model-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "T-SPAT-20 completion names signal plan admission";
        needle = "rejects missing programs, duplicate identities, invalid selectors";
      }
      {
        label = "T-SPAT-20 completion names terminal gate";
        needle = "`checks.crucible.phase7.gates.signalFaultSystem`";
      }
      {
        label = "T-SPAT-20 completion names resource ceilings";
        needle = "exceeded resource ceilings before hashing or execution";
      }
      {
        label = "T-SPAT-20 completion names typed time";
        needle = "Typed signal coordinates prevent negative time";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "typed unsigned virtual time";
        needle = "pub struct VirtualTime";
      }
      {
        label = "virtual time tick is u64";
        needle = "pub ticks: u64";
      }
      {
        label = "fault signal plan admission constructor";
        needle = "pub fn new(\n        mut programs: Vec<SignalProgram>,";
      }
      {
        label = "duplicate programs rejected";
        needle = "FaultSignalPlanError::DuplicateProgram";
      }
      {
        label = "duplicate bindings rejected";
        needle = "FaultSignalPlanError::DuplicateBinding";
      }
      {
        label = "bindings cannot reference missing programs";
        needle = "FaultSignalPlanError::MissingProgram";
      }
      {
        label = "hard program ceiling enforced";
        needle = "HARD_FAULT_SIGNAL_PROGRAM_LIMIT";
      }
      {
        label = "bindings canonicalized before hashing";
        needle = "bindings.sort_by(|left, right| left.id().cmp(right.id()))";
      }
      {
        label = "world admission validates fault signals";
        needle = ".validate_for_world(world)";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "focused duplicate and graph-count admission test";
        needle = "fn one_plan_level_graph_is_required_and_duplicates_fail_closed()";
      }
      {
        label = "wire admission validates versions and identities";
        needle = "fn wire_admission_rejects_versions_missing_programs_and_duplicate_contracts()";
      }
      {
        label = "wire decoding reenters scalar and selector validation";
        needle = "fn wire_decode_reenters_identity_scalar_and_selector_validation()";
      }
      {
        label = "world validation rejects invalid wakeups";
        needle = "fn world_validation_rejects_unrepresentable_binding_wakeups()";
      }
      {
        label = "compact decode validates world targets";
        needle = "fn compact_plan_rejects_resolved_targets_absent_from_decode_world()";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes spatial plan validation check";
        needle = "spatialPlanValidation = import ./phase1-spatial-plan-validation.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 spatial plan validation check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-spatial-plan-validation";
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
          name = "run-spatial-plan-validation";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-spatial-plan-validation-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible \
              --lib \
              fault_signal::plan_test \
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
            tasks=${builtins.concatStringsSep "," taskIds}
            component=plan-validation
            signal_programs=single-graph-duplicate-checked
            bindings=canonical-world-validated
            selectors=typed-and-world-owned
            resource_ceilings=pre-hash
            RESULT
          '';
        }
      ];
    }
