{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.spatialPlanValidation",
  taskIds ? ["T-SPAT-20"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};

  spatialGraph = builtins.readFile ../../docs/rfcs/0010-crucible/06-spatial-graph.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  signalTests = import ./_rust-module-source.nix {
    inherit lib;
    entry = ../../crates/crucible/src/model/fault_signal/plan_test.rs;
  };
  failures =
    failuresFor "crates/crucible/src/model/fault_signal/plan_test.rs" signalTests [
      {
        label = "duplicate identity admission";
        needle = "one_plan_level_graph_is_required_and_duplicates_fail_closed";
      }
      {
        label = "complete signal layer identity";
        needle = "outer_plan_identity_commits_to_the_complete_fault_layer";
      }
      {
        label = "closed TOML contracts";
        needle = "singleton_signal_alias_canonicalizes_and_closed_tables_reject_unknowns";
      }
      {
        label = "world target validation";
        needle = "compact_plan_rejects_resolved_targets_absent_from_decode_world";
      }
      {
        label = "complete binding codec";
        needle = "plan_binary_round_trips_a_complete_binding_contract";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/06-spatial-graph.md" spatialGraph [
      {
        label = "current signal admission specification";
        needle = "undeclared targets, incompatible mapping types";
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
              model::fault_signal::plan_test:: \
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
            signal_plan_admission=validated
            unknown_fields=rejected
            world_targets=validated
            canonical_binding_codecs=validated
            RESULT
          '';
        }
      ];
    }
