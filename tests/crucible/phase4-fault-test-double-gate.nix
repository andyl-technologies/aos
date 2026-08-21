{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.faultTestDoubleGate",
  taskIds ? ["T-FAULT-16"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  gateTest = builtins.readFile ../../crates/crucible/tests/fault_test_double_gate.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-16 completion note";
        needle = "Completed by `checks.crucible.phase4.faultTestDoubleGate`";
      }
    ]
    ++ failuresFor "crates/crucible/tests/fault_test_double_gate.rs" gateTest [
      {
        label = "network fault double gate";
        needle = "fault_test_double_exercises_each_network_fault_kind";
      }
      {
        label = "block fault double gate";
        needle = "fault_test_double_exercises_each_block_fault_kind";
      }
      {
        label = "9p fault double gate";
        needle = "fault_test_double_exercises_each_9p_fault_kind";
      }
      {
        label = "network A-to-B partition coverage";
        needle = "network.partition.a-to-b";
      }
      {
        label = "network reverse partition unaffected coverage";
        needle = "network.partition.b-to-a-unaffected";
      }
      {
        label = "network bidirectional partition coverage";
        needle = "PartitionDirection::Bidirectional";
      }
      {
        label = "network reverse partition direction";
        needle = "PartitionDirection::EndpointBToEndpointA";
      }
      {
        label = "network field mutation coverage";
        needle = "network.corruption.field-mutation";
      }
      {
        label = "network truncation coverage";
        needle = "network.corruption.truncation";
      }
      {
        label = "block failure drop coverage";
        needle = "block.failure.drop";
      }
      {
        label = "9p failure coverage";
        needle = "9p.failure";
      }
      {
        label = "run twice helper";
        needle = "run_twice";
      }
      {
        label = "same-seed link harness script";
        needle = "seeded_link_script";
      }
      {
        label = "recorded link run";
        needle = "recorded_link_run";
      }
      {
        label = "fault-free directed-link comparison";
        needle = "fault_free_link_script";
      }
      {
        label = "divergence localization helper";
        needle = "localize_divergence";
      }
      {
        label = "pinned divergence expectations";
        needle = "ExpectedDivergence";
      }
      {
        label = "exact divergence assertion";
        needle = "assert_divergence";
      }
      {
        label = "true reorder assertion";
        needle = "assert_reordered_ids";
      }
      {
        label = "network reorder batch";
        needle = "LINK_REORDER_REQUESTS";
      }
      {
        label = "block reorder batch";
        needle = "BLOCK_REORDER_REQUESTS";
      }
      {
        label = "9p reorder batch";
        needle = "NINEP_REORDER_REQUESTS";
      }
      {
        label = "exact recorded fault decisions";
        needle = "assert_exact_fault_decisions";
      }
      {
        label = "I/O RNG decision batch assertion";
        needle = "assert_io_rng_draw_batches";
      }
      {
        label = "RNG draw sequence assertion";
        needle = "assert_rng_draw_sequence";
      }
      {
        label = "link recorded fault helper";
        needle = "emit_link_frame_with_recorded_faults";
      }
      {
        label = "block scheduling subnode";
        needle = "DeviceSchedulingSubNode::new(";
      }
      {
        label = "9p scheduling subnode";
        needle = "DeviceSchedulingSubNode::new_ninep";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 fault test double gate import";
        needle = "faultTestDoubleGate = import ./phase4-fault-test-double-gate.nix";
      }
      {
        label = "phase4 fault test double gate attr path";
        needle = "attrPath = \"checks.crucible.phase4.faultTestDoubleGate\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/fault_test_double_gate.rs" gateTest [
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
  then throw "crucible phase4 fault-test-double-gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-fault-test-double-gate";
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
          name = "run-fault-test-double-gate";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-test-double-gate-target" \
              -p crucible \
              --test fault_test_double_gate \
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
            gate=fault-test-double
            run_twice=true
            RESULT
          '';
        }
      ];
    }
