{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase4.faultCombination",
  taskIds ? ["T-FAULT-5"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  model = import ./_crucible-model-source.nix {inherit lib;};
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  faultTest = builtins.readFile ../../crates/crucible/tests/fault_combination.rs;
  faultDoc = builtins.readFile ../../docs/rfcs/0010-crucible/17-fault-injection.md;
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  taskList = builtins.concatStringsSep "," taskIds;
  failures =
    failuresFor "docs/rfcs/0010-crucible/17-fault-injection.md" faultDoc [
      {
        label = "T-FAULT-5 completion note";
        needle = "Completed by `checks.crucible.phase4.faultCombination`";
      }
    ]
    ++ failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "combined fault root";
        needle = "pub struct CombinedFaults";
      }
      {
        label = "order-independent constructor";
        needle = "pub fn from_faults(faults: &[Fault]) -> Self";
      }
      {
        label = "combined network faults";
        needle = "pub struct CombinedNetworkFaults";
      }
      {
        label = "partition any-covers";
        needle = "fn cover(&mut self, direction: PartitionDirection)";
      }
      {
        label = "loss any-fires ordered rates";
        needle = "pub loss_rates: Vec<FaultRateBasisPoints>";
      }
      {
        label = "highest-first rate sort";
        needle = "fn sort_rates_highest_first";
      }
      {
        label = "latency sum";
        needle = "saturating_add";
      }
      {
        label = "reorder widest";
        needle = "fn max_duration";
      }
      {
        label = "duplicate highest rate";
        needle = "fn max_duplicate";
      }
      {
        label = "corruption strategy fixed order";
        needle = "fn network_corruption_kind_order";
      }
      {
        label = "combined node faults";
        needle = "pub struct CombinedNodeFaults";
      }
      {
        label = "clock skew sum";
        needle = "fn saturating_offset_add";
      }
      {
        label = "combined block faults";
        needle = "pub struct CombinedBlockFaults";
      }
      {
        label = "block failure severity";
        needle = "current.max(*mode)";
      }
      {
        label = "combined 9p faults";
        needle = "pub struct CombinedNinePFaults";
      }
      {
        label = "9p failure payload stays paired";
        needle = "pub struct CombinedNinePFailureFault";
      }
      {
        label = "9p failures sorted as pairs";
        needle = "self.failures.sort_by";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "combined root export";
        needle = "CombinedFaults";
      }
      {
        label = "combined network export";
        needle = "CombinedNetworkFaults";
      }
      {
        label = "combined node export";
        needle = "CombinedNodeFaults";
      }
      {
        label = "combined block export";
        needle = "CombinedBlockFaults";
      }
      {
        label = "combined 9p export";
        needle = "CombinedNinePFaults";
      }
      {
        label = "combined 9p failure export";
        needle = "CombinedNinePFailureFault";
      }
    ]
    ++ failuresFor "crates/crucible/tests/fault_combination.rs" faultTest [
      {
        label = "order independence test";
        needle = "overlapping_fault_combination_is_order_independent";
      }
      {
        label = "network table test";
        needle = "network_faults_follow_the_rfc_combination_table";
      }
      {
        label = "node table test";
        needle = "node_faults_follow_the_rfc_combination_table";
      }
      {
        label = "block and 9p table test";
        needle = "block_and_9p_faults_follow_the_rfc_combination_table";
      }
      {
        label = "highest-first loss rates";
        needle = "vec![rate(9_000), rate(2_500), rate(100)]";
      }
      {
        label = "partition any-covers both directions";
        needle = "assert!(partition.endpoint_b_to_endpoint_a);";
      }
      {
        label = "block drop most severe";
        needle = "Some(IoFailureMode::Drop)";
      }
      {
        label = "9p failure pair expectation";
        needle = "ninep_failure(6_000, 5)";
      }
      {
        label = "second network target isolated";
        needle = "combined network faults should include admin-db";
      }
      {
        label = "second node target isolated";
        needle = "combined node faults should include cache";
      }
      {
        label = "second block target isolated";
        needle = "combined block faults should include disk1";
      }
      {
        label = "second 9p target isolated";
        needle = "combined 9p faults should include fs1";
      }
      {
        label = "node slow largest";
        needle = "Some(slowdown(20_000))";
      }
      {
        label = "clock skew sum";
        needle = "SimOffset { nanos: 40 }";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase4 fault combination import";
        needle = "faultCombination = import ./phase4-fault-combination.nix";
      }
      {
        label = "phase4 fault combination attr path";
        needle = "attrPath = \"checks.crucible.phase4.faultCombination\"";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/fault_combination.rs" faultTest [
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
  then throw "crucible phase4 fault-combination check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase4-fault-combination";
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
          name = "run-fault-combination";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-fault-combination-target" \
              -p crucible \
              --test fault_combination \
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
            combination=input-order-independent
            any_fires=highest-first-rates
            sum=latency,bandwidth,clock-skew
            max=reorder,duplicate,corruption,slow
            RESULT
          '';
        }
      ];
    }
