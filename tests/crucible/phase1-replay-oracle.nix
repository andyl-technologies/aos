{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.replayOracle",
  taskIds ? ["T-DET-18" "T-DET-21" "T-HARN-12" "T-EXEC-4" "T-EXEC-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-7PIlTjQ6Cnb2k2+Qn4A49maDZSffD20krhCcwJ7od8Y=";
  };
  guestNonModification = import ./phase1-guest-non-modification.nix {inherit pkgs lib;};
  model = builtins.readFile ../../crates/crucible/src/model.rs;
  modelCanonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  libSource = builtins.readFile ../../crates/crucible/src/lib.rs;
  cargoManifest = builtins.readFile ../../crates/crucible/Cargo.toml;
  replayGate = builtins.readFile ../../crates/crucible/tests/gate_replay_oracle.rs;
  replayOracleHarness = builtins.readFile ../../crates/crucible-harness/src/replay_oracle.rs;
  qemuRealization = builtins.readFile ../../crates/crucible-qemu/src/realization.rs;
  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  determinismContract = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  executionModel = builtins.readFile ../../docs/rfcs/0010-crucible/05-execution-model.md;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  forbiddenFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (hasInfix requirement.needle content) [
          "${fileLabel}: forbidden ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "crates/crucible/src/model.rs" model [
      {
        label = "pure reducer implementation";
        needle = "pub fn reduce(def: &ScenarioDef, schedule: &Schedule) -> Result<State, EngineError>";
      }
      {
        label = "reduce delegates to canonical reduced-state hash";
        needle = "id: canonical::reduced_state_hash(def, schedule)";
      }
      {
        label = "configuration content hash";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
      {
        label = "schedule content hash";
        needle = "pub fn content_hash(&self) -> ContentHash";
      }
    ]
    ++ failuresFor "crates/crucible/src/model/canonical.rs" modelCanonical [
      {
        label = "reduce state domain separator";
        needle = "crucible.reduce.state.v1";
      }
      {
        label = "scenario identity folded into reduce";
        needle = "write_content_hash(&mut hasher, &def.id);";
      }
      {
        label = "schedule folded into reduce";
        needle = "write_schedule(&mut hasher, schedule);";
      }
      {
        label = "explicit decision encoding";
        needle = "fn write_decision(hasher: &mut MaterialHasher, decision: &Decision)";
      }
    ]
    ++ forbiddenFor "crates/crucible/src/model.rs" model [
      {
        label = "reduce not-implemented placeholder";
        needle = "operation: \"reduce\"";
      }
    ]
    ++ failuresFor "crates/crucible/src/lib.rs" libSource [
      {
        label = "reduce purity test";
        needle = "reduce_is_pure_over_scenario_and_schedule";
      }
      {
        label = "prefix closure test";
        needle = "reduce_is_prefix_closed_by_schedule_hash";
      }
    ]
    ++ failuresFor "crates/crucible/Cargo.toml" cargoManifest [
      {
        label = "replay-oracle dev dependency";
        needle = "crucible-harness = { path = \"../crucible-harness\" }";
      }
      {
        label = "test-double replay oracle target";
        needle = "name = \"gate_replay_oracle\"";
      }
      {
        label = "replay oracle target requires test-double feature";
        needle = "required-features = [\"test-double\"]";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_replay_oracle.rs" replayGate [
      {
        label = "fixed checkpoint corpus";
        needle = "assert_replay_oracle_fixed_checkpoint_corpus(";
      }
      {
        label = "materialized checkpoint descriptor";
        needle = "struct MaterializedCheckpoint";
      }
      {
        label = "test-double fat checkpoint materialization";
        needle = "fn materialize_fat_checkpoint(";
      }
      {
        label = "ancestor schedule delta extraction";
        needle = "fn schedule_delta(";
      }
      {
        label = "thin ancestor replay schedule reconstruction";
        needle = "fn replay_schedule(";
      }
      {
        label = "checkpoint metadata hash";
        needle = "fn test_double_checkpoint_hash(";
      }
      {
        label = "corrupt configuration metadata negative";
        needle = "assert_replay_oracle_rejects_corrupt_configuration_metadata(";
      }
      {
        label = "corrupt schedule delta metadata negative";
        needle = "assert_replay_oracle_rejects_corrupt_schedule_delta_metadata(";
      }
      {
        label = "first mismatch reporting path";
        needle = "assert_replay_oracle_reports_first_mismatch(";
      }
      {
        label = "observational-entry exclusion";
        needle = "assert_replay_oracle_excludes_observational_entries(";
      }
      {
        label = "twice-reduce canonical digest";
        needle = "assert_twice_reduce_canonical_digest(";
      }
      {
        label = "SimDouble test-double marker";
        needle = "SimDouble";
      }
      {
        label = "materialized replay-oracle checker";
        needle = "check_materialized_replay_oracle(&corpus)";
      }
      {
        label = "schedule-order sensitivity";
        needle = "gate_replay_oracle_is_sensitive_to_schedule_order";
      }
      {
        label = "wrong-order oracle failure";
        needle = "wrong-order thin reconstruction should fail the replay oracle";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_replay_oracle.rs" replayGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "direct byte-only corpus check";
        needle = "check_replay_oracle(&corpus)";
      }
      {
        label = "same-schedule fat/thin reducer comparison";
        needle = ".prefix(checkpoint.schedule.len())";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/replay_oracle.rs" replayOracleHarness [
      {
        label = "first mismatch reporting";
        needle = "fn mismatch(checkpoint_id: &str, fat_hash: &[u8], thin_hash: &[u8])";
      }
      {
        label = "fat checkpoint hash field";
        needle = "pub fat_hash: Vec<u8>";
      }
      {
        label = "thin reconstruction hash field";
        needle = "pub thin_hash: Vec<u8>";
      }
      {
        label = "materialized replay-oracle case type";
        needle = "pub struct ReplayOracleMaterializedCase";
      }
      {
        label = "checkpoint kind metadata";
        needle = "pub enum ReplayOracleCheckpointKind";
      }
      {
        label = "materialized checkpoint hash field";
        needle = "pub fat_checkpoint_hash: Vec<u8>";
      }
      {
        label = "materialized configuration metadata field";
        needle = "pub fat_configuration_hash: Vec<u8>";
      }
      {
        label = "materialized ancestor metadata field";
        needle = "pub fat_ancestor_hash: Vec<u8>";
      }
      {
        label = "materialized schedule-delta metadata field";
        needle = "pub fat_schedule_delta_hash: Vec<u8>";
      }
      {
        label = "metadata-validating replay-oracle checker";
        needle = "pub fn check_materialized_replay_oracle(";
      }
      {
        label = "fat checkpoint kind validation";
        needle = "case.kind != ReplayOracleCheckpointKind::Fat";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/realization.rs" qemuRealization [
      {
        label = "QEMU replay-oracle checker";
        needle = "pub fn check_qemu_replay_oracle(";
      }
      {
        label = "loadvm probe executor hook";
        needle = "load_exact_snapshot_for_replay_oracle_probe";
      }
      {
        label = "thin replay derivation";
        needle = "fn realize_qemu_replay_oracle_thin_path(";
      }
      {
        label = "probe-only loadvm authorization";
        needle = "policy.authorize_loadvm_probe()";
      }
      {
        label = "replay-oracle match result";
        needle = "QemuReplayOracleValidation::Match";
      }
      {
        label = "replay-oracle mismatch result";
        needle = "QemuReplayOracleValidation::Mismatch";
      }
      {
        label = "QEMU replay-oracle match test";
        needle = "qemu_replay_oracle_matches_loadvm_snapshot_to_replay_from_ancestor";
      }
      {
        label = "QEMU replay-oracle mismatch test";
        needle = "qemu_replay_oracle_reports_loadvm_replay_mismatch";
      }
      {
        label = "snapshot-completeness probe purpose";
        needle = "QemuLoadvmCommandPurpose::SnapshotCompletenessProbe";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "QEMU replay-oracle checker exported";
        needle = "check_qemu_replay_oracle";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "implemented replay-oracle target";
        needle = "gate: \"gate:replay-oracle\",\n        package: \"crucible\",\n        test_target: \"gate_replay_oracle\",\n        required_features: &[\"test-double\"],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "implemented replay-oracle catalog status";
        needle = "name: \"gate:replay-oracle\",\n        phase: GatePhase::Phase1,\n        owner: \"crucible\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "replay oracle implemented status assertion";
        needle = "find_gate(\"gate:replay-oracle\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented replay-oracle mapping target";
        needle = "gate = \"gate:replay-oracle\";\n      package = \"crucible\";\n      testTarget = \"gate_replay_oracle\";\n      requiredFeatures = [\"test-double\"];\n      placeholder = false;";
      }
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=14";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes replay-oracle gate";
        needle = "replayOracle = import ./phase1-replay-oracle.nix";
      }
      {
        label = "phase1 replay-oracle attr path";
        needle = "attrPath = \"checks.crucible.phase1.gates.replayOracle\"";
      }
      {
        label = "phase1 replay-oracle lists T-DET-18";
        needle = "\"T-DET-18\"";
      }
      {
        label = "phase1 replay-oracle lists T-DET-21";
        needle = "\"T-DET-21\"";
      }
      {
        label = "phase1 replay-oracle lists T-HARN-12";
        needle = "\"T-HARN-12\"";
      }
      {
        label = "phase1 replay-oracle lists T-EXEC-4";
        needle = "\"T-EXEC-4\"";
      }
      {
        label = "phase1 replay-oracle lists T-EXEC-11";
        needle = "\"T-EXEC-11\"";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismContract [
      {
        label = "T-DET-18 checklist complete";
        needle = "- [x] **T-DET-18**";
      }
      {
        label = "T-DET-21 checklist complete";
        needle = "- [x] **T-DET-21**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-12 checklist complete";
        needle = "- [x] **T-HARN-12**";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/05-execution-model.md" executionModel [
      {
        label = "T-EXEC-4 checklist complete";
        needle = "- [x] **T-EXEC-4**";
      }
      {
        label = "T-EXEC-11 checklist complete";
        needle = "- [x] **T-EXEC-11**";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 replay-oracle gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-replay-oracle";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
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
          name = "run-replay-oracle";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-replay-oracle-target" \
              -p crucible \
              --features test-double \
              --test gate_replay_oracle \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-replay-oracle-target" \
              -p crucible-qemu \
              --lib \
              replay_oracle \
              -- --test-threads=1
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"

            require_line() {
              result="$1/result"
              line="$2"
              grep -Fxq "$line" "$result" || {
                echo "dependency missing evidence: $line" >&2
                cat "$result" >&2
                exit 1
              }
            }

            require_leaf() {
              dependency="$1"
              shift
              require_line "$dependency" "PASS"
              for line in "$@"; do
                require_line "$dependency" "$line"
              done
            }

            require_leaf ${guestNonModification} \
              "gate=gate:replay-oracle" \
              "required_gates=gate:any-guest,gate:replay-oracle" \
              "tasks=T-DET-21" \
              "guest_writes=copy-on-write-overlay" \
              "guest_backing_state=byte-identical-genesis" \
              "guest_on_disk_mutation_policy=forbidden-by-launch-profile" \
              "guest_core_content=host-side-only"

            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            gate=gate:replay-oracle
            tasks=${builtins.concatStringsSep "," taskIds}
            rust_test=crucible::gate_replay_oracle
            qemu_rust_test=crucible-qemu::realization::replay_oracle
            oracle=fat-materialized-equals-thin-from-ancestor
            qemu_oracle=loadvm-snapshot-equals-replay-from-ancestor
            qemu_oracle_probe_authorization=snapshot-completeness
            corpus=fixed-checkpoints
            guest_non_modification=launch-contract-gate
            required_guest_non_modification_gates=gate:any-guest,gate:replay-oracle
            guest_writes=copy-on-write-overlay
            guest_backing_state=byte-identical-genesis
            guest_on_disk_mutation_policy=forbidden-by-launch-profile
            guest_core_content=host-side-only
            RESULT
          '';
        }
      ];
    }
