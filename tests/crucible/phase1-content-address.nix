{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase1.gates.contentAddress",
  taskIds ? ["T-HARN-11"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-7PIlTjQ6Cnb2k2+Qn4A49maDZSffD20krhCcwJ7od8Y=";
  };
  model = builtins.readFile ../../crates/crucible/src/model.rs;
  modelCanonical = builtins.readFile ../../crates/crucible/src/model/canonical.rs;
  simLib = builtins.readFile ../../crates/crucible-sim/src/lib.rs;
  crucibleGate = builtins.readFile ../../crates/crucible/tests/gate_content_address.rs;
  simGate = builtins.readFile ../../crates/crucible-sim/tests/gate_content_address.rs;
  gateTargets = builtins.readFile ../../crates/crucible-harness/src/gate_targets.rs;
  gateCatalog = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  gateCatalogTest = builtins.readFile ../../crates/crucible-harness/tests/gate_catalog.rs;
  gateTargetMapping = builtins.readFile ./phase1-gate-target-mapping.nix;
  defaultChecks = builtins.readFile ./default.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

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
        label = "scenario canonical material entry point";
        needle = "pub fn from_canonical_material(domain: &str, material: &str) -> Self";
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
        label = "content hash domain separator";
        needle = "crucible.content-hash.v1";
      }
      {
        label = "configuration hash domain separator";
        needle = "crucible.configuration.v1";
      }
      {
        label = "schedule hash domain separator";
        needle = "crucible.schedule.v1";
      }
      {
        label = "explicit schedule decision encoding";
        needle = "fn write_decision(hasher: &mut MaterialHasher, decision: &Decision)";
      }
    ]
    ++ failuresFor "crates/crucible-sim/src/lib.rs" simLib [
      {
        label = "stable hashing primitive";
        needle = "pub struct StableHasher";
      }
      {
        label = "canonical stable digest bytes";
        needle = "pub bytes: [u8; 32]";
      }
      {
        label = "content-addressing seam";
        needle = "FUTURE_RATCHET_INTEGRATION_SEAM";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_content_address.rs" crucibleGate [
      {
        label = "fixed vector coverage";
        needle = "gate_content_address_keeps_fixed_vectors_stable";
      }
      {
        label = "equal content coverage";
        needle = "gate_content_address_hashes_equal_content_to_equal_ids";
      }
      {
        label = "single-byte mutation coverage";
        needle = "gate_content_address_changes_on_single_byte_mutations";
      }
      {
        label = "schedule order sensitivity";
        needle = "gate_content_address_is_sensitive_to_schedule_order";
      }
      {
        label = "materialization cache exclusion";
        needle = "gate_content_address_excludes_materialization_cache_from_identity";
      }
      {
        label = "collision corpus";
        needle = "gate_content_address_collision_corpus_has_unique_ids";
      }
      {
        label = "twice-reduce canonical digest";
        needle = "assert_twice_reduce_canonical_digest(";
      }
    ]
    ++ failuresFor "crates/crucible-sim/tests/gate_content_address.rs" simGate [
      {
        label = "fixed vector coverage";
        needle = "gate_content_address_keeps_fixed_vectors_stable";
      }
      {
        label = "equal content coverage";
        needle = "gate_content_address_hashes_equal_content_to_equal_ids";
      }
      {
        label = "single-byte mutation coverage";
        needle = "gate_content_address_changes_on_single_byte_mutations";
      }
      {
        label = "domain and ordering coverage";
        needle = "gate_content_address_separates_domains_and_ordering";
      }
      {
        label = "collision corpus";
        needle = "gate_content_address_collision_corpus_has_unique_ids";
      }
      {
        label = "twice-reduce canonical digest";
        needle = "assert_twice_reduce_canonical_digest(";
      }
    ]
    ++ forbiddenFor "crates/crucible/tests/gate_content_address.rs" crucibleGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "red placeholder panic";
        needle = "implementation is pending T-HARN-11";
      }
    ]
    ++ forbiddenFor "crates/crucible-sim/tests/gate_content_address.rs" simGate [
      {
        label = "ignored placeholder";
        needle = "#[ignore";
      }
      {
        label = "red placeholder panic";
        needle = "implementation is pending T-HARN-11";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/gate_targets.rs" gateTargets [
      {
        label = "implemented crucible content-address target";
        needle = "gate: \"gate:content-address\",\n        package: \"crucible\",\n        test_target: \"gate_content_address\",\n        required_features: &[\"test-double\"],\n        placeholder: false,";
      }
      {
        label = "implemented crucible-sim content-address target";
        needle = "gate: \"gate:content-address\",\n        package: \"crucible-sim\",\n        test_target: \"gate_content_address\",\n        required_features: &[],\n        placeholder: false,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" gateCatalog [
      {
        label = "implemented content-address catalog status";
        needle = "name: \"gate:content-address\",\n        phase: GatePhase::Phase1,\n        owner: \"crucible\",\n        status: GateStatus::Implemented,";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/gate_catalog.rs" gateCatalogTest [
      {
        label = "content-address implemented status assertion";
        needle = "find_gate(\"gate:content-address\").map(|spec| spec.status),\n        Some(GateStatus::Implemented)";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-gate-target-mapping.nix" gateTargetMapping [
      {
        label = "implemented crucible mapping target";
        needle = "gate = \"gate:content-address\";\n      package = \"crucible\";\n      testTarget = \"gate_content_address\";\n      requiredFeatures = [\"test-double\"];\n      placeholder = false;";
      }
      {
        label = "implemented crucible-sim mapping target";
        needle = "gate = \"gate:content-address\";\n      package = \"crucible-sim\";\n      testTarget = \"gate_content_address\";\n      requiredFeatures = [];\n      placeholder = false;";
      }
      {
        label = "updated placeholder count";
        needle = "placeholder_targets=18";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase1 exposes content-address gate";
        needle = "contentAddress = import ./phase1-content-address.nix";
      }
      {
        label = "phase1 content-address attr path";
        needle = "attrPath = \"checks.crucible.phase1.gates.contentAddress\"";
      }
      {
        label = "phase1 content-address lists T-HARN-11";
        needle = "\"T-HARN-11\"";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-11 checklist complete";
        needle = "- [x] **T-HARN-11**";
      }
    ];
in
  if failures != []
  then throw "crucible phase1 content-address gate check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-content-address";
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
          name = "run-content-address";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-content-address-target" \
              -p crucible \
              --features test-double \
              --test gate_content_address \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-content-address-target" \
              -p crucible-sim \
              --test gate_content_address \
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
            gate=gate:content-address
            tasks=${builtins.concatStringsSep "," taskIds}
            rust_tests=crucible::gate_content_address,crucible-sim::gate_content_address
            corpus=fixed-vectors-and-collision-sampling
            RESULT
          '';
        }
      ];
    }
