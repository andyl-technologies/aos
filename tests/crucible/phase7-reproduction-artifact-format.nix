{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.reproductionArtifactFormat",
  taskIds ? ["T-HARN-24"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  harnessManifest = builtins.readFile ../../crates/crucible-harness/Cargo.toml;
  cliManifest = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  harnessLib = builtins.readFile ../../crates/crucible-harness/src/lib.rs;
  reproduction = builtins.readFile ../../crates/crucible-harness/src/reproduction.rs;
  reproductionTest = builtins.readFile ../../crates/crucible-harness/tests/reproduction_artifact.rs;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;
  harnessTesting = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "T-HARN-24 checklist complete";
        needle = "- [x] **T-HARN-24**";
      }
      {
        label = "T-HARN-24 completion note";
        needle = "Completed by `checks.crucible.phase7.reproductionArtifactFormat`";
      }
      {
        label = "T-HARN-25 handoff note";
        needle = "T-HARN-25 adds the shared mock machine-profile verifier";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessTesting [
      {
        label = "stale T-HARN-24 placeholder";
        needle = "- [ ] **T-HARN-24**";
      }
    ]
    ++ forbiddenFor "crates/crucible-harness/Cargo.toml" harnessManifest [
      {
        label = "runtime BLAKE3 dependency";
        needle = "blake3 = { workspace = true }";
      }
      {
        label = "runtime serde dependency";
        needle = "serde = { workspace = true }";
      }
      {
        label = "runtime serde_json dependency";
        needle = "serde_json = { workspace = true }";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "CLI test-only harness dependency";
        needle = "crucible-harness = { path = \"../crucible-harness\" }";
      }
      {
        label = "CLI tempfile test dependency";
        needle = "tempfile = { workspace = true }";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/Cargo.toml" cliManifest [
      {
        label = "CLI runtime harness dependency";
        needle = "[dependencies]\nclap = { workspace = true }\ncrucible-harness = { path = \"../crucible-harness\" }";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/lib.rs" harnessLib [
      {
        label = "reproduction module export";
        needle = "pub mod reproduction;";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/reproduction.rs" reproduction [
      {
        label = "artifact schema constant";
        needle = "pub const REPRODUCTION_ARTIFACT_SCHEMA: &str = \"crucible.reproduction-artifact.v2\";";
      }
      {
        label = "artifact type";
        needle = "pub struct ReproductionArtifact";
      }
      {
        label = "pinned identities";
        needle = "pub struct PinnedBuildIdentity";
      }
      {
        label = "QEMU build identity";
        needle = "pub qemu_build_id: String";
      }
      {
        label = "QEMU patch series identity";
        needle = "pub qemu_patch_series_hash: String";
      }
      {
        label = "shmem ABI version identity";
        needle = "pub shmem_abi_version: String";
      }
      {
        label = "guest-host protocol identity";
        needle = "pub guest_host_protocol_version: String";
      }
      {
        label = "RPC ABI version identity";
        needle = "pub rpc_abi_version: String";
      }
      {
        label = "RPC ABI build identity";
        needle = "pub rpc_abi_build: String";
      }
      {
        label = "plugin ABI identity";
        needle = "pub plugin_abi: String";
      }
      {
        label = "content-addressed component";
        needle = "pub struct ContentAddressedComponent";
      }
      {
        label = "inline component payload";
        needle = "pub struct ComponentPayload";
      }
      {
        label = "CAS URI";
        needle = "store_uri: format!(\"cas:{digest}\")";
      }
      {
        label = "stable content address";
        needle = "format!(\"crucible-hash:{}\", hex_bytes(&stable_digest(bytes)))";
      }
      {
        label = "schedule type";
        needle = "pub struct ReproductionSchedule";
      }
      {
        label = "recorded decision";
        needle = "pub struct RecordedDecision";
      }
      {
        label = "canonical encode";
        needle = "pub fn encode(&self) -> Result<Vec<u8>, ReproductionArtifactError>";
      }
      {
        label = "canonical decode";
        needle = "pub fn decode(bytes: &[u8]) -> Result<Self, ReproductionArtifactError>";
      }
      {
        label = "mock producer";
        needle = "pub fn mock_e2e_reproduction_artifact";
      }
      {
        label = "e2e conversion";
        needle = "pub fn reproduction_artifact_from_mock_e2e";
      }
      {
        label = "scenario component reference required";
        needle = "ScenarioComponentMissing";
      }
      {
        label = "payload digest mismatch rejected";
        needle = "PayloadDigestMismatch";
      }
      {
        label = "schedule digest mismatch rejected";
        needle = "ScheduleDigestMismatch";
      }
    ]
    ++ failuresFor "crates/crucible-harness/tests/reproduction_artifact.rs" reproductionTest [
      {
        label = "round-trip test";
        needle = "reproduction_artifact_format_round_trips_seed_scenario_schedule_and_pinned_identities";
      }
      {
        label = "schedule digest negative test";
        needle = "reproduction_artifact_format_rejects_mutated_schedule_digest";
      }
      {
        label = "missing component negative test";
        needle = "reproduction_artifact_format_rejects_unresolved_scenario_component";
      }
      {
        label = "identity negative test";
        needle = "reproduction_artifact_format_rejects_unpinned_or_malformed_identities";
      }
      {
        label = "schedule order negative test";
        needle = "reproduction_artifact_format_enforces_total_schedule_order";
      }
      {
        label = "small artifact reference test";
        needle = "reproduction_artifact_format_keeps_large_components_by_reference";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "replay artifact argument";
        needle = "artifact: PathBuf";
      }
      {
        label = "CLI replay validation";
        needle = "fn replay_reproduction_artifact";
      }
      {
        label = "CLI v2 artifact schema";
        needle = "const REPRODUCTION_ARTIFACT_SCHEMA: &str = \"crucible.reproduction-artifact.v2\";";
      }
      {
        label = "CLI patch-series identity";
        needle = "qemu_patch_series_hash: String";
      }
      {
        label = "CLI guest-host identity";
        needle = "guest_host_protocol_version: String";
      }
      {
        label = "CLI RPC identity";
        needle = "rpc_abi_build: String";
      }
      {
        label = "CLI failure artifact writer";
        needle = "fn write_failure_reproduction_artifact";
      }
      {
        label = "CLI replay command footer";
        needle = "crucible replay {}";
      }
      {
        label = "CLI debug command footer";
        needle = "debug_command.ends_with(\" --at-failure\")";
      }
      {
        label = "CLI mock failure artifact seam";
        needle = "emit_mock_failure_artifact";
      }
      {
        label = "CLI replay test";
        needle = "cli_replay_validates_reproduction_artifact";
      }
      {
        label = "CLI failure writer test";
        needle = "cli_failure_artifact_writer_emits_replay_and_debug_commands";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 reproduction artifact check";
        needle = "reproductionArtifactFormat = import ./phase7-reproduction-artifact-format.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 reproduction-artifact format check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-reproduction-artifact-format";
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
          name = "run-reproduction-artifact-format";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cd crates
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-reproduction-artifact-format-target" \
              -p crucible-harness \
              --test reproduction_artifact \
              -- --test-threads=1
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-reproduction-artifact-format-target" \
              -p crucible-cli \
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
            schema=crucible.reproduction-artifact.v2
            tuple=seed,scenario-def-ref,schedule
            component_addressing=cas-crucible-hash
            inline_payloads=small-components
            pinned_identities=engine,artifact-abi,qemu-build,qemu-patch-series,shmem-abi,guest-host-protocol,rpc-abi,plugin-abi
            cli_replay=validates-artifact-format
            cli_failure_artifact=emits-replay-and-debug-commands
            machine_independent_reproduction=checks.crucible.phase7.machineIndependentReproduction
            real_host_reproduction=deferred-to-packaging-and-fleet-gates
            RESULT
          '';
        }
      ];
    }
