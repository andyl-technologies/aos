{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.reproductionProvenanceTriple",
  taskIds ? ["T-PKG-20"],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  reproduction = builtins.readFile ../../crates/crucible-harness/src/reproduction.rs;
  e2e = builtins.readFile ../../crates/crucible-harness/src/e2e.rs;
  replayOracle = builtins.readFile ../../crates/crucible-harness/src/replay_oracle.rs;
  replayOracleGate = builtins.readFile ../../crates/crucible/tests/gate_replay_oracle.rs;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliManifest = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  cliManifestToml = builtins.fromTOML cliManifest;
  cliRuntimeDependencyTables =
    [
      {
        scope = "dependencies";
        dependencies = cliManifestToml.dependencies or {};
      }
    ]
    ++ map (target: {
      scope = "target.${target}.dependencies";
      dependencies = cliManifestToml.target.${target}.dependencies or {};
    }) (builtins.attrNames (cliManifestToml.target or {}));
  cliDevDependencies = cliManifestToml."dev-dependencies" or {};
  cliRuntimeProtocolBypasses =
    builtins.filter (
      table: builtins.hasAttr "crucible-protocol" table.dependencies
    )
    cliRuntimeDependencyTables;
  cliManifestDependencyFailures =
    lib.optional
    (!(builtins.hasAttr "crucible-api" cliManifestToml.dependencies))
    "crates/crucible-cli/Cargo.toml: missing CLI control-plane API dependency"
    ++ lib.optional
    (!(builtins.hasAttr "crucible-protocol" cliDevDependencies))
    "crates/crucible-cli/Cargo.toml: missing black-box guest protocol fixture dev dependency"
    ++ map (
      table: "crates/crucible-cli/Cargo.toml ${table.scope}: forbidden production CLI bypass of the API protocol re-export"
    )
    cliRuntimeProtocolBypasses;
  defaultChecks = builtins.readFile ./default.nix;
  gateCiWiring = builtins.readFile ./phase7-crucible-gate-ci-wiring.nix;
  releaseManifestGate = builtins.readFile ./phase7-crucible-release-manifest.nix;
  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  apiRpcAbi = builtins.readFile ../../crates/crucible-api/src/rpc_abi.rs;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  firstLineWith = label: prefix: content: let
    matches = builtins.filter (line: lib.hasPrefix prefix line) (lib.splitString "\n" content);
  in
    if matches == []
    then throw "crucible reproduction provenance gate failed to read ${label}"
    else builtins.head matches;
  sourceConst = label: prefix: content:
    lib.removeSuffix ";"
    (lib.removePrefix prefix (firstLineWith label prefix content));
  sourceStringConst = label: prefix: content:
    lib.removeSuffix "\";"
    (lib.removePrefix prefix (firstLineWith label prefix content));

  guestHostProtocolVersion =
    sourceConst
    "guest-host protocol version"
    "pub const CONTROL_PROTOCOL_VERSION: u32 = "
    protocolLib;
  rpcProtocolMajor = sourceConst "RPC ABI major version" "pub const RPC_PROTOCOL_MAJOR: u16 = " apiRpcAbi;
  rpcProtocolMinor = sourceConst "RPC ABI minor version" "pub const RPC_PROTOCOL_MINOR: u16 = " apiRpcAbi;
  rpcProtocolPatch = sourceConst "RPC ABI patch version" "pub const RPC_PROTOCOL_PATCH: u16 = " apiRpcAbi;
  rpcProtocolBuild = sourceStringConst "RPC ABI build tag" "pub const RPC_PROTOCOL_BUILD: &str = \"" apiRpcAbi;
  rpcAbiVersion = "${rpcProtocolMajor}.${rpcProtocolMinor}.${rpcProtocolPatch}";

  failures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-20 completion note";
        needle = "Completed by `checks.crucible.phase7.reproductionProvenanceTriple`";
      }
      {
        label = "PKG-38 provenance triple text";
        needle = "build identity + atomic-patch hash, and the three ABI versions";
      }
    ]
    ++ forbiddenFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
    ]
    ++ failuresFor "crates/crucible-harness/src/reproduction.rs" reproduction [
      {
        label = "current reproduction schema";
        needle = "pub const REPRODUCTION_ARTIFACT_SCHEMA: &str = \"crucible.reproduction-artifact.v4\";";
      }
      {
        label = "QEMU atomic-patch identity field";
        needle = "pub qemu_atomic_patch_hash: String";
      }
      {
        label = "shmem ABI version field";
        needle = "pub shmem_abi_version: String";
      }
      {
        label = "guest-host protocol version field";
        needle = "pub guest_host_protocol_version: String";
      }
      {
        label = "RPC ABI version field";
        needle = "pub rpc_abi_version: String";
      }
      {
        label = "RPC ABI build field";
        needle = "pub rpc_abi_build: String";
      }
      {
        label = "current identity decode arity";
        needle = "require_field_count(line_index, tag, &fields, 11)?;";
      }
      {
        label = "QEMU atomic-patch validation";
        needle = "build_identity.qemu_atomic_patch_hash";
      }
      {
        label = "guest-host validation";
        needle = "build_identity.guest_host_protocol_version";
      }
      {
        label = "RPC build validation";
        needle = "build_identity.rpc_abi_build";
      }
      {
        label = "plugin ABI e2e conversion";
        needle = "plugin_abi: source.plugin_abi.clone()";
      }
      {
        label = "e2e Crucible version conversion";
        needle = "engine_version: source.crucible_version.clone()";
      }
      {
        label = "QEMU atomic-patch e2e conversion";
        needle = "qemu_atomic_patch_hash: source.qemu_atomic_patch_hash.clone()";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/e2e.rs" e2e [
      {
        label = "mock e2e Crucible version identity";
        needle = "pub crucible_version: String";
      }
      {
        label = "mock e2e Crucible version source";
        needle = "crucible_version: env!(\"CARGO_PKG_VERSION\").to_string()";
      }
      {
        label = "mock e2e QEMU atomic-patch identity";
        needle = "pub qemu_atomic_patch_hash: String";
      }
      {
        label = "mock e2e shmem ABI source";
        needle = "shmem_abi_version: CANONICAL_SHMEM_ABI_VERSION.to_string()";
      }
      {
        label = "mock e2e canonical shmem ABI declaration";
        needle = "pub const CANONICAL_SHMEM_ABI_VERSION: u32 = include!(\"../../crucible-shmem/src/abi_version.in\")";
      }
      {
        label = "mock e2e guest-host ABI source";
        needle = "guest_host_protocol_version: CANONICAL_GUEST_HOST_PROTOCOL_VERSION.to_string()";
      }
      {
        label = "mock e2e RPC ABI source";
        needle = "rpc_abi_version: String::from(\"${rpcAbiVersion}\")";
      }
      {
        label = "mock e2e RPC build source";
        needle = "rpc_abi_build: String::from(\"${rpcProtocolBuild}\")";
      }
      {
        label = "mock e2e plugin ABI identity";
        needle = "pub plugin_abi: String";
      }
      {
        label = "mock e2e plugin ABI source";
        needle = "plugin_abi: String::from(\"simdouble-mock-plugin-abi\")";
      }
      {
        label = "mock e2e canonical material includes Crucible version";
        needle = "CanonicalField::Str(&self.build_identity.crucible_version)";
      }
      {
        label = "mock e2e canonical material includes atomic patch";
        needle = "CanonicalField::Str(&self.build_identity.qemu_atomic_patch_hash)";
      }
      {
        label = "mock e2e canonical material includes plugin ABI";
        needle = "CanonicalField::Str(&self.build_identity.plugin_abi)";
      }
    ]
    ++ failuresFor "crates/crucible-harness/src/replay_oracle.rs" replayOracle [
      {
        label = "replay-oracle Crucible version identity";
        needle = "pub crucible_version: String";
      }
      {
        label = "replay-oracle Crucible version source";
        needle = "crucible_version: env!(\"CARGO_PKG_VERSION\").to_string()";
      }
      {
        label = "replay-oracle QEMU atomic-patch identity";
        needle = "pub qemu_atomic_patch_hash: String";
      }
      {
        label = "replay-oracle shmem ABI source";
        needle = "shmem_abi_version: crate::e2e::CANONICAL_SHMEM_ABI_VERSION.to_string()";
      }
      {
        label = "replay-oracle guest-host ABI source";
        needle = "guest_host_protocol_version: crate::e2e::CANONICAL_GUEST_HOST_PROTOCOL_VERSION";
      }
      {
        label = "replay-oracle RPC ABI source";
        needle = "rpc_abi_version: String::from(\"${rpcAbiVersion}\")";
      }
      {
        label = "replay-oracle RPC build source";
        needle = "rpc_abi_build: String::from(\"${rpcProtocolBuild}\")";
      }
      {
        label = "replay-oracle plugin ABI identity";
        needle = "pub plugin_abi: String";
      }
      {
        label = "replay-oracle plugin ABI source";
        needle = "plugin_abi: String::from(\"unit-test-plugin-abi\")";
      }
      {
        label = "replay-oracle plugin ABI drift test";
        needle = "reproduction_artifact_round_trip_rejects_plugin_identity_mismatch";
      }
    ]
    ++ failuresFor "crates/crucible/tests/gate_replay_oracle.rs" replayOracleGate [
      {
        label = "engine replay-oracle Crucible version source";
        needle = "crucible_version: env!(\"CARGO_PKG_VERSION\").to_string()";
      }
      {
        label = "engine replay-oracle shmem ABI source";
        needle = "shmem_abi_version: crucible_shmem::ABI_VERSION.to_string()";
      }
      {
        label = "engine replay-oracle guest-host ABI source";
        needle = "guest_host_protocol_version: crucible_protocol::CONTROL_PROTOCOL_VERSION.to_string()";
      }
      {
        label = "engine replay-oracle RPC ABI source";
        needle = "rpc_abi_version: String::from(\"${rpcAbiVersion}\")";
      }
      {
        label = "engine replay-oracle plugin ABI source";
        needle = "plugin_abi: String::from(\"simdouble-mock-plugin-abi\")";
      }
    ]
    ++ cliManifestDependencyFailures
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "CLI current reproduction schema";
        needle = "const REPRODUCTION_ARTIFACT_SCHEMA: &str = \"crucible.reproduction-artifact.v4\";";
      }
      {
        # The CLI reads the shared guest-host protocol through the public API
        # boundary and records that exact constant in the provenance triple.
        label = "CLI reads guest-host protocol constant";
        needle = "CONTROL_PROTOCOL_VERSION, CommandResultStatus";
      }
      {
        label = "CLI reads RPC ABI constants";
        needle = "RPC_PROTOCOL_BUILD, RPC_PROTOCOL_MAJOR,";
      }
      {
        label = "CLI reads RPC ABI patch constants";
        needle = "RPC_PROTOCOL_MINOR, RPC_PROTOCOL_PATCH";
      }
      {
        label = "CLI identity carries QEMU atomic-patch hash";
        needle = "qemu_atomic_patch_hash: String";
      }
      {
        label = "CLI identity carries shmem ABI version";
        needle = "shmem_abi_version: String";
      }
      {
        label = "CLI identity carries guest-host protocol version";
        needle = "guest_host_protocol_version: String";
      }
      {
        label = "CLI identity carries RPC ABI version";
        needle = "rpc_abi_version: String";
      }
      {
        label = "CLI identity carries RPC ABI build";
        needle = "rpc_abi_build: String";
      }
      {
        label = "CLI requires QEMU marker atomic patch";
        needle = "required_metadata_field(&fields, \"qemu_atomic_patch_hash\", &marker)";
      }
      {
        label = "CLI current identity decode arity";
        needle = "require_field_count(line_index, tag, &fields, 11)?;";
      }
      {
        label = "CLI replay mismatch names atomic-patch";
        needle = "atomic-patch";
      }
      {
        label = "CLI replay mismatch names guest-host";
        needle = "guest-host";
      }
      {
        label = "CLI replay mismatch names RPC";
        needle = "RPC `{}+{}`";
      }
      {
        label = "CLI derives guest-host version from Rust source";
        needle = "CONTROL_PROTOCOL_VERSION.to_string()";
      }
      {
        label = "CLI derives RPC version from Rust source";
        needle = "format!(\"{RPC_PROTOCOL_MAJOR}.{RPC_PROTOCOL_MINOR}.{RPC_PROTOCOL_PATCH}\")";
      }
      {
        label = "CLI derives RPC build from Rust source";
        needle = "RPC_PROTOCOL_BUILD.to_string()";
      }
      {
        label = "CLI refuses remote daemon replay without producer provenance";
        needle = "remote daemon replay cannot validate reproduction artifacts";
      }
      {
        label = "CLI refuses remote mock failure artifacts";
        needle = "mock failure reproduction artifacts require local producer provenance";
      }
      {
        label = "CLI identifies captured Interactive session artifacts";
        needle = "let captures_interactive_session = run_plan.execution_mode == RunExecutionMode::Interactive";
      }
      {
        label = "CLI binds captured Interactive artifacts to session ownership";
        needle = "report.execution_owner == RunExecutionOwner::Session";
      }
      {
        label = "CLI emits non-passing or captured Interactive artifacts";
        needle = "outcome.status.is_non_passing() || captures_interactive_session";
      }
      {
        label = "CLI limits emitted artifacts to local producers";
        needle = "backend_plan.target == BackendExecutionTarget::Local";
      }
      {
        label = "CLI skips remote verify artifacts without provenance";
        needle = "verify-reproduction-artifacts\\tskipped=producer-provenance-unavailable";
      }
      {
        label = "CLI output accepts explicit provenance skip";
        needle = "fn outcome_skipped_reproduction_artifacts";
      }
      {
        label = "CLI live verify witnesses make artifacts optional";
        needle = "artifact: Option<Vec<u8>>";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-release-manifest.nix" releaseManifestGate [
      {
        label = "release manifest gate validates atomic-patch";
        needle = "qemu_atomic_patch_hash=" + "$" + "{qemuPackageMetadataProbe.atomicPatchHash}";
      }
      {
        label = "release manifest gate validates guest-host ABI";
        needle = "guest_host_protocol_abi=" + "$" + "{guestHostProtocolAbi}";
      }
      {
        label = "release manifest gate validates RPC ABI";
        needle = "rpc_abi=" + "$" + "{rpcAbi}";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "T-PKG-20 gate import";
        needle = "reproductionProvenanceTriple = import ./phase7-reproduction-provenance-triple.nix";
      }
      {
        label = "T-PKG-20 gate attrPath";
        needle = ''attrPath = "checks.crucible.phase7.reproductionProvenanceTriple";'';
      }
      {
        label = "e2e raw gate waits for T-PKG-20";
        needle = "phase7.crucibleReleaseManifest phase7.reproductionProvenanceTriple";
      }
    ]
    ++ failuresFor "tests/crucible/phase7-crucible-gate-ci-wiring.nix" gateCiWiring [
      {
        label = "CI wiring guard names reproduction provenance dependency";
        needle = "release-manifest+reproduction-provenance->gate:e2e-determinism";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 reproduction provenance triple check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-reproduction-provenance-triple";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils];

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${builtins.concatStringsSep "," taskIds}
            schema=crucible.reproduction-artifact.v4
            provenance=crucible-version,qemu-build-id,qemu-atomic-patch-hash,shmem-abi-version,guest-host-protocol-version,rpc-abi-version,rpc-abi-build,plugin-abi
            replay_refusal=identity-mismatch
            local_artifacts=non-passing-or-interactive-session
            remote_verify_artifacts=skipped-without-producer-provenance
            e2e_dependency=checks.crucible.phase7.reproductionProvenanceTriple
            RESULT
          '';
        }
      ];
    }
