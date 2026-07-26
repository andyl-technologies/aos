{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.cruciblePackageAbiVersioning",
  taskIds ? ["T-PKG-10"],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  qemuPackageNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  pluginPackageNix = builtins.readFile ../../pkgs/emulation/crucible-qemu-plugin.nix;
  cruciblePackageNix = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;
  workspaceBuildCheck = builtins.readFile ./phase1-aos-workspace-build.nix;
  abiConformanceCheck = builtins.readFile ./phase2-abi-conformance.nix;
  patchRegenerationCheck = builtins.readFile ./phase2-qemu-patch-regeneration.nix;
  patchMicrotestsCheck = builtins.readFile ./phase2-patch-microtests.nix;
  cliHermeticDiscoveryCheck = builtins.readFile ./phase5-cli-hermetic-discovery.nix;
  cliMain = import ./_cli-source.nix {inherit lib;};
  shmemLib =
    builtins.readFile ../../crates/crucible-shmem/src/lib.rs
    + builtins.readFile ../../crates/crucible-shmem/src/shmem/region.rs;
  shmemHeader = builtins.readFile ../../crates/crucible-shmem/include/crucible_shmem_abi.h;
  shmemHeaderTest = builtins.readFile ../../crates/crucible-shmem/tests/generated_abi_header.rs;
  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  protocolGoldenVectors = builtins.readFile ../../crates/crucible-protocol/src/golden_vectors.rs;
  apiRpcAbi = builtins.readFile ../../crates/crucible-api/src/rpc_abi.rs;
  apiAbiGate = builtins.readFile ../../crates/crucible-api/tests/gate_abi_conformance.rs;
  defaultChecks = builtins.readFile ./default.nix;

  firstLineWith = label: prefix: content: let
    matches = builtins.filter (line: lib.hasPrefix prefix line) (lib.splitString "\n" content);
  in
    if matches == []
    then throw "crucible phase7 ABI versioning check failed: missing ${label}"
    else builtins.head matches;
  sourceConst = label: prefix: content:
    lib.removeSuffix ";"
    (lib.removePrefix prefix (firstLineWith label prefix content));
  sourceStringConst = label: prefix: content:
    lib.removeSuffix "\";"
    (lib.removePrefix prefix (firstLineWith label prefix content));

  shmemAbiVersion = sourceConst "shmem ABI version" "pub const ABI_VERSION: u32 = " shmemLib;
  guestHostProtocolVersion = sourceConst "guest-host protocol version" "pub const CONTROL_PROTOCOL_VERSION: u32 = " protocolLib;
  rpcProtocolMajor = sourceConst "RPC ABI major version" "pub const RPC_PROTOCOL_MAJOR: u16 = " apiRpcAbi;
  rpcProtocolMinor = sourceConst "RPC ABI minor version" "pub const RPC_PROTOCOL_MINOR: u16 = " apiRpcAbi;
  rpcProtocolPatch = sourceConst "RPC ABI patch version" "pub const RPC_PROTOCOL_PATCH: u16 = " apiRpcAbi;
  rpcProtocolBuild = sourceStringConst "RPC ABI build tag" "pub const RPC_PROTOCOL_BUILD: &str = \"" apiRpcAbi;
  rpcAbiVersion = "${rpcProtocolMajor}.${rpcProtocolMinor}.${rpcProtocolPatch}";
  shmemAbi = "crucible-shmem-abi-v${shmemAbiVersion}";
  guestHostProtocolAbi = "crucible-guest-host-channel-v${guestHostProtocolVersion}";
  shmemHeaderHash = builtins.hashFile "sha256" ../../crates/crucible-shmem/include/crucible_shmem_abi.h;
  qemuPackageMetadataProbe = import ../../pkgs/emulation/qemu.nix {
    inherit lib;
    pname = "qemu-crucible";
    enablePlugins = true;
    applyCruciblePatches = true;
    mkDerivation = args: let
      passthru = args.passthru or {};
    in
      args // passthru;
    fetchurl = args: args;
    gnumake = null;
    pkg-config = null;
    meson = null;
    ninja = null;
    python3 = "/aos-python3";
    setuptools = null;
    distlib = null;
    glib = null;
    pixman = null;
    zlib = null;
    libslirp = null;
    dtc = null;
  };
  qemuPackageShmemAbi = qemuPackageMetadataProbe.shmemAbi;
  qemuPackageShmemAbiVersion = qemuPackageMetadataProbe.shmemAbiVersion;
  qemuPackageShmemHeaderHash = qemuPackageMetadataProbe.shmemHeaderHash;
  qemuPackageShmemHeaderInstallPath = qemuPackageMetadataProbe.shmemHeaderInstallPath;
  qemuIdentityMaterialLine = "qemu_build_id_material_includes=qemu_version,qemu_source_hash,qemu_nix_hash,qemu_configure_flags_hash,patch_series_hash,patch_branch_bundle_hash,patch_branch_material_hash,qemu_shmem_abi_version,qemu_shmem_header_hash";

  hasInfix = needle: haystack:
    needle == ""
    || builtins.replaceStrings [needle] [""] haystack != haystack;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    lib.optionals (qemuPackageShmemAbiVersion != shmemAbiVersion) [
      "pkgs.qemu-crucible: passthru shmem ABI version ${qemuPackageShmemAbiVersion} does not match Rust ABI version ${shmemAbiVersion}"
    ]
    ++ lib.optionals (qemuPackageShmemAbi != shmemAbi) [
      "pkgs.qemu-crucible: passthru shmem ABI ${qemuPackageShmemAbi} does not match Rust ABI ${shmemAbi}"
    ]
    ++ lib.optionals (qemuPackageShmemHeaderHash != shmemHeaderHash) [
      "pkgs.qemu-crucible: passthru shmem header hash ${qemuPackageShmemHeaderHash} does not match committed generated header hash ${shmemHeaderHash}"
    ]
    ++ lib.optionals (qemuPackageShmemHeaderInstallPath != "include/aos/crucible/crucible_shmem_abi.h") [
      "pkgs.qemu-crucible: passthru shmem header install path ${qemuPackageShmemHeaderInstallPath} is not the canonical generated header install path"
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-10 checklist complete";
        needle = "- [x] **T-PKG-10**";
      }
      {
        label = "T-PKG-10 completion note";
        needle = "Completed by `checks.crucible.phase7.cruciblePackageAbiVersioning`";
      }
      {
        label = "phase1 smoke reference";
        needle = "`checks.crucible.phase1.aosWorkspaceBuild`";
      }
      {
        label = "phase2 ABI conformance reference";
        needle = "`checks.crucible.phase2.abiConformance`";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuPackageNix [
      {
        label = "generated shmem header input";
        needle = "shmemGeneratedHeader = ../../crates/crucible-shmem/include/crucible_shmem_abi.h;";
      }
      {
        label = "generated shmem header hash";
        needle = "shmemHeaderHash = builtins.hashFile \"sha256\" shmemGeneratedHeader;";
      }
      {
        label = "QEMU build copies generated shmem header";
        needle = "cp " + "$" + "{shmemGeneratedHeader} include/aos/crucible/crucible_shmem_abi.h";
      }
      {
        label = "QEMU package C-side generated header probe";
        needle = "qemu-crucible-shmem-abi-probe.c";
      }
      {
        label = "QEMU package C-side ABI version probe";
        needle = "CRUCIBLE_EXPECTED_SHMEM_ABI_VERSION";
      }
      {
        label = "QEMU installs generated shmem header";
        needle = "install -m 644 include/aos/crucible/crucible_shmem_abi.h";
      }
      {
        label = "QEMU sim-capability marker";
        needle = "qemu_sim_capability=" + "$" + "{qemuSimCapability}";
      }
      {
        label = "QEMU shmem ABI version marker";
        needle = "qemu_shmem_abi_version=" + "$" + "{shmemAbiVersion}";
      }
      {
        label = "QEMU shmem ABI marker";
        needle = "qemu_shmem_abi=" + "$" + "{shmemAbi}";
      }
      {
        label = "QEMU shmem header hash marker";
        needle = "qemu_shmem_header_hash=" + "$" + "{shmemHeaderHash}";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPackageNix [
      {
        label = "plugin C probe includes generated shmem header";
        needle = "#include <aos/crucible/crucible_shmem_abi.h>";
      }
      {
        label = "plugin C probe compares generated header ABI";
        needle = "CRUCIBLE_EXPECTED_SHMEM_ABI_VERSION";
      }
      {
        label = "plugin records QEMU sim-capability marker";
        needle = "qemu_sim_capability_marker=" + "$" + "{qemu-crucible}/share/aos/crucible/qemu-build-identity.env";
      }
      {
        label = "plugin records shared generated header path";
        needle = "shmem_generated_header=" + "$" + "{qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h";
      }
      {
        label = "plugin records shared generated header hash";
        needle = "shmem_generated_header_hash=" + "$" + "{qemu-crucible.passthru.shmemHeaderHash}";
      }
      {
        label = "plugin records shmem ABI version";
        needle = "shmem_abi_version=$shmem_abi_version";
      }
      {
        label = "plugin records shmem ABI label";
        needle = "shmem_abi=crucible-shmem-abi-v$shmem_abi_version";
      }
      {
        label = "plugin ABI marker remains shmem ABI";
        needle = "plugin_abi=crucible-shmem-abi-v$shmem_abi_version";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible/crucible.nix" cruciblePackageNix [
      {
        label = "CLI package reads shmem ABI source";
        needle = "shmemLib = builtins.readFile ../../../crates/crucible-shmem/src/lib.rs;";
      }
      {
        label = "CLI package reads guest-host protocol source";
        needle = "protocolLib = builtins.readFile ../../../crates/crucible-protocol/src/lib.rs;";
      }
      {
        label = "CLI package reads RPC ABI source";
        needle = "apiRpcAbi = builtins.readFile ../../../crates/crucible-api/src/rpc_abi.rs;";
      }
      {
        label = "CLI build-info shmem ABI version";
        needle = "shmem_abi_version=" + "$" + "{shmemAbiVersion}";
      }
      {
        label = "CLI build-info guest-host ABI";
        needle = "guest_host_protocol_abi=crucible-guest-host-channel-v" + "$" + "{guestHostProtocolVersion}";
      }
      {
        label = "CLI build-info RPC ABI";
        needle = "rpc_abi_version=" + "$" + "{rpcProtocolMajor}." + "$" + "{rpcProtocolMinor}." + "$" + "{rpcProtocolPatch}";
      }
      {
        label = "CLI build-info RPC build tag";
        needle = "rpc_abi_build=" + "$" + "{rpcProtocolBuild}";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "CLI requires QEMU sim capability";
        needle = "required_metadata_field(&fields, \"qemu_sim_capability\", &marker)?";
      }
      {
        label = "CLI reads QEMU shmem ABI marker";
        needle = "required_metadata_field(&fields, \"qemu_shmem_abi\", &marker)?";
      }
      {
        label = "CLI rejects QEMU/plugin shmem ABI mismatch";
        needle = "qemu_marker.shmem_abi != plugin_marker.plugin_abi";
      }
      {
        label = "CLI rejects QEMU/plugin shmem ABI version mismatch";
        needle = "qemu_marker.shmem_abi_version != plugin_marker.shmem_abi_version";
      }
      {
        label = "CLI rejects QEMU/plugin shmem header hash mismatch";
        needle = "qemu_marker.shmem_header_hash != plugin_marker.shmem_header_hash";
      }
      {
        label = "CLI validates marker ABI label from version";
        needle = "shmem_abi_label_for_version(&shmem_abi_version)";
      }
      {
        label = "CLI loud shmem ABI mismatch diagnostic";
        needle = "advertises shmem ABI";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "shmem ABI version constant";
        needle = "pub const ABI_VERSION: u32 = ${shmemAbiVersion};";
      }
      {
        label = "shmem setup loud ABI mismatch";
        needle = "RegionSetupValidationError::AbiVersionMismatch";
      }
      {
        label = "shmem generated C header export";
        needle = "pub use abi_header::generated_c_header;";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/include/crucible_shmem_abi.h" shmemHeader [
      {
        label = "committed generated shmem ABI version";
        needle = "#define CRUCIBLE_SHMEM_ABI_VERSION ${shmemAbiVersion}u";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/tests/generated_abi_header.rs" shmemHeaderTest [
      {
        label = "committed header equals generated Rust layout";
        needle = "committed_header_matches_generated_rust_layout";
      }
      {
        label = "header static asserts covered";
        needle = "generated_header_asserts_every_shared_struct_layout";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/lib.rs" protocolLib [
      {
        label = "guest-host protocol version constant";
        needle = "pub const CONTROL_PROTOCOL_VERSION: u32 = ${guestHostProtocolVersion};";
      }
      {
        label = "guest-host handshake loud ABI mismatch";
        needle = "HandshakeError::AbiMismatch";
      }
      {
        label = "guest-host shmem ABI mismatch diagnostic";
        needle = "shared-memory ABI mismatch";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/golden_vectors.rs" protocolGoldenVectors [
      {
        label = "guest-host golden vectors track protocol version";
        needle = "GOLDEN_VECTOR_PROTOCOL_VERSION == CONTROL_PROTOCOL_VERSION";
      }
    ]
    ++ failuresFor "crates/crucible-api/src/rpc_abi.rs" apiRpcAbi [
      {
        label = "RPC major version";
        needle = "pub const RPC_PROTOCOL_MAJOR: u16 = ${rpcProtocolMajor};";
      }
      {
        label = "RPC minor version";
        needle = "pub const RPC_PROTOCOL_MINOR: u16 = ${rpcProtocolMinor};";
      }
      {
        label = "RPC patch version";
        needle = "pub const RPC_PROTOCOL_PATCH: u16 = ${rpcProtocolPatch};";
      }
      {
        label = "RPC build tag";
        needle = "pub const RPC_PROTOCOL_BUILD: &str = \"${rpcProtocolBuild}\";";
      }
      {
        label = "RPC major mismatch fails loudly";
        needle = "RpcAbiError::MajorVersionMismatch";
      }
      {
        label = "RPC golden vectors track live version";
        needle = "GOLDEN_VECTOR_RPC_PROTOCOL_VERSION.major == RPC_PROTOCOL_VERSION.major";
      }
    ]
    ++ failuresFor "crates/crucible-api/tests/gate_abi_conformance.rs" apiAbiGate [
      {
        label = "RPC v2 gate assertion";
        needle = "assert_eq!(RPC_PROTOCOL_MAJOR, ${rpcProtocolMajor});";
      }
      {
        label = "RPC major mismatch gate assertion";
        needle = "RpcAbiError::MajorVersionMismatch";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-aos-workspace-build.nix" workspaceBuildCheck [
      {
        label = "phase1 smoke checks shmem ABI";
        needle = "grep -q '^shmem_abi=${shmemAbi}$'";
      }
      {
        label = "phase1 smoke checks guest-host ABI";
        needle = "grep -q '^guest_host_protocol_abi=${guestHostProtocolAbi}$'";
      }
      {
        label = "phase1 smoke checks RPC ABI";
        needle = "grep -q '^rpc_abi_version=${rpcAbiVersion}$'";
      }
      {
        label = "phase1 smoke checks QEMU sim capability";
        needle = "grep -q '^qemu_sim_capability=qemu-crucible$'";
      }
      {
        label = "phase1 smoke checks generated shmem header hash";
        needle = "grep -q '^qemu_shmem_header_hash=" + "$" + "{packages.qemu-crucible.passthru.shmemHeaderHash}$'";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-abi-conformance.nix" abiConformanceCheck [
      {
        label = "phase2 static ABI gate expects current RPC major";
        needle = "pub const RPC_PROTOCOL_MAJOR: u16 = ${rpcProtocolMajor};";
      }
      {
        label = "phase2 static ABI gate expects current RPC minor";
        needle = "pub const RPC_PROTOCOL_MINOR: u16 = ${rpcProtocolMinor};";
      }
      {
        label = "phase2 static ABI gate expects current RPC build";
        needle = "pub const RPC_PROTOCOL_BUILD: &str = \\\"${rpcProtocolBuild}\\\";";
      }
    ]
    ++ failuresFor "tests/crucible/phase2-qemu-patch-regeneration.nix" patchRegenerationCheck [
      {
        label = "patch regeneration checks QEMU shmem ABI marker";
        needle = "grep -q '^qemu_shmem_abi=" + "$" + "{shmemAbi}$' \"$identity_file\"";
      }
      {
        label = "patch regeneration checks QEMU shmem header hash marker";
        needle = "grep -q '^qemu_shmem_header_hash=" + "$" + "{shmemHeaderHash}$' \"$identity_file\"";
      }
      {
        label = "patch regeneration checks QEMU package C-side header probe";
        needle = "CRUCIBLE_EXPECTED_SHMEM_ABI_VERSION";
      }
      {
        label = "patch regeneration result records expanded build identity material";
        needle = qemuIdentityMaterialLine;
      }
    ]
    ++ failuresFor "tests/crucible/phase2-patch-microtests.nix" patchMicrotestsCheck [
      {
        label = "patch microtests require expanded build identity material";
        needle = qemuIdentityMaterialLine;
      }
    ]
    ++ failuresFor "tests/crucible/phase5-cli-hermetic-discovery.nix" cliHermeticDiscoveryCheck [
      {
        label = "phase5 validates QEMU marker";
        needle = "qemu_crucible_patches_applied";
      }
      {
        label = "phase5 validates plugin marker";
        needle = "plugin_marker.plugin_abi != required_plugin_abi";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 ABI versioning package check imported";
        needle = "cruciblePackageAbiVersioning = import ./phase7-crucible-package-abi-versioning.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 package ABI versioning check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    builtins.derivation {
      name = "crucible-phase7-package-abi-versioning-0";
      inherit (lib) system;
      builder = "${pkgs.bash}/bin/bash";
      PATH = "${pkgs.coreutils}/bin";
      args = [
        "-c"
        ''
          set -eu
          mkdir -p "$out"

          {
            printf '%s\n' 'PASS'
            printf 'check=%s\n' "$ATTR_PATH"
            printf 'tasks=%s\n' "$TASK_IDS"
            printf '%s\n' 'package=crucible'
            printf 'shmem_abi=%s\n' "$SHMEM_ABI"
            printf 'guest_host_protocol_abi=%s\n' "$GUEST_HOST_PROTOCOL_ABI"
            printf 'rpc_abi=%s+%s\n' "$RPC_ABI_VERSION" "$RPC_ABI_BUILD"
            printf '%s\n' 'qemu_sim_capability=qemu-crucible'
            printf 'generated_shmem_header=%s\n' "$QEMU_SHMEM_HEADER_INSTALL_PATH"
            printf 'generated_shmem_header_hash=%s\n' "$SHMEM_HEADER_HASH"
            printf '%s\n' 'mismatch_policy=loud'
            printf '%s\n' 'output_smoke=checks.crucible.phase1.aosWorkspaceBuild'
            printf '%s\n' 'abi_gate=checks.crucible.phase2.abiConformance'
            printf '%s\n' 'qemu_marker_gate=checks.crucible.phase2.qemuPatchRegeneration'
          } > "$out/result"
        ''
      ];
      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      SHMEM_ABI = shmemAbi;
      GUEST_HOST_PROTOCOL_ABI = guestHostProtocolAbi;
      RPC_ABI_VERSION = rpcAbiVersion;
      RPC_ABI_BUILD = rpcProtocolBuild;
      SHMEM_HEADER_HASH = shmemHeaderHash;
      QEMU_SHMEM_HEADER_INSTALL_PATH = qemuPackageShmemHeaderInstallPath;
    }
