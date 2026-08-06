{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleReleaseManifest",
  taskIds ? ["T-PKG-19"],
  cruciblePackage ? pkgs.crucible,
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  releaseManifestNix = builtins.readFile ../../pkgs/tools/crucible/_release-manifest.nix;
  cruciblePackageNix = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;
  pluginPackageNix = builtins.readFile ../../pkgs/emulation/crucible-qemu-plugin.nix;
  qemuPackageNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  sourceNix = builtins.readFile ../../pkgs/tools/crucible/_source.nix;
  defaultChecks = builtins.readFile ./default.nix;
  shmemLib = import ./_crucible-shmem-source.nix {inherit lib;};
  protocolLib = builtins.readFile ../../crates/crucible-protocol/src/lib.rs;
  apiRpcAbi = builtins.readFile ../../crates/crucible-api/src/rpc_abi.rs;
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};

  firstLineWith = label: prefix: content: let
    matches = builtins.filter (line: lib.hasPrefix prefix line) (lib.splitString "\n" content);
  in
    if matches == []
    then throw "crucible phase7 release manifest check failed: missing ${label}"
    else builtins.head matches;
  sourceConst = label: prefix: content:
    lib.removeSuffix ";"
    (lib.removePrefix prefix (firstLineWith label prefix content));
  sourceStringConst = label: prefix: content:
    lib.removeSuffix "\";"
    (lib.removePrefix prefix (firstLineWith label prefix content));
  crucibleVersion = sourceStringConst "Crucible package version" "  version = \"" cruciblePackageNix;
  crucibleCargoDepsHash = sourceStringConst "Crucible cargo deps hash" "  cargoDepsHash = \"" cruciblePackageNix;
  pluginCargoDepsHash = sourceStringConst "plugin cargo deps hash" "      hash = \"" pluginPackageNix;
  shmemAbiVersion = sourceConst "shmem ABI version" "pub const ABI_VERSION: u32 = " shmemLib;
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
  shmemAbi = "crucible-shmem-abi-v${shmemAbiVersion}";
  guestHostProtocolAbi = "crucible-guest-host-channel-v${guestHostProtocolVersion}";
  rpcAbi = "crucible-rpc-abi-v${rpcAbiVersion}+${rpcProtocolBuild}";
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
  releaseManifest = import ../../pkgs/tools/crucible/_release-manifest.nix {
    inherit lib;
    version = crucibleVersion;
    src = crucibleSrc;
    cargoDepsHash = crucibleCargoDepsHash;
    qemuPackage = qemuPackageMetadataProbe;
  };
  manifest = releaseManifest.manifest;
  manifestEnv = releaseManifest.envText;
  manifestJson = releaseManifest.jsonText;
  sourceStoreName = baseNameOf crucibleSrc;
  sourceStoreHash = builtins.substring 0 32 sourceStoreName;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  forbiddenTimestampNeedles = [
    {
      label = "builtins current time";
      needle = "builtins.currentTime";
    }
    {
      label = "shell date substitution";
      needle = "$(date";
    }
    {
      label = "shell date backtick";
      needle = "`date";
    }
    {
      label = "shell UTC date";
      needle = "date -u";
    }
    {
      label = "shell formatted date";
      needle = "date +";
    }
    {
      label = "C compile date";
      needle = "__DATE__";
    }
    {
      label = "C compile time";
      needle = "__TIME__";
    }
  ];
  timestampFailuresFor = fileLabel: content:
    lib.concatMap (
      forbidden:
        lib.optionals (hasInfix forbidden.needle content) [
          "${fileLabel}: forbidden embedded timestamp source (${forbidden.label}) `${forbidden.needle}`"
        ]
    )
    forbiddenTimestampNeedles;

  failures =
    lib.optionals (manifest.schemaVersion != 1) [
      "release manifest schema version is not 1"
    ]
    ++ lib.optionals (manifest.crucible.version != crucibleVersion) [
      "release manifest Crucible version ${manifest.crucible.version} does not match package version ${crucibleVersion}"
    ]
    ++ lib.optionals (manifest.crucible.cargoDeps.hash != crucibleCargoDepsHash) [
      "release manifest cargo deps hash ${manifest.crucible.cargoDeps.hash} does not match package hash ${crucibleCargoDepsHash}"
    ]
    ++ lib.optionals (manifest.crucible.cargoDeps.kind != "fetchCargoDeps") [
      "release manifest cargo deps kind is not fetchCargoDeps"
    ]
    ++ lib.optionals (!manifest.crucible.cargoDeps.vendored) [
      "release manifest does not mark cargo deps as vendored"
    ]
    ++ lib.optionals (manifest.crucible.source.sourceStoreName != sourceStoreName) [
      "release manifest source store name ${manifest.crucible.source.sourceStoreName} does not match filtered source ${sourceStoreName}"
    ]
    ++ lib.optionals (manifest.crucible.source.sourceStoreHash != sourceStoreHash) [
      "release manifest source store hash ${manifest.crucible.source.sourceStoreHash} does not match filtered source hash ${sourceStoreHash}"
    ]
    ++ lib.optionals (pluginCargoDepsHash != crucibleCargoDepsHash) [
      "crucible-qemu-plugin cargo deps hash ${pluginCargoDepsHash} does not match Crucible workspace hash ${crucibleCargoDepsHash}"
    ]
    ++ lib.optionals (manifest.qemu.version != qemuPackageMetadataProbe.series.qemuVersion) [
      "release manifest QEMU version ${manifest.qemu.version} does not match QEMU series ${qemuPackageMetadataProbe.series.qemuVersion}"
    ]
    ++ lib.optionals (manifest.qemu.sourceHash != qemuPackageMetadataProbe.series.qemuSourceHash) [
      "release manifest QEMU source hash does not match QEMU series"
    ]
    ++ lib.optionals (manifest.qemu.patchSeriesHash != qemuPackageMetadataProbe.patchSeriesHash) [
      "release manifest QEMU patch series hash does not match qemu-crucible passthru"
    ]
    ++ lib.optionals (manifest.qemu.patchBranchBundleHash != qemuPackageMetadataProbe.patchBranchBundleHash) [
      "release manifest QEMU patch branch bundle hash does not match qemu-crucible passthru"
    ]
    ++ lib.optionals (manifest.qemu.patchBranchMaterialHash != qemuPackageMetadataProbe.patchBranchMaterialHash) [
      "release manifest QEMU patch branch material hash does not match qemu-crucible passthru"
    ]
    ++ lib.optionals (manifest.qemu.buildId != qemuPackageMetadataProbe.qemuBuildIdentity) [
      "release manifest QEMU build identity does not match qemu-crucible passthru"
    ]
    ++ lib.optionals (manifest.components.boundaryCrates.license != "MIT") [
      "release manifest does not record the GPL plugin's MIT boundary-crate license selection"
    ]
    ++ lib.optionals (manifest.components.boundaryCrates.packages != ["crucible-protocol" "crucible-shmem"]) [
      "release manifest boundary-crate inventory is incomplete"
    ]
    ++ lib.optionals (
      manifest.components.debugGateway.package
      != "crucible-debug-gateway"
      || manifest.components.debugGateway.license != "GPL-2.0-only"
      || manifest.components.debugGateway.boundary != "separate-process-qemu-rsp-owner"
      || manifest.components.debugGateway.source != "crucible.workspace"
    ) [
      "release manifest debugger gateway component is incomplete"
    ]
    ++ lib.optionals (
      manifest.components.gdb.package
      != "gdb"
      || manifest.components.gdb.license != "GPL-3.0-or-later"
      || manifest.components.gdb.boundary != "operator-debugger-client"
    ) [
      "release manifest GDB component is incomplete"
    ]
    ++ lib.optionals (manifest.components.qemu.licenses != ["GPL-2.0-only" "GPL-2.0-or-later" "MIT"]) [
      "release manifest QEMU component license inventory is incomplete"
    ]
    ++ lib.optionals (manifest.components.qemu.combinedWorkLicense != "GPL-2.0-only") [
      "release manifest QEMU combined-work license is inaccurate"
    ]
    ++ lib.optionals (manifest.components.qemu.createdSourceLicense != "GPL-2.0-or-later") [
      "release manifest QEMU created-source license is inaccurate"
    ]
    ++ lib.optionals (manifest.components.qemu.generatedBoundaryHeaderLicenseOption != "MIT") [
      "release manifest QEMU boundary-header license option is inaccurate"
    ]
    ++ lib.optionals manifest.components.qemu.standaloneRelease [
      "release manifest must mark patched QEMU non-standalone"
    ]
    ++ lib.optionals (manifest.components.qemu.releaseVia != "crucible") [
      "release manifest must route patched QEMU through the suite"
    ]
    ++ lib.optionals (manifest.components.correspondingSource.licenses != ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later"]) [
      "release manifest corresponding-source license inventory is incomplete"
    ]
    ++ lib.optionals (manifest.licensing.licenses != ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later" "GPL-3.0-or-later"]) [
      "release manifest aggregate project license inventory is incomplete"
    ]
    ++ lib.optionals (manifest.licensing.licenseSetScope != "primary-project-components") [
      "release manifest does not distinguish its project component license set"
    ]
    ++ lib.optionals (manifest.publication.rootPackage != "crucible" || manifest.publication.rawQemuAllowed) [
      "release manifest publication root policy is inaccurate"
    ]
    ++ lib.optionals (manifest.publication.correspondingSourcePath != manifest.components.correspondingSource.path) [
      "release manifest publication source pairing drifted"
    ]
    ++ lib.optionals (manifest.licensing.thirdPartyLicenseMetadata != "vendored-source-manifests") [
      "release manifest does not identify the location of third-party license metadata"
    ]
    ++ lib.optionals (manifest.abi.shmem.version != shmemAbiVersion) [
      "release manifest shmem ABI ${manifest.abi.shmem.version} does not match Rust ABI ${shmemAbiVersion}"
    ]
    ++ lib.optionals (manifest.abi.shmem.label != shmemAbi) [
      "release manifest shmem ABI label ${manifest.abi.shmem.label} does not match ${shmemAbi}"
    ]
    ++ lib.optionals (manifest.abi.shmem.generatedHeaderHash != qemuPackageMetadataProbe.shmemHeaderHash) [
      "release manifest shmem generated header hash does not match qemu-crucible passthru"
    ]
    ++ lib.optionals (manifest.abi.guestHostChannel.version != guestHostProtocolVersion) [
      "release manifest guest-host version ${manifest.abi.guestHostChannel.version} does not match Rust protocol ${guestHostProtocolVersion}"
    ]
    ++ lib.optionals (manifest.abi.guestHostChannel.label != guestHostProtocolAbi) [
      "release manifest guest-host label ${manifest.abi.guestHostChannel.label} does not match ${guestHostProtocolAbi}"
    ]
    ++ lib.optionals (manifest.abi.rpc.version != rpcAbiVersion) [
      "release manifest RPC ABI ${manifest.abi.rpc.version} does not match Rust RPC ABI ${rpcAbiVersion}"
    ]
    ++ lib.optionals (manifest.abi.rpc.build != rpcProtocolBuild) [
      "release manifest RPC build ${manifest.abi.rpc.build} does not match Rust RPC build ${rpcProtocolBuild}"
    ]
    ++ lib.optionals (manifest.abi.rpc.label != rpcAbi) [
      "release manifest RPC label ${manifest.abi.rpc.label} does not match ${rpcAbi}"
    ]
    ++ lib.optionals (manifest.reproducibility.timestampPolicy != "no-wall-clock-timestamps") [
      "release manifest timestamp policy is not no-wall-clock-timestamps"
    ]
    ++ lib.optionals (manifest.reproducibility.hostPathPolicy != "no-host-paths") [
      "release manifest host path policy is not no-host-paths"
    ]
    ++ lib.optionals (!(builtins.elem "qemu.sourceHash" manifest.reproducibility.pinnedHashes)) [
      "release manifest pinned hash list does not include qemu.sourceHash"
    ]
    ++ lib.optionals (!(builtins.elem "qemu.patchSeriesHash" manifest.reproducibility.pinnedHashes)) [
      "release manifest pinned hash list does not include qemu.patchSeriesHash"
    ]
    ++ lib.optionals (!(builtins.elem "crucible.cargoDeps.hash" manifest.reproducibility.pinnedHashes)) [
      "release manifest pinned hash list does not include crucible.cargoDeps.hash"
    ]
    ++ lib.optionals (!(builtins.elem "crucible.source.sourceStoreHash" manifest.reproducibility.pinnedHashes)) [
      "release manifest pinned hash list does not include crucible.source.sourceStoreHash"
    ]
    ++ lib.optionals (!(builtins.elem "qemu_patch_series_hash" manifest.reproducibility.qemuBuildIdentityFields)) [
      "release manifest QEMU build identity field list does not include qemu_patch_series_hash"
    ]
    ++ lib.optionals (!(builtins.elem "qemu_shmem_abi_version" manifest.reproducibility.qemuBuildIdentityFields)) [
      "release manifest QEMU build identity field list does not include qemu_shmem_abi_version"
    ]
    ++ failuresFor "pkgs/tools/crucible/_release-manifest.nix" releaseManifestNix [
      {
        label = "manifest reads package inventory";
        needle = "packages = import ./_packages.nix;";
      }
      {
        label = "manifest records Crucible version";
        needle = "inherit version;";
      }
      {
        label = "manifest records source store hash";
        needle = "sourceStoreHash = builtins.substring 0 32 sourceStoreName;";
      }
      {
        label = "manifest records QEMU source hash";
        needle = "sourceHash = qemuSeries.qemuSourceHash;";
      }
      {
        label = "manifest records QEMU patch series hash";
        needle = "patchSeriesHash = qemuPassthru.patchSeriesHash;";
      }
      {
        label = "manifest records QEMU build identity";
        needle = "buildId = qemuPassthru.qemuBuildIdentity;";
      }
      {
        label = "manifest records shmem ABI source";
        needle = "pub const ABI_VERSION: u32 = ";
      }
      {
        label = "manifest records guest-host ABI source";
        needle = "pub const CONTROL_PROTOCOL_VERSION: u32 = ";
      }
      {
        label = "manifest records RPC ABI source";
        needle = "pub const RPC_PROTOCOL_MAJOR: u16 = ";
      }
      {
        label = "manifest records no timestamp policy";
        needle = "timestampPolicy = \"no-wall-clock-timestamps\";";
      }
      {
        label = "manifest records host path policy";
        needle = "hostPathPolicy = \"no-host-paths\";";
      }
      {
        label = "manifest records MIT boundary-crate selection";
        needle = "license = \"MIT\";\n        selection = \"gpl-plugin-consumption\";";
      }
      {
        label = "manifest scopes aggregate licenses to project components";
        needle = "licenseSetScope = \"primary-project-components\";";
      }
      {
        label = "manifest locates third-party license metadata";
        needle = "thirdPartyLicenseMetadata = \"vendored-source-manifests\";";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible/crucible.nix" cruciblePackageNix [
      {
        label = "release manifest imported";
        needle = "releaseManifest = import ./_release-manifest.nix";
      }
      {
        label = "release manifest uses qemu-crucible package metadata";
        needle = "qemuPackage = qemu-crucible;";
      }
      {
        label = "cargo deps hash is shared manifest input";
        needle = "hash = cargoDepsHash;";
      }
      {
        label = "release manifest env installed";
        needle = "$out/share/aos/crucible/release-manifest.env";
      }
      {
        label = "release manifest JSON installed";
        needle = "$out/share/aos/crucible/release-manifest.json";
      }
      {
        label = "release manifest env text emitted";
        needle = "releaseManifest.envText";
      }
      {
        label = "release manifest JSON text emitted";
        needle = "releaseManifest.jsonText";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuPackageNix [
      {
        label = "QEMU source hash pinned from series";
        needle = "hash = series.qemuSourceHash;";
      }
      {
        label = "QEMU patch series hash calculated from patch files";
        needle = "patchSeriesHash = builtins.hashString \"sha256\" patchSeriesHashMaterial;";
      }
      {
        label = "QEMU build identity installed";
        needle = "$out/share/aos/crucible/qemu-build-identity.env";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPackageNix [
      {
        label = "plugin cargo deps vendored";
        needle = "cargoDeps = fetchCargoDeps";
      }
      {
        label = "plugin cargo deps source root";
        needle = "sourceRoot = \"source/crates\";";
      }
      {
        label = "plugin cargo deps hash";
        needle = "hash = \"${crucibleCargoDepsHash}\";";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible/_source.nix" sourceNix [
      {
        label = "source filter excludes git";
        needle = "!= \".git\"";
      }
      {
        label = "source filter excludes target";
        needle = "base != \"target\"";
      }
      {
        label = "source filter excludes result";
        needle = "base != \"result\"";
      }
    ]
    ++ failuresFor "release manifest env" manifestEnv [
      {
        label = "Crucible version";
        needle = "crucible_version=${crucibleVersion}";
      }
      {
        label = "QEMU version";
        needle = "qemu_version=${qemuPackageMetadataProbe.series.qemuVersion}";
      }
      {
        label = "QEMU patch series hash";
        needle = "qemu_patch_series_hash=${qemuPackageMetadataProbe.patchSeriesHash}";
      }
      {
        label = "QEMU build identity";
        needle = "qemu_build_id=${qemuPackageMetadataProbe.qemuBuildIdentity}";
      }
      {
        label = "Crucible source store name";
        needle = "crucible_source_store_name=${sourceStoreName}";
      }
      {
        label = "Crucible source store hash";
        needle = "crucible_source_store_hash=${sourceStoreHash}";
      }
      {
        label = "shmem ABI";
        needle = "shmem_abi=${shmemAbi}";
      }
      {
        label = "guest-host ABI";
        needle = "guest_host_protocol_abi=${guestHostProtocolAbi}";
      }
      {
        label = "RPC ABI";
        needle = "rpc_abi=${rpcAbi}";
      }
      {
        label = "timestamp policy";
        needle = "reproducibility_timestamp_policy=no-wall-clock-timestamps";
      }
      {
        label = "aggregate project licenses include MIT";
        needle = "aggregate_licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later,GPL-3.0-or-later";
      }
      {
        label = "debug gateway component";
        needle = "debug_gateway_package=crucible-debug-gateway";
      }
      {
        label = "debug gateway process boundary";
        needle = "debug_gateway_boundary=separate-process-qemu-rsp-owner";
      }
      {
        label = "aggregate license scope";
        needle = "aggregate_license_scope=primary-project-components";
      }
      {
        label = "third-party metadata location";
        needle = "third_party_license_metadata=vendored-source-manifests";
      }
    ]
    ++ failuresFor "release manifest JSON" manifestJson [
      {
        label = "schema version";
        needle = "\"schemaVersion\":1";
      }
      {
        label = "QEMU patch series hash";
        needle = "\"patchSeriesHash\":\"${qemuPackageMetadataProbe.patchSeriesHash}\"";
      }
      {
        label = "Crucible source store hash";
        needle = "\"sourceStoreHash\":\"${sourceStoreHash}\"";
      }
      {
        label = "RPC build";
        needle = "\"build\":\"${rpcProtocolBuild}\"";
      }
      {
        label = "debug gateway component";
        needle = "\"debugGateway\":{";
      }
      {
        label = "debug gateway GPL license";
        needle = "\"license\":\"GPL-2.0-only\"";
      }
      {
        label = "GDB component";
        needle = "\"gdb\":{";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 release manifest check imported";
        needle = "crucibleReleaseManifest = import ./phase7-crucible-release-manifest.nix";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-19 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleReleaseManifest`";
      }
      {
        label = "PKG-36 release manifest requirement";
        needle = "[PKG-36]";
      }
      {
        label = "PKG-37 reproducibility requirement";
        needle = "[PKG-37]";
      }
    ]
    ++ timestampFailuresFor "pkgs/tools/crucible/_release-manifest.nix" releaseManifestNix
    ++ timestampFailuresFor "pkgs/tools/crucible/crucible.nix" cruciblePackageNix
    ++ timestampFailuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPackageNix
    ++ timestampFailuresFor "pkgs/emulation/qemu.nix" qemuPackageNix;
in
  if failures != []
  then throw "crucible phase7 release manifest check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    builtins.derivation {
      name = "crucible-phase7-release-manifest-0";
      inherit (lib) system;
      builder = "${pkgs.bash}/bin/bash";
      PATH = "${pkgs.coreutils}/bin:${pkgs.grep}/bin";
      args = [
        "-c"
        ''
          set -eu
          mkdir -p "$out"

          manifest_env="$CRUCIBLE_PACKAGE/share/aos/crucible/release-manifest.env"
          manifest_json="$CRUCIBLE_PACKAGE/share/aos/crucible/release-manifest.json"
          test -f "$manifest_env"
          test -f "$manifest_json"
          grep -q "^crucible_version=$CRUCIBLE_VERSION$" "$manifest_env"
          grep -q "^crucible_source_store_name=$CRUCIBLE_SOURCE_STORE_NAME$" "$manifest_env"
          grep -q "^crucible_source_store_hash=$CRUCIBLE_SOURCE_STORE_HASH$" "$manifest_env"
          grep -q "^qemu_version=$QEMU_VERSION$" "$manifest_env"
          grep -q "^qemu_patch_series_hash=$QEMU_PATCH_SERIES_HASH$" "$manifest_env"
          grep -q "^qemu_build_id=$QEMU_BUILD_ID$" "$manifest_env"
          grep -q "^shmem_abi=$SHMEM_ABI$" "$manifest_env"
          grep -q "^guest_host_protocol_abi=$GUEST_HOST_PROTOCOL_ABI$" "$manifest_env"
          grep -q "^rpc_abi=$RPC_ABI$" "$manifest_env"
          grep -q '^reproducibility_timestamp_policy=no-wall-clock-timestamps$' "$manifest_env"
          grep -q '^boundary_crates_license=MIT$' "$manifest_env"
          grep -q '^qemu_component_licenses=GPL-2.0-only,GPL-2.0-or-later,MIT$' "$manifest_env"
          grep -q '^qemu_combined_work_license=GPL-2.0-only$' "$manifest_env"
          grep -q '^qemu_created_source_license=GPL-2.0-or-later$' "$manifest_env"
          grep -q '^qemu_generated_boundary_header_license_option=MIT$' "$manifest_env"
          grep -q '^qemu_standalone_release=false$' "$manifest_env"
          grep -q '^qemu_release_via=crucible$' "$manifest_env"
          grep -q '^gdb_package=gdb$' "$manifest_env"
          grep -q '^gdb_license=GPL-3.0-or-later$' "$manifest_env"
          grep -q '^gdb_boundary=operator-debugger-client$' "$manifest_env"
          grep -q '^aggregate_licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later,GPL-3.0-or-later$' "$manifest_env"
          grep -q '^aggregate_license_scope=primary-project-components$' "$manifest_env"
          grep -q '^third_party_license_metadata=vendored-source-manifests$' "$manifest_env"
          grep -q '^publication_root_package=crucible$' "$manifest_env"
          grep -q '^publication_raw_qemu_allowed=false$' "$manifest_env"
          grep -q '^publication_policy=aggregate-direct-reference-pair$' "$manifest_env"
          grep -q "\"sourceStoreHash\":\"$CRUCIBLE_SOURCE_STORE_HASH\"" "$manifest_json"
          grep -q "\"patchSeriesHash\":\"$QEMU_PATCH_SERIES_HASH\"" "$manifest_json"
          grep -q "\"buildId\":\"$QEMU_BUILD_ID\"" "$manifest_json"
          grep -q "\"label\":\"$RPC_ABI\"" "$manifest_json"

          {
            printf '%s\n' 'PASS'
            printf 'check=%s\n' "$ATTR_PATH"
            printf 'tasks=%s\n' "$TASK_IDS"
            printf 'crucible_version=%s\n' "$CRUCIBLE_VERSION"
            printf 'crucible_source_store_hash=%s\n' "$CRUCIBLE_SOURCE_STORE_HASH"
            printf 'qemu_version=%s\n' "$QEMU_VERSION"
            printf 'qemu_patch_series_hash=%s\n' "$QEMU_PATCH_SERIES_HASH"
            printf 'qemu_build_id=%s\n' "$QEMU_BUILD_ID"
            printf 'shmem_abi=%s\n' "$SHMEM_ABI"
            printf 'guest_host_protocol_abi=%s\n' "$GUEST_HOST_PROTOCOL_ABI"
            printf 'rpc_abi=%s\n' "$RPC_ABI"
            printf '%s\n' 'cargo_deps=fetchCargoDeps'
            printf '%s\n' 'cargo_deps_vendored=true'
            printf '%s\n' 'timestamp_policy=no-wall-clock-timestamps'
            printf '%s\n' 'host_path_policy=no-host-paths'
          } > "$out/result"
        ''
      ];
      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      CRUCIBLE_PACKAGE = cruciblePackage;
      CRUCIBLE_VERSION = crucibleVersion;
      CRUCIBLE_SOURCE_STORE_NAME = sourceStoreName;
      CRUCIBLE_SOURCE_STORE_HASH = sourceStoreHash;
      QEMU_VERSION = qemuPackageMetadataProbe.series.qemuVersion;
      QEMU_PATCH_SERIES_HASH = qemuPackageMetadataProbe.patchSeriesHash;
      QEMU_BUILD_ID = qemuPackageMetadataProbe.qemuBuildIdentity;
      SHMEM_ABI = shmemAbi;
      GUEST_HOST_PROTOCOL_ABI = guestHostProtocolAbi;
      RPC_ABI = rpcAbi;
    }
