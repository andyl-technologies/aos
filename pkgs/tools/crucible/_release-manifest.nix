{
  lib,
  qemuPackage,
  version,
  src,
  cargoDepsHash,
}: let
  packages = import ./_packages.nix;
  crateRoot = ../../../crates;
  shmemLib = builtins.readFile (crateRoot + "/crucible-shmem/src/lib.rs");
  protocolLib = builtins.readFile (crateRoot + "/crucible-protocol/src/lib.rs");
  apiRpcAbi = builtins.readFile (crateRoot + "/crucible-api/src/rpc_abi.rs");
  firstLineWith = label: prefix: content: let
    matches = builtins.filter (line: lib.hasPrefix prefix line) (lib.splitString "\n" content);
  in
    if matches == []
    then throw "crucible release manifest failed to read ${label}"
    else builtins.head matches;
  sourceConst = label: prefix: content:
    lib.removeSuffix ";"
    (lib.removePrefix prefix (firstLineWith label prefix content));
  sourceStringConst = label: prefix: content:
    lib.removeSuffix "\";"
    (lib.removePrefix prefix (firstLineWith label prefix content));
  tomlStringConst = label: prefix: content:
    lib.removeSuffix "\""
    (lib.removePrefix prefix (firstLineWith label prefix content));
  packageVersion = package:
    tomlStringConst
    "crate ${package} version"
    "version = \""
    (builtins.readFile (crateRoot + "/${package}/Cargo.toml"));
  packageVersions =
    builtins.listToAttrs
    (map (package: {
        name = package;
        value = packageVersion package;
      })
      packages);
  mismatchedPackageVersions = builtins.filter (package: packageVersions.${package} != version) packages;
  qemuPassthru = qemuPackage.passthru or qemuPackage;
  qemuSeries = qemuPassthru.series;
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
  sourceStoreName = baseNameOf src;
  sourceStoreHash = builtins.substring 0 32 sourceStoreName;
  qemuBuildIdentityFields = [
    "qemu_version"
    "qemu_source_hash"
    "qemu_nix_hash"
    "qemu_configure_flags_hash"
    "qemu_patch_series_hash"
    "qemu_patch_branch_bundle_hash"
    "qemu_patch_branch_material_hash"
    "qemu_shmem_abi_version"
    "qemu_shmem_header_hash"
  ];
  manifest = {
    schemaVersion = 1;
    crucible = {
      inherit version;
      workspacePackages = packages;
      workspacePackageVersions = packageVersions;
      cargoDeps = {
        kind = "fetchCargoDeps";
        sourceRoot = "source/crates";
        hash = cargoDepsHash;
        vendored = true;
      };
      source = {
        rootName = "crucible-workspace-src";
        inherit sourceStoreName sourceStoreHash;
        excludedPathBasenames = [".git" "target" "result"];
      };
    };
    qemu = {
      package = "qemu-crucible";
      version = qemuSeries.qemuVersion;
      sourceUrl = qemuSeries.qemuSourceUrl;
      sourceHash = qemuSeries.qemuSourceHash;
      patchBranchRef = qemuSeries.patchBranchRef;
      patchSeriesHash = qemuPassthru.patchSeriesHash;
      patchBranchBundleHash = qemuPassthru.patchBranchBundleHash;
      patchBranchMaterialHash = qemuPassthru.patchBranchMaterialHash;
      buildId = qemuPassthru.qemuBuildIdentity;
      deterministicBaseDate = qemuSeries.deterministicBaseDate;
      deterministicPatchDate = qemuSeries.deterministicPatchDate;
    };
    abi = {
      shmem = {
        version = shmemAbiVersion;
        label = shmemAbi;
        generatedHeaderHash = qemuPassthru.shmemHeaderHash;
      };
      guestHostChannel = {
        version = guestHostProtocolVersion;
        label = guestHostProtocolAbi;
      };
      rpc = {
        version = rpcAbiVersion;
        build = rpcProtocolBuild;
        label = rpcAbi;
      };
    };
    reproducibility = {
      timestampPolicy = "no-wall-clock-timestamps";
      hostPathPolicy = "no-host-paths";
      pinnedHashes = [
        "crucible.cargoDeps.hash"
        "crucible.source.sourceStoreHash"
        "qemu.sourceHash"
        "qemu.patchSeriesHash"
        "qemu.patchBranchBundleHash"
        "qemu.patchBranchMaterialHash"
        "abi.shmem.generatedHeaderHash"
      ];
      inherit qemuBuildIdentityFields;
    };
  };
  envText = ''
    manifest_schema_version=1
    crucible_version=${version}
    crucible_workspace_packages=${builtins.concatStringsSep "," packages}
    cargo_deps=fetchCargoDeps
    cargo_deps_source_root=source/crates
    cargo_deps_hash=${cargoDepsHash}
    cargo_deps_vendored=true
    crucible_source_store_name=${sourceStoreName}
    crucible_source_store_hash=${sourceStoreHash}
    qemu_package=qemu-crucible
    qemu_version=${manifest.qemu.version}
    qemu_source_url=${manifest.qemu.sourceUrl}
    qemu_source_hash=${manifest.qemu.sourceHash}
    qemu_patch_branch_ref=${manifest.qemu.patchBranchRef}
    qemu_patch_series_hash=${manifest.qemu.patchSeriesHash}
    qemu_patch_branch_bundle_hash=${manifest.qemu.patchBranchBundleHash}
    qemu_patch_branch_material_hash=${manifest.qemu.patchBranchMaterialHash}
    qemu_build_id=${manifest.qemu.buildId}
    shmem_abi_version=${shmemAbiVersion}
    shmem_abi=${shmemAbi}
    shmem_generated_header_hash=${manifest.abi.shmem.generatedHeaderHash}
    guest_host_protocol_version=${guestHostProtocolVersion}
    guest_host_protocol_abi=${guestHostProtocolAbi}
    rpc_abi_version=${rpcAbiVersion}
    rpc_abi_build=${rpcProtocolBuild}
    rpc_abi=${rpcAbi}
    reproducibility_timestamp_policy=${manifest.reproducibility.timestampPolicy}
    reproducibility_host_path_policy=${manifest.reproducibility.hostPathPolicy}
    reproducibility_pinned_hashes=${builtins.concatStringsSep "," manifest.reproducibility.pinnedHashes}
    qemu_build_identity_fields=${builtins.concatStringsSep "," qemuBuildIdentityFields}
  '';
in
  if mismatchedPackageVersions != []
  then throw "crucible release manifest version mismatch: ${builtins.concatStringsSep ", " mismatchedPackageVersions}"
  else {
    inherit manifest envText;
    jsonText = builtins.toJSON manifest;
  }
