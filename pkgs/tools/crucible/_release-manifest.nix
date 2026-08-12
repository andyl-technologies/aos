{
  lib,
  qemuPackage,
  version,
  src,
  cargoDepsHash,
  controllerPackage ? null,
  pluginPackage ? null,
  debugGatewayPackage ? null,
  gdbPackage ? null,
  sshPackage ? null,
  qemuSourcePackage ? null,
}: let
  packages = import ./_packages.nix;
  crateRoot = ../../../crates;
  shmemLib = builtins.readFile (crateRoot + "/crucible-shmem/src/lib.rs");
  protocolLib = builtins.readFile (crateRoot + "/crucible-protocol/src/lib.rs");
  doorbellAbi = builtins.readFile (crateRoot + "/crucible-protocol/src/doorbell_abi.rs");
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
  componentPath = package:
    if package == null
    then "unavailable"
    else if builtins.isAttrs package && !(package ? outPath)
    then "metadata-probe"
    else toString package;
  qemuSeries = qemuPassthru.series;
  shmemAbiVersion = sourceConst "shmem ABI version" "pub const ABI_VERSION: u32 = " shmemLib;
  guestHostProtocolVersion =
    sourceConst
    "guest-host protocol version"
    "pub const CONTROL_PROTOCOL_VERSION: u32 = "
    protocolLib;
  doorbellInstructionAbiVersion =
    sourceConst
    "doorbell instruction ABI version"
    "pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = "
    doorbellAbi;
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
        kind = "fetchCargoVendor";
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
    components = {
      controller = {
        package = "crucible-controller";
        path = componentPath controllerPackage;
        license = "Apache-2.0";
        boundary = "separate-process-controller";
      };
      qemu = {
        package = "qemu-crucible";
        path = componentPath qemuPackage;
        licenses = ["GPL-2.0-only" "GPL-2.0-or-later" "MIT"];
        combinedWorkLicense = "GPL-2.0-only";
        createdSourceLicense = "GPL-2.0-or-later";
        generatedBoundaryHeaderLicenseOption = "MIT";
        standaloneRelease = false;
        releaseVia = "crucible";
        boundary = "qemu-process";
      };
      plugin = {
        package = "crucible-qemu-plugin";
        path = componentPath pluginPackage;
        license = "GPL-2.0-only";
        boundary = "loaded-into-qemu-process";
      };
      debugGateway = {
        package = "crucible-debug-gateway";
        path = componentPath debugGatewayPackage;
        license = "GPL-2.0-only";
        boundary = "separate-process-qemu-rsp-owner";
        source = "crucible.workspace";
      };
      gdb = {
        package = "gdb";
        path = componentPath gdbPackage;
        license = "GPL-3.0-or-later";
        boundary = "operator-debugger-client";
      };
      ssh = {
        package = "openssh";
        path = componentPath sshPackage;
        license = "BSD-2-Clause";
        boundary = "operator-guest-bridge-client";
      };
      boundaryCrates = {
        packages = ["crucible-protocol" "crucible-shmem"];
        license = "MIT";
        selection = "gpl-plugin-consumption";
      };
      correspondingSource = {
        package = "qemu-crucible-source";
        path = componentPath qemuSourcePackage;
        licenses = ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later"];
        scope = ["qemu-crucible" "crucible-qemu-plugin"];
        qemuBuildId = qemuPassthru.qemuBuildIdentity;
      };
    };
    licensing = {
      aggregate = true;
      licenses = ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later" "GPL-3.0-or-later" "BSD-2-Clause"];
      licenseSetScope = "primary-project-components";
      thirdPartyLicenseMetadata = "vendored-source-manifests";
      processBoundary = "unix-socket-control+memfd-shared-memory-data";
      sharedMemoryRole = "versioned-process-to-process-protocol";
    };
    publication = {
      rootPackage = "crucible";
      rawQemuAllowed = false;
      pairedQemuPath = componentPath qemuPackage;
      correspondingSourcePath = componentPath qemuSourcePackage;
      policy = "aggregate-direct-reference-pair";
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
      doorbellInstruction = {
        version = doorbellInstructionAbiVersion;
        architectures = ["x86_64" "aarch64"];
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
    cargo_deps=fetchCargoVendor
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
    controller_package=crucible-controller
    controller_path=${manifest.components.controller.path}
    controller_license=Apache-2.0
    qemu_path=${manifest.components.qemu.path}
    qemu_license=GPL-2.0-only
    qemu_component_licenses=GPL-2.0-only,GPL-2.0-or-later,MIT
    qemu_combined_work_license=GPL-2.0-only
    qemu_created_source_license=GPL-2.0-or-later
    qemu_generated_boundary_header_license_option=MIT
    qemu_standalone_release=false
    qemu_release_via=crucible
    plugin_package=crucible-qemu-plugin
    plugin_path=${manifest.components.plugin.path}
    plugin_license=GPL-2.0-only
    debug_gateway_package=crucible-debug-gateway
    debug_gateway_path=${manifest.components.debugGateway.path}
    debug_gateway_license=GPL-2.0-only
    debug_gateway_boundary=separate-process-qemu-rsp-owner
    gdb_package=gdb
    gdb_path=${manifest.components.gdb.path}
    gdb_license=GPL-3.0-or-later
    gdb_boundary=operator-debugger-client
    ssh_package=openssh
    ssh_path=${manifest.components.ssh.path}
    ssh_license=BSD-2-Clause
    ssh_boundary=operator-guest-bridge-client
    boundary_crates=crucible-protocol,crucible-shmem
    boundary_crates_license=MIT
    qemu_corresponding_source_package=qemu-crucible-source
    qemu_corresponding_source_path=${manifest.components.correspondingSource.path}
    qemu_corresponding_source_build_id=${manifest.components.correspondingSource.qemuBuildId}
    corresponding_source_scope=qemu-crucible,crucible-qemu-plugin
    publication_root_package=crucible
    publication_raw_qemu_allowed=false
    publication_policy=aggregate-direct-reference-pair
    aggregate_licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later,GPL-3.0-or-later,BSD-2-Clause
    aggregate_license_scope=primary-project-components
    third_party_license_metadata=vendored-source-manifests
    process_boundary=unix-socket-control+memfd-shared-memory-data
    shmem_abi_version=${shmemAbiVersion}
    shmem_abi=${shmemAbi}
    shmem_generated_header_hash=${manifest.abi.shmem.generatedHeaderHash}
    guest_host_protocol_version=${guestHostProtocolVersion}
    guest_host_protocol_abi=${guestHostProtocolAbi}
    doorbell_instruction_abi_version=${doorbellInstructionAbiVersion}
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
