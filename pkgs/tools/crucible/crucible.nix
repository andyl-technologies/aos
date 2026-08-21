##! crucible — RFC-0010 Crucible Rust workspace and CLI
{
  lib,
  stdenv,
  mkDerivation,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  fetchCargoDeps,
  rust,
  openssl,
  pkg-config,
  qemu-crucible,
  crucible-qemu-plugin,
  linux-crucible,
  crucible-fixtures,
  bash,
  coreutils,
  grep,
  sed,
  util-linux,
  qemu-crucible-source,
  gdb,
  openssh,
  controllerOnly ? false,
}: let
  version = "0.1.0";
  nativeQemuSystemBinary =
    {
      "x86_64-linux" = "qemu-system-x86_64";
      "aarch64-linux" = "qemu-system-aarch64";
    }
    .${
      stdenv.hostPlatform.system
    }
    or (throw "crucible: unsupported native QEMU system '${stdenv.hostPlatform.system}'");
  nativeQemuPath = "${qemu-crucible}/bin/${nativeQemuSystemBinary}";
  liveDebuggerMatrixArchitectures =
    if stdenv.hostPlatform.system == "x86_64-linux"
    then "x86_64"
    else "aarch64";
  cargoDepsHash = "sha256-ULD9g6d87886b8O6/sGCMktquGwaUAyf+DLHUrFzod0=";
  liveDebuggerMatrixScript = ../../../examples/codex-skills/crucible-debugger/scripts/live-matrix.sh;
  src = import ./_source.nix {inherit lib;};
  cargoDeps = fetchCargoDeps {
    inherit src;
    sourceRoot = "source/crates";
    hash = cargoDepsHash;
  };
  packages = import ./_packages.nix;
  nonCrucibleWorkspacePackages = [
    "aos"
    "aos-core"
    "aos-net"
    "aos-proto"
    "aos-proto-types"
    "aos-server"
    "aos-cache"
    "aos-remote"
    "aos-doc"
    "aos-package"
    "aos-hub-core"
    "aos-hub"
    "aos-registry-surface"
    "aos-registry-spa"
    "aos-hub-worker"
    "aos-profile"
    "aos-systemd"
  ];
  gplSidePackages = ["crucible-qemu-plugin" "crucible-debug-gateway"];
  controllerPackages = builtins.filter (package: !(builtins.elem package gplSidePackages)) packages;
  workspaceCargoFlags = builtins.concatStringsSep " " (
    ["--workspace"] ++ map (package: "--exclude ${package}") (nonCrucibleWorkspacePackages ++ gplSidePackages)
  );
  packageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") controllerPackages);
  docPackages = builtins.filter (package: package != "crucible-cli") controllerPackages;
  docPackageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") docPackages);
  doctestPackages = builtins.filter (package: package != "crucible-cli") controllerPackages;
  doctestPackageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") doctestPackages);
  forbiddenControllerRuntimePaths =
    map
    (package: builtins.unsafeDiscardStringContext (toString package))
    [debugGateway qemu-crucible crucible-qemu-plugin linux-crucible crucible-fixtures];
  shmemLib = builtins.readFile ../../../crates/crucible-shmem/src/lib.rs;
  protocolLib = builtins.readFile ../../../crates/crucible-protocol/src/lib.rs;
  doorbellAbi = builtins.readFile ../../../crates/crucible-protocol/src/doorbell_abi.rs;
  apiRpcAbi = builtins.readFile ../../../crates/crucible-api/src/rpc_abi.rs;
  firstLineWith = label: prefix: content: let
    matches = builtins.filter (line: lib.hasPrefix prefix line) (lib.splitString "\n" content);
  in
    if matches == []
    then throw "crucible package failed to read ${label}"
    else builtins.head matches;
  sourceConst = label: prefix: content:
    lib.removeSuffix ";"
    (lib.removePrefix prefix (firstLineWith label prefix content));
  sourceStringConst = label: prefix: content:
    lib.removeSuffix "\";"
    (lib.removePrefix prefix (firstLineWith label prefix content));
  shmemAbiVersion = sourceConst "shmem ABI version" "pub const ABI_VERSION: u32 = " shmemLib;
  guestHostProtocolVersion = sourceConst "guest-host protocol version" "pub const CONTROL_PROTOCOL_VERSION: u32 = " protocolLib;
  doorbellInstructionAbiVersion = sourceConst "doorbell instruction ABI version" "pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = " doorbellAbi;
  rpcProtocolMajor = sourceConst "RPC ABI major version" "pub const RPC_PROTOCOL_MAJOR: u16 = " apiRpcAbi;
  rpcProtocolMinor = sourceConst "RPC ABI minor version" "pub const RPC_PROTOCOL_MINOR: u16 = " apiRpcAbi;
  rpcProtocolPatch = sourceConst "RPC ABI patch version" "pub const RPC_PROTOCOL_PATCH: u16 = " apiRpcAbi;
  rpcProtocolBuild = sourceStringConst "RPC ABI build tag" "pub const RPC_PROTOCOL_BUILD: &str = \"" apiRpcAbi;
  controllerCargoEnv = {
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
  };
  controllerArtifactContract = {
    family = "crucible-apache-host-release-and-test";
    nativeInputs = map toString [rust.dev pkg-config openssl];
    licenseScope = "Apache-2.0";
  };
  controllerArtifacts = mkCargoArtifacts {
    pname = "crucible-apache-host-artifacts";
    inherit version cargoDeps;
    cargoEnv = controllerCargoEnv;
    cargoArtifactContract = controllerArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../../crates;
      name = "crucible-apache-host-dummy-source";
    };
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES ${workspaceCargoFlags}"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES ${workspaceCargoFlags} --features crucible-cli/test-double"
    ];
    buildDeps = [rust.dev pkg-config openssl];
    runtimeDeps = [openssl];
  };
  debugGatewayArtifactContract = {
    family = "crucible-gpl-debug-gateway-release-and-test";
    nativeInputs = map toString [rust.dev];
    licenseScope = "GPL-2.0-only";
  };
  debugGatewayArtifacts = mkCargoArtifacts {
    pname = "crucible-debug-gateway-artifacts";
    inherit version cargoDeps;
    cargoArtifactContract = debugGatewayArtifactContract;
    src = mkCargoDummySource {
      srcRoot = ../../../crates;
      name = "crucible-debug-gateway-dummy-source";
    };
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p crucible-debug-gateway"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p crucible-debug-gateway"
    ];
    buildDeps = [rust.dev];
  };
  controller = mkCargoPackage {
    pname = "crucible-controller";
    inherit version src;

    inherit cargoDeps;
    cargoArtifacts = controllerArtifacts;
    cargoArtifactContract = controllerArtifactContract;
    cargoEnv = controllerCargoEnv;
    cargoRoot = "crates";
    cargoNextest = true;

    cargoFlags = workspaceCargoFlags;
    cargoTestFlags = "${workspaceCargoFlags} --features crucible-cli/test-double";
    doCheck = true;
    buildDeps = [rust.dev pkg-config openssl];
    runtimeDeps = [openssl];
    # The controller is the Apache side of a process boundary. Fail the build
    # if any QEMU-side implementation, guest kernel, or fixture enters either
    # its direct references or its runtime closure.
    disallowedReferences = forbiddenControllerRuntimePaths;
    disallowedRequisites = forbiddenControllerRuntimePaths;
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";

    # The source root includes root guidance, docs/, pkgs/tools/crucible/, and
    # tests/crucible/ so harness lints can read RFC-0010 and AOS check wiring,
    # while Cargo's virtual workspace remains rooted at crates/.
    postBuild = ''
      cargo test \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        -p crucible-harness \
        --test gate_license_boundary
      cargo clippy \
        --all-targets \
        --features crucible-cli/test-double \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        ${workspaceCargoFlags} \
        -- \
        -D warnings
      export RUSTDOCFLAGS="-D warnings -D missing_docs"
      cargo doc \
        --no-deps \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        --target-dir target/crucible-doc-libs \
        ${docPackageFlags}
      cargo doc \
        --no-deps \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        --target-dir target/crucible-doc-cli \
        -p crucible-cli \
        --bin crucible
      cargo test \
        --doc \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        --target-dir target/crucible-doctest-libs \
        ${doctestPackageFlags}
    '';

    # The check phase enables the test-only backend and writes a feature-enabled
    # binary to target/release. Rebuild the installed CLI without test features.
    preInstall = ''
      cargo build \
        --release \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        -p crucible-cli \
        --bin crucible
      cargo build \
        --release \
        --frozen \
        --offline \
        -j$NIX_BUILD_CORES \
        -p crucible \
        --example crucible-debugger-live-fixture
    '';

    postInstall = ''
      test -x "$out/bin/crucible"
      cp target/release/examples/crucible-debugger-live-fixture \
        "$out/bin/crucible-debugger-live-fixture"
      if "$out/bin/crucible" --help | grep -q 'auto|qemu|double'; then
        echo "installed Crucible CLI unexpectedly contains the test-only backend" >&2
        exit 1
      fi
      if "$out/bin/crucible" selftest --help | grep -q -- '--with-qemu'; then
        echo "installed Crucible CLI unexpectedly exposes --with-qemu" >&2
        exit 1
      fi

      mkdir -p "$out/share/licenses/crucible-controller"
      cp ${../../../LICENSES/Apache-2.0.txt} "$out/share/licenses/crucible-controller/Apache-2.0.txt"

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-build-info" <<'INFO'
      package=crucible-controller
      component=controller
      component_license=Apache-2.0
      build_system=mkCargoPackage
      cargo_deps=fetchCargoDeps
      cargo_workspace=crates
      cargo_workspace_flags=${workspaceCargoFlags}
      cargo_member_flags=${packageFlags}
      cargo_doc=warning-free
      cargo_doctest=hermetic
      gate_license_boundary=crucible-harness/gate_license_boundary
      rustdocflags=-D warnings -D missing_docs
      qemu_package=none
      plugin_package=none
      discovery_hint=flags-or-runtime-environment
      shmem_abi_version=${shmemAbiVersion}
      shmem_abi=crucible-shmem-abi-v${shmemAbiVersion}
      guest_host_protocol_version=${guestHostProtocolVersion}
      guest_host_protocol_abi=crucible-guest-host-channel-v${guestHostProtocolVersion}
      doorbell_instruction_abi_version=${doorbellInstructionAbiVersion}
      rpc_abi_version=${rpcProtocolMajor}.${rpcProtocolMinor}.${rpcProtocolPatch}
      rpc_abi_build=${rpcProtocolBuild}
      INFO
    '';

    meta = {
      description = "Apache-licensed Crucible controller and CLI";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      mainProgram = "crucible";
    };
  };
  debugGateway = mkCargoPackage {
    pname = "crucible-debug-gateway";
    inherit version src;

    inherit cargoDeps;
    cargoArtifacts = debugGatewayArtifacts;
    cargoArtifactContract = debugGatewayArtifactContract;
    cargoRoot = "crates";
    cargoNextest = true;

    cargoFlags = "-p crucible-debug-gateway";
    cargoTestFlags = "-p crucible-debug-gateway";
    doCheck = true;
    buildDeps = [rust.dev];
    runtimeDeps = [];

    postInstall = ''
      mkdir -p "$out/share/licenses/crucible-debug-gateway"
      cp ${../../../LICENSES/GPL-2.0-only.txt} \
        "$out/share/licenses/crucible-debug-gateway/GPL-2.0.txt"
      cp ${../../../LICENSES/MIT.txt} \
        "$out/share/licenses/crucible-debug-gateway/MIT.txt"
      cat > "$out/share/licenses/crucible-debug-gateway/COMPONENT" <<'LICENSE_SCOPE'
      crucible-debug-gateway is a standalone QEMU RSP mediation process.
      SPDX-License-Identifier: GPL-2.0-only
      crucible-protocol is used under its MIT option.
      LICENSE_SCOPE
    '';

    meta = {
      description = "GPL-side persistent Crucible debugger gateway";
      homepage = "https://github.com/andyl/andyl-os";
      license = "GPL-2.0-only";
      mainProgram = "crucible-debug-gateway";
    };
  };
  releaseManifest = import ./_release-manifest.nix {
    inherit lib version src cargoDepsHash;
    qemuPackage = qemu-crucible;
    controllerPackage = controller;
    pluginPackage = crucible-qemu-plugin;
    debugGatewayPackage = debugGateway;
    gdbPackage = gdb;
    sshPackage = openssh;
    qemuSourcePackage = qemu-crucible-source;
  };
  suite = mkDerivation {
    pname = "crucible";
    inherit version;
    src = null;
    buildDeps = [bash];
    runtimeDeps = [controller debugGateway qemu-crucible crucible-qemu-plugin qemu-crucible-source linux-crucible crucible-fixtures gdb openssh coreutils grep sed util-linux];
    propagatedDeps = [];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/aos/crucible" "$out/share/licenses/crucible"
          cat > "$out/bin/crucible" <<'EOF'
          #!${bash}/bin/bash
          : "''${CRUCIBLE_QEMU:=${nativeQemuPath}}"
          : "''${CRUCIBLE_NATIVE_GUEST_ARCHITECTURE:=${
            if stdenv.hostPlatform.system == "aarch64-linux"
            then "aarch64"
            else "x86_64"
          }}"
          : "''${CRUCIBLE_PLUGIN:=${crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so}"
          : "''${CRUCIBLE_DEBUG_GATEWAY:=${debugGateway}/bin/crucible-debug-gateway}"
          : "''${CRUCIBLE_KERNEL:=${linux-crucible}/boot/vmlinuz-${linux-crucible.version}}"
          : "''${CRUCIBLE_ROOT_IMAGE:=${crucible-fixtures}/share/crucible/fixtures/root/aos-minimal-root.ext4}"
          : "''${CRUCIBLE_KERNEL_CMDLINE:=${linux-crucible.passthru.crucibleFixtureKernelCmdline} init=/init}"
          ${lib.optionalString (stdenv.hostPlatform.system == "x86_64-linux") ''
            : "''${CRUCIBLE_KERNEL_X86_64:=$CRUCIBLE_KERNEL}"
            : "''${CRUCIBLE_ROOT_IMAGE_X86_64:=$CRUCIBLE_ROOT_IMAGE}"
            : "''${CRUCIBLE_KERNEL_CMDLINE_X86_64:=$CRUCIBLE_KERNEL_CMDLINE}"
          ''}
          ${lib.optionalString (stdenv.hostPlatform.system == "aarch64-linux") ''
            : "''${CRUCIBLE_KERNEL_AARCH64:=$CRUCIBLE_KERNEL}"
            : "''${CRUCIBLE_ROOT_IMAGE_AARCH64:=$CRUCIBLE_ROOT_IMAGE}"
            : "''${CRUCIBLE_KERNEL_CMDLINE_AARCH64:=$CRUCIBLE_KERNEL_CMDLINE}"
          ''}
          export CRUCIBLE_QEMU CRUCIBLE_NATIVE_GUEST_ARCHITECTURE CRUCIBLE_PLUGIN CRUCIBLE_DEBUG_GATEWAY CRUCIBLE_KERNEL CRUCIBLE_ROOT_IMAGE CRUCIBLE_KERNEL_CMDLINE
          ${lib.optionalString (stdenv.hostPlatform.system == "x86_64-linux") ''
            export CRUCIBLE_KERNEL_X86_64 CRUCIBLE_ROOT_IMAGE_X86_64 CRUCIBLE_KERNEL_CMDLINE_X86_64
          ''}
          ${lib.optionalString (stdenv.hostPlatform.system == "aarch64-linux") ''
            export CRUCIBLE_KERNEL_AARCH64 CRUCIBLE_ROOT_IMAGE_AARCH64 CRUCIBLE_KERNEL_CMDLINE_AARCH64
          ''}
          exec ${controller}/bin/crucible "$@"
          EOF
          chmod +x "$out/bin/crucible"
          ln -s ${gdb}/bin/gdb "$out/bin/gdb"
          ln -s ${gdb}/bin/gdbserver "$out/bin/gdbserver"
          ln -s ${openssh}/bin/ssh "$out/bin/ssh"
          ln -s ${controller}/bin/crucible-debugger-live-fixture \
            "$out/bin/crucible-debugger-live-fixture"
          cp ${liveDebuggerMatrixScript} "$out/share/aos/crucible/debugger-live-matrix.sh"
          cat > "$out/bin/crucible-debugger-live-matrix" <<EOF
          #!${bash}/bin/bash
          unset CRUCIBLE_QEMU CRUCIBLE_PLUGIN CRUCIBLE_DEBUG_GATEWAY \
            CRUCIBLE_NATIVE_GUEST_ARCHITECTURE CRUCIBLE_KERNEL CRUCIBLE_ROOT_IMAGE \
            CRUCIBLE_KERNEL_CMDLINE CRUCIBLE_KERNEL_X86_64 CRUCIBLE_ROOT_IMAGE_X86_64 \
            CRUCIBLE_KERNEL_CMDLINE_X86_64 CRUCIBLE_KERNEL_AARCH64 \
            CRUCIBLE_ROOT_IMAGE_AARCH64 CRUCIBLE_KERNEL_CMDLINE_AARCH64 \
            CRUCIBLE_VALIDATE_GUEST_ASSET_REFERENCES
          export CRUCIBLE_VALIDATE_GUEST_ASSET_REFERENCES=1
          export CRUCIBLE_MATRIX_CRUCIBLE="$out/bin/crucible"
          export CRUCIBLE_MATRIX_GDB="$out/bin/gdb"
          export CRUCIBLE_MATRIX_SSH="$out/bin/ssh"
          export CRUCIBLE_MATRIX_FIXTURE_GENERATOR="$out/bin/crucible-debugger-live-fixture"
          export CRUCIBLE_MATRIX_BUILD_INFO="$out/nix-support/crucible-build-info"
          export CRUCIBLE_MATRIX_SUPPORTED_ARCHITECTURES="${liveDebuggerMatrixArchitectures}"
          export CRUCIBLE_MATRIX_DOORBELL_INSTRUCTION_ABI_VERSION="${doorbellInstructionAbiVersion}"
          ${lib.optionalString (stdenv.hostPlatform.system == "x86_64-linux") ''
            export CRUCIBLE_MATRIX_KERNEL_X86_64="${linux-crucible}/boot/vmlinuz-${linux-crucible.version}"
            export CRUCIBLE_MATRIX_ROOT_IMAGE_X86_64="${crucible-fixtures}/share/crucible/fixtures/root/aos-minimal-root.ext4"
            export CRUCIBLE_MATRIX_KERNEL_CMDLINE_X86_64="${linux-crucible.passthru.crucibleFixtureKernelCmdline} init=/init"
          ''}
          ${lib.optionalString (stdenv.hostPlatform.system == "aarch64-linux") ''
            export CRUCIBLE_MATRIX_KERNEL_AARCH64="${linux-crucible}/boot/vmlinuz-${linux-crucible.version}"
            export CRUCIBLE_MATRIX_ROOT_IMAGE_AARCH64="${crucible-fixtures}/share/crucible/fixtures/root/aos-minimal-root.ext4"
            export CRUCIBLE_KERNEL_CMDLINE_AARCH64="${linux-crucible.passthru.crucibleFixtureKernelCmdline} init=/init"
          ''}
          export PATH="${coreutils}/bin:${grep}/bin:${sed}/bin:${util-linux}/bin:${bash}/bin"
          exec ${bash}/bin/bash "$out/share/aos/crucible/debugger-live-matrix.sh" "\$@"
          EOF
          chmod +x "$out/bin/crucible-debugger-live-matrix"

          cat > "$out/share/aos/crucible/release-manifest.env" <<'CRUCIBLE_RELEASE_MANIFEST'
          ${releaseManifest.envText}
          CRUCIBLE_RELEASE_MANIFEST
          cat > "$out/share/aos/crucible/release-manifest.json" <<'CRUCIBLE_RELEASE_MANIFEST_JSON'
          ${releaseManifest.jsonText}
          CRUCIBLE_RELEASE_MANIFEST_JSON

          cp ${../../../LICENSES/Apache-2.0.txt} "$out/share/licenses/crucible/Apache-2.0.txt"
          cp ${../../../LICENSES/MIT.txt} "$out/share/licenses/crucible/MIT.txt"
          cp ${../../../LICENSES/GPL-2.0-only.txt} "$out/share/licenses/crucible/GPL-2.0-only.txt"
          cp ${../../../LICENSES/GPL-2.0-or-later.txt} "$out/share/licenses/crucible/GPL-2.0-or-later.txt"
          cp ${gdb}/share/licenses/gdb/GPL-3.0.txt "$out/share/licenses/crucible/GPL-3.0.txt"
          mkdir -p "$out/nix-support"
          cat > "$out/nix-support/crucible-build-info" <<'INFO'
          package=crucible
          component=suite
          component_licenses=Apache-2.0,MIT,GPL-2.0-only,GPL-2.0-or-later,GPL-3.0-or-later,BSD-2-Clause
          boundary_crates=crucible-protocol,crucible-shmem
          boundary_crates_license=MIT
          controller_package=crucible-controller
          controller_path=${controller}
          controller_license=Apache-2.0
          qemu_package=qemu-crucible
          qemu_path=${nativeQemuPath}
          qemu_license=GPL-2.0-only
          qemu_component_licenses=GPL-2.0-only,GPL-2.0-or-later,MIT
          qemu_combined_work_license=GPL-2.0-only
          qemu_created_source_license=GPL-2.0-or-later
          qemu_generated_boundary_header_license_option=MIT
          plugin_package=crucible-qemu-plugin
          plugin_path=${crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
          plugin_license=GPL-2.0-only
          debug_gateway_package=crucible-debug-gateway
          debug_gateway_path=${debugGateway}/bin/crucible-debug-gateway
          debug_gateway_license=GPL-2.0-only
          gdb_package=gdb
          gdb_path=${gdb}/bin/gdb
          gdb_license=GPL-3.0-or-later
          ssh_package=openssh
          ssh_path=${openssh}/bin/ssh
          ssh_license=BSD-2-Clause
          debugger_fixture_generator_path=${controller}/bin/crucible-debugger-live-fixture
          debugger_live_matrix_path=bin/crucible-debugger-live-matrix
          debugger_live_matrix_architectures=${liveDebuggerMatrixArchitectures}
          debugger_live_matrix_external_architectures=aarch64
          qemu_corresponding_source_package=qemu-crucible-source
          qemu_corresponding_source_path=${qemu-crucible-source}
          qemu_corresponding_source_build_id=${qemu-crucible-source.passthru.qemuBuildIdentity}
          corresponding_source_scope=qemu-crucible,crucible-qemu-plugin
          discovery_hint=runtime-environment-wrapper
          shmem_abi_version=${shmemAbiVersion}
          shmem_abi=crucible-shmem-abi-v${shmemAbiVersion}
          guest_host_protocol_version=${guestHostProtocolVersion}
          guest_host_protocol_abi=crucible-guest-host-channel-v${guestHostProtocolVersion}
          doorbell_instruction_abi_version=${doorbellInstructionAbiVersion}
          rpc_abi_version=${rpcProtocolMajor}.${rpcProtocolMinor}.${rpcProtocolPatch}
          rpc_abi_build=${rpcProtocolBuild}
          INFO
          cat > "$out/nix-support/aos-release-policy" <<'RELEASE_POLICY'
          policy_version=1
          artifact_role=aggregate-release-root
          standalone_release=true
          pair_count=1
          pair_1_component_path=${qemu-crucible}
          pair_1_corresponding_source_path=${qemu-crucible-source}
          pair_1_identity=${qemu-crucible.passthru.qemuBuildIdentity}
          RELEASE_POLICY
        '';
      }
    ];
    passthru = {
      inherit controller;
      debugGateway = debugGateway;
      debugger = gdb;
      qemu = qemu-crucible;
      plugin = crucible-qemu-plugin;
      correspondingSource = qemu-crucible-source;
      standaloneRelease = true;
    };
    meta = {
      description = "Crucible controller with the GPL QEMU backend";
      homepage = "https://github.com/andyl/andyl-os";
      license = ["Apache-2.0" "MIT" "GPL-2.0-only" "GPL-2.0-or-later" "GPL-3.0-or-later" "BSD-2-Clause"];
      mainProgram = "crucible";
    };
  };
in
  if controllerOnly
  then controller
  else suite
