##! crucible — RFC-0010 Crucible Rust workspace and CLI
{
  lib,
  mkDerivation,
  mkCargoPackage,
  fetchCargoDeps,
  rust,
  openssl,
  pkg-config,
  qemu-crucible,
  crucible-qemu-plugin,
  linux-crucible,
  crucible-fixtures,
  bash,
  qemu-crucible-source,
  controllerOnly ? false,
}: let
  version = "0.1.0";
  cargoDepsHash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  src = import ./_source.nix {inherit lib;};
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
  controllerPackages = builtins.filter (package: package != "crucible-qemu-plugin") packages;
  workspaceCargoFlags = builtins.concatStringsSep " " (
    ["--workspace"] ++ map (package: "--exclude ${package}") (nonCrucibleWorkspacePackages ++ ["crucible-qemu-plugin"])
  );
  packageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") controllerPackages);
  docPackages = builtins.filter (package: package != "crucible-cli") controllerPackages;
  docPackageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") docPackages);
  doctestPackages = builtins.filter (package: package != "crucible-cli") controllerPackages;
  doctestPackageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") doctestPackages);
  shmemLib = builtins.readFile ../../../crates/crucible-shmem/src/lib.rs;
  protocolLib = builtins.readFile ../../../crates/crucible-protocol/src/lib.rs;
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
  rpcProtocolMajor = sourceConst "RPC ABI major version" "pub const RPC_PROTOCOL_MAJOR: u16 = " apiRpcAbi;
  rpcProtocolMinor = sourceConst "RPC ABI minor version" "pub const RPC_PROTOCOL_MINOR: u16 = " apiRpcAbi;
  rpcProtocolPatch = sourceConst "RPC ABI patch version" "pub const RPC_PROTOCOL_PATCH: u16 = " apiRpcAbi;
  rpcProtocolBuild = sourceStringConst "RPC ABI build tag" "pub const RPC_PROTOCOL_BUILD: &str = \"" apiRpcAbi;
  controller = mkCargoPackage {
    pname = "crucible-controller";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      sourceRoot = "source/crates";
      hash = cargoDepsHash;
    };

    cargoFlags = workspaceCargoFlags;
    cargoTestFlags = "${workspaceCargoFlags} --features crucible-cli/test-double";
    doCheck = true;
    buildDeps = [rust.dev pkg-config openssl];
    runtimeDeps = [openssl];
    OPENSSL_DIR = "${openssl}";
    OPENSSL_LIB_DIR = "${openssl}/lib";
    OPENSSL_INCLUDE_DIR = "${openssl}/include";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";

    # The source root includes root guidance, docs/, pkgs/tools/crucible/, and
    # tests/crucible/ so harness lints can read RFC-0010 and AOS check wiring,
    # while Cargo's virtual workspace remains rooted at crates/.
    preBuild = ''
      cd crates
    '';

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
    '';

    postInstall = ''
      test -x "$out/bin/crucible"
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
  releaseManifest = import ./_release-manifest.nix {
    inherit lib version src cargoDepsHash;
    qemuPackage = qemu-crucible;
    controllerPackage = controller;
    pluginPackage = crucible-qemu-plugin;
    qemuSourcePackage = qemu-crucible-source;
  };
  suite = mkDerivation {
    pname = "crucible";
    inherit version;
    src = null;
    buildDeps = [bash];
    runtimeDeps = [controller qemu-crucible crucible-qemu-plugin linux-crucible crucible-fixtures];
    propagatedDeps = [];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/aos/crucible" "$out/share/licenses/crucible"
          cat > "$out/bin/crucible" <<'EOF'
          #!${bash}/bin/bash
          : "''${CRUCIBLE_QEMU:=${qemu-crucible}/bin/qemu-system-x86_64}"
          : "''${CRUCIBLE_PLUGIN:=${crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so}"
          : "''${CRUCIBLE_KERNEL:=${linux-crucible}/boot/vmlinuz-${linux-crucible.version}}"
          : "''${CRUCIBLE_ROOT_IMAGE:=${crucible-fixtures}/share/crucible/fixtures/root/aos-minimal-root.ext4}"
          : "''${CRUCIBLE_KERNEL_CMDLINE:=${linux-crucible.passthru.crucibleFixtureKernelCmdline} init=/init}"
          export CRUCIBLE_QEMU CRUCIBLE_PLUGIN CRUCIBLE_KERNEL CRUCIBLE_ROOT_IMAGE CRUCIBLE_KERNEL_CMDLINE
          exec ${controller}/bin/crucible "$@"
          EOF
          chmod +x "$out/bin/crucible"

          cat > "$out/share/aos/crucible/release-manifest.env" <<'CRUCIBLE_RELEASE_MANIFEST'
          ${releaseManifest.envText}
          CRUCIBLE_RELEASE_MANIFEST
          cat > "$out/share/aos/crucible/release-manifest.json" <<'CRUCIBLE_RELEASE_MANIFEST_JSON'
          ${releaseManifest.jsonText}
          CRUCIBLE_RELEASE_MANIFEST_JSON

          cp ${../../../LICENSES/Apache-2.0.txt} "$out/share/licenses/crucible/Apache-2.0.txt"
          cp ${../../../LICENSES/GPL-2.0-only.txt} "$out/share/licenses/crucible/GPL-2.0-only.txt"
          mkdir -p "$out/nix-support"
          cat > "$out/nix-support/crucible-build-info" <<'INFO'
          package=crucible
          component=suite
          component_licenses=Apache-2.0,GPL-2.0-only
          controller_package=crucible-controller
          controller_path=${controller}
          controller_license=Apache-2.0
          qemu_package=qemu-crucible
          qemu_path=${qemu-crucible}/bin/qemu-system-x86_64
          qemu_license=GPL-2.0-only
          plugin_package=crucible-qemu-plugin
          plugin_path=${crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
          plugin_license=GPL-2.0-only
          qemu_corresponding_source_package=qemu-crucible-source
          qemu_corresponding_source_build_id=${qemu-crucible-source.passthru.qemuBuildIdentity}
          corresponding_source_scope=qemu-crucible,crucible-qemu-plugin
          discovery_hint=runtime-environment-wrapper
          shmem_abi_version=${shmemAbiVersion}
          shmem_abi=crucible-shmem-abi-v${shmemAbiVersion}
          guest_host_protocol_version=${guestHostProtocolVersion}
          guest_host_protocol_abi=crucible-guest-host-channel-v${guestHostProtocolVersion}
          rpc_abi_version=${rpcProtocolMajor}.${rpcProtocolMinor}.${rpcProtocolPatch}
          rpc_abi_build=${rpcProtocolBuild}
          INFO
        '';
      }
    ];
    passthru = {
      inherit controller;
      qemu = qemu-crucible;
      plugin = crucible-qemu-plugin;
      correspondingSource = qemu-crucible-source;
    };
    meta = {
      description = "Crucible controller with the GPL QEMU backend";
      homepage = "https://github.com/andyl/andyl-os";
      license = ["Apache-2.0" "GPL-2.0-only"];
      mainProgram = "crucible";
    };
  };
in
  if controllerOnly
  then controller
  else suite
