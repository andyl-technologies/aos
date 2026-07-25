##! crucible — RFC-0010 Crucible Rust workspace and CLI
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  rust,
  qemu-crucible,
  crucible-qemu-plugin,
}: let
  version = "0.1.0";
  cargoDepsHash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  src = import ./_source.nix {inherit lib;};
  packages = import ./_packages.nix;
  releaseManifest = import ./_release-manifest.nix {
    inherit lib version src cargoDepsHash;
    qemuPackage = qemu-crucible;
  };
  nonCrucibleWorkspacePackages = [
    "aos"
    "aos-core"
    "aos-net"
    "aos-proto"
    "aos-server"
    "aos-cache"
    "aos-remote"
    "aos-doc"
    "aos-package"
    "aos-systemd"
  ];
  workspaceCargoFlags = builtins.concatStringsSep " " (
    ["--workspace"] ++ map (package: "--exclude ${package}") nonCrucibleWorkspacePackages
  );
  packageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") packages);
  docPackages = builtins.filter (package: package != "crucible-cli") packages;
  docPackageFlags = builtins.concatStringsSep " " (map (package: "-p ${package}") docPackages);
  doctestPackages = builtins.filter (package: package != "crucible-cli" && package != "crucible-qemu-plugin") packages;
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
in
  mkCargoPackage {
    pname = "crucible";
    inherit version src;

    cargoDeps = fetchCargoDeps {
      inherit src;
      sourceRoot = "source/crates";
      hash = cargoDepsHash;
    };

    cargoFlags = workspaceCargoFlags;
    cargoTestFlags = workspaceCargoFlags;
    doCheck = true;
    buildDeps = [rust.dev];
    runtimeDeps = [qemu-crucible crucible-qemu-plugin];
    CRUCIBLE_AOS_QEMU = "${qemu-crucible}/bin/qemu-system-x86_64";
    CRUCIBLE_AOS_PLUGIN = "${crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so";

    # The source root includes root guidance, docs/, pkgs/tools/crucible/, and
    # tests/crucible/ so harness lints can read RFC-0010 and AOS check wiring,
    # while Cargo's virtual workspace remains rooted at crates/.
    preBuild = ''
      cd crates
    '';

    postBuild = ''
      cargo clippy \
        --all-targets \
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

    postInstall = ''
      test -x "$out/bin/crucible"

      mkdir -p "$out/share/aos/crucible"
      cat > "$out/share/aos/crucible/release-manifest.env" <<'CRUCIBLE_RELEASE_MANIFEST'
      ${releaseManifest.envText}
      CRUCIBLE_RELEASE_MANIFEST
      cat > "$out/share/aos/crucible/release-manifest.json" <<'CRUCIBLE_RELEASE_MANIFEST_JSON'
      ${releaseManifest.jsonText}
      CRUCIBLE_RELEASE_MANIFEST_JSON

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-build-info" <<'INFO'
      package=crucible
      build_system=mkCargoPackage
      cargo_deps=fetchCargoDeps
      cargo_workspace=crates
      cargo_workspace_flags=${workspaceCargoFlags}
      cargo_member_flags=${packageFlags}
      cargo_doc=warning-free
      cargo_doctest=hermetic
      rustdocflags=-D warnings -D missing_docs
      qemu_package=qemu-crucible
      qemu_path=${qemu-crucible}/bin/qemu-system-x86_64
      plugin_package=crucible-qemu-plugin
      plugin_path=${crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
      discovery_hint=compile-time-aos-package-set
      shmem_abi_version=${shmemAbiVersion}
      shmem_abi=crucible-shmem-abi-v${shmemAbiVersion}
      guest_host_protocol_version=${guestHostProtocolVersion}
      guest_host_protocol_abi=crucible-guest-host-channel-v${guestHostProtocolVersion}
      rpc_abi_version=${rpcProtocolMajor}.${rpcProtocolMinor}.${rpcProtocolPatch}
      rpc_abi_build=${rpcProtocolBuild}
      INFO
    '';

    meta = {
      description = "Crucible deterministic VM exploration workspace and CLI";
      homepage = "https://github.com/andyl/andyl-os";
      license = "MIT";
      mainProgram = "crucible";
    };
  }
