##! crucible-qemu-plugin — RFC-0010 QEMU plugin cdylib
{
  lib,
  stdenv,
  callPackage,
  mkCargoPackage,
  mkCargoArtifacts,
  mkCargoDummySource,
  aosWorkspaceVendor,
  glib,
  pkg-config,
  qemu-crucible,
  sqlite,
}: let
  version = "0.1.0";
  src = import ../tools/crucible/_source.nix {inherit lib;};
  cargoDeps = aosWorkspaceVendor;
  cargoWorkspaceMembers = import ../tools/crucible/_workspace.nix {inherit lib;};
  cargoArtifactContract = {
    family = "crucible-gpl-qemu-plugin-release-and-test";
    nativeInputs = map toString [glib glib.dev glib.tools pkg-config qemu-crucible sqlite];
    licenseScope = "GPL-2.0-only";
  };
  cargoEnv = {LIBSQLITE3_SYS_USE_PKG_CONFIG = "1";};
  qemuTestOracle = callPackage ../tools/crucible/_qemu-test-oracle.nix {};
  cargoArtifacts = mkCargoArtifacts {
    pname = "crucible-qemu-plugin-artifacts";
    inherit version cargoDeps cargoWorkspaceMembers cargoArtifactContract cargoEnv;
    src = mkCargoDummySource {
      srcRoot = ../../crates;
      name = "crucible-qemu-plugin-dummy-source";
      cargoRoot = "crates";
    };
    cargoRoot = "crates";
    cargoBuildCommands = [
      "build --release --frozen --offline -j$NIX_BUILD_CORES -p crucible-qemu-plugin"
      "test --release --no-run --frozen --offline -j$NIX_BUILD_CORES -p crucible-qemu-plugin"
    ];
    buildDeps = [glib.dev glib.tools pkg-config qemu-crucible sqlite];
    runtimeDeps = [glib qemu-crucible sqlite];
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "build-input";
    };
    pname = "crucible-qemu-plugin";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The artifact is an ELF shared object containing qemu_plugin_install.";
        "files" = {};
        "input" = "The packaged QEMU plugin shared object.";
        "operation" = "Validate its ELF identity and required QEMU plugin entry-point symbol.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib\nplugin = pathlib.Path(\"@out@/lib/qemu/plugins/crucible-qemu-plugin.so\").read_bytes()\nassert plugin.startswith(bytes([0x7f]) + b\"ELF\") and b\"qemu_plugin_install\" in plugin\nprint(\"crucible-qemu-plugin data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "crucible-qemu-plugin data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The package rejects a plugin format it does not produce.";
        "files" = {};
        "input" = "A request for an undeclared static-library form of the QEMU plugin.";
        "operation" = "Resolve the absent static archive beneath the plugin output.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import pathlib, sys\nif pathlib.Path(\"@out@/lib/qemu/plugins/crucible-qemu-plugin.a\").exists():\n    raise SystemExit(2)\nsys.stderr.write(\"crucible-qemu-plugin rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "crucible-qemu-plugin rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src;

    inherit cargoDeps cargoWorkspaceMembers cargoArtifacts cargoArtifactContract cargoEnv;
    cargoRoot = "crates";
    cargoNextest = true;

    cargoFlags = "-p crucible-qemu-plugin";
    cargoTestFlags = "-p crucible-qemu-plugin";
    installBins = false;
    installLibs = false;
    doCheck = true;

    buildDeps = [glib.dev glib.tools pkg-config qemu-crucible sqlite];
    runtimeDeps = [glib qemu-crucible sqlite];

    postBuild = lib.optionalString (!stdenv.isCross) ''
      export CRUCIBLE_QEMU_TEST_ORACLE=${qemuTestOracle}/bin/crucible-qemu-test-oracle
    '';
    preInstall = ''
      unset CRUCIBLE_QEMU_TEST_ORACLE
    '';

    preBuild = import ./_crucible-qemu-plugin-abi.nix {
      inherit lib glib qemu-crucible;
      pluginAbiSource = "crucible/crucible-qemu-plugin/src/abi.rs";
      shmemAbiSource = "crucible/crucible-qemu-shmem/src/lib.rs";
    };

    postInstall = ''
      # Dependency artifacts include native procedural macros in cross builds.
      # Install only the target plugin named by Cargo's artifact record.
      pluginLibrary=$(jq -er '
        select(.reason == "compiler-artifact")
        | select(.target.name == "crucible_qemu_plugin")
        | select(.target.crate_types | index("cdylib"))
        | .filenames[]
        | select(endswith("/libcrucible_qemu_plugin.so"))
      ' "$NIX_BUILD_TOP/cargo-build-messages.jsonl" | sort -u)
      test -n "$pluginLibrary"
      test -f "$pluginLibrary"
      mkdir -p "$out/lib"
      install -m 644 "$pluginLibrary" "$out/lib/libcrucible_qemu_plugin.so"

      test -f "$out/lib/libcrucible_qemu_plugin.so"
      mkdir -p "$out/lib/qemu/plugins"
      ln -s ../../libcrucible_qemu_plugin.so \
        "$out/lib/qemu/plugins/crucible-qemu-plugin.so"

      qemu_plugin_api_version=
      while IFS= read -r line; do
        case "$line" in
          "pub const QEMU_PLUGIN_API_VERSION: c_int = "*";")
            qemu_plugin_api_version=''${line#pub const QEMU_PLUGIN_API_VERSION: c_int = }
            qemu_plugin_api_version=''${qemu_plugin_api_version%;}
            ;;
        esac
      done < crucible/crucible-qemu-plugin/src/abi.rs
      test -n "$qemu_plugin_api_version"

      shmem_abi_version=
      while IFS= read -r line; do
        case "$line" in
          "pub const ABI_VERSION: u32 = "*";")
            shmem_abi_version=''${line#pub const ABI_VERSION: u32 = }
            shmem_abi_version=''${shmem_abi_version%;}
            ;;
        esac
      done < crucible/crucible-qemu-shmem/src/lib.rs
      test -n "$shmem_abi_version"

      mkdir -p "$out/nix-support"
      cat > "$out/nix-support/crucible-qemu-plugin-build-info" <<INFO
      package=crucible-qemu-plugin
      build_system=mkCargoPackage
      cargo_deps=fetchCargoVendor
      qemu_package=qemu-crucible
      qemu_build_id=${qemu-crucible.passthru.qemuBuildIdentity}
      qemu_sim_capability_marker=${qemu-crucible}/share/aos/crucible/qemu-build-identity.env
      qemu_plugin_header=${qemu-crucible}/include/qemu/qemu-plugin.h
      qemu_plugin_api_version=$qemu_plugin_api_version
      qemu_plugin_abi=qemu-plugin-api-v$qemu_plugin_api_version
      shmem_abi_version=$shmem_abi_version
      shmem_abi=crucible-shmem-abi-v$shmem_abi_version
      qemu_shmem_abi=${qemu-crucible.passthru.shmemAbi}
      shmem_generated_header=${qemu-crucible}/include/aos/crucible/crucible_shmem_abi.h
      shmem_generated_header_hash=${qemu-crucible.passthru.shmemHeaderHash}
      plugin_abi=crucible-shmem-abi-v$shmem_abi_version
      component=qemu-in-process-adapter
      component_license=GPL-2.0-only
      INFO

      mkdir -p "$out/share/licenses/crucible-qemu-plugin"
      cp ${../../LICENSES/GPL-2.0-only.txt} \
        "$out/share/licenses/crucible-qemu-plugin/GPL-2.0.txt"
      cp ${../../LICENSES/MIT.txt} \
        "$out/share/licenses/crucible-qemu-plugin/MIT.txt"
      cat > "$out/share/licenses/crucible-qemu-plugin/COMPONENT" <<'LICENSE_SCOPE'
      crucible-qemu-plugin is an in-process QEMU adapter.
      SPDX-License-Identifier: GPL-2.0-only
      crucible-qemu-protocol and crucible-qemu-shmem are used under their MIT option.
      LICENSE_SCOPE
    '';

    meta = {
      description = "Crucible QEMU plugin cdylib built against AOS QEMU headers";
      homepage = "https://github.com/andyl/andyl-os";
      license = "GPL-2.0-only";
    };
  }
