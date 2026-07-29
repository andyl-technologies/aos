{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.crucibleQemuPluginPackage",
  taskIds ? ["T-PKG-7"],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  pluginPackageNix = builtins.readFile ../../pkgs/emulation/crucible-qemu-plugin.nix;
  qemuPackageNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  cruciblePackageNix = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;
  workspaceBuildCheck = builtins.readFile ./phase1-aos-workspace-build.nix;
  pluginAbi = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi.rs;
  shmemLib = builtins.readFile ../../crates/crucible-shmem/src/lib.rs;
  defaultChecks = builtins.readFile ./default.nix;

  qemuPluginApiVersionPrefix = "pub const QEMU_PLUGIN_API_VERSION: c_int = ";
  shmemAbiVersionPrefix = "pub const ABI_VERSION: u32 = ";

  firstLineWith = label: prefix: content: let
    matches = builtins.filter (line: lib.hasPrefix prefix line) (lib.splitString "\n" content);
  in
    if matches == []
    then throw "crucible phase7 QEMU plugin package check failed: missing ${label}"
    else builtins.head matches;

  qemuPluginApiVersion =
    lib.removeSuffix ";"
    (lib.removePrefix qemuPluginApiVersionPrefix (
      firstLineWith "QEMU plugin API version" qemuPluginApiVersionPrefix pluginAbi
    ));
  shmemAbiVersion =
    lib.removeSuffix ";"
    (lib.removePrefix shmemAbiVersionPrefix (
      firstLineWith "shmem ABI version" shmemAbiVersionPrefix shmemLib
    ));

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-7 checklist complete";
        needle = "- [x] **T-PKG-7**";
      }
      {
        label = "T-PKG-7 completion note";
        needle = "Completed by `checks.crucible.phase7.crucibleQemuPluginPackage`";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPackageNix [
      {
        label = "AOS cargo package builder";
        needle = "mkCargoPackage {";
      }
      {
        label = "plugin package name";
        needle = "pname = \"crucible-qemu-plugin\";";
      }
      {
        label = "vendored cargo deps";
        needle = "cargoDeps = fetchCargoDeps";
      }
      {
        label = "plugin crate cargo build";
        needle = "cargoFlags = \"-p crucible-qemu-plugin\";";
      }
      {
        label = "plugin crate cargo tests";
        needle = "cargoTestFlags = \"-p crucible-qemu-plugin\";";
      }
      {
        label = "cdylib install enabled";
        needle = "installLibs = true;";
      }
      {
        label = "matched qemu package dependency";
        needle = "qemu-crucible";
      }
      {
        label = "patched qemu plugin header probe";
        needle = "header=\"" + "$" + "{qemu-crucible}/include/qemu/qemu-plugin.h\"";
      }
      {
        label = "QEMU plugin API version probe";
        needle = "QEMU_PLUGIN_VERSION != CRUCIBLE_EXPECTED_QEMU_PLUGIN_API_VERSION";
      }
      {
        label = "plugin API version source";
        needle = "done < crates/crucible-qemu-plugin/src/abi.rs";
      }
      {
        label = "installed QEMU plugin path";
        needle = "$out/lib/qemu/plugins/crucible-qemu-plugin.so";
      }
      {
        label = "QEMU plugin API version marker";
        needle = "qemu_plugin_api_version=$qemu_plugin_api_version";
      }
      {
        label = "QEMU plugin ABI marker";
        needle = "qemu_plugin_abi=qemu-plugin-api-v$qemu_plugin_api_version";
      }
      {
        label = "shmem ABI version marker";
        needle = "shmem_abi_version=$shmem_abi_version";
      }
      {
        label = "shmem ABI marker";
        needle = "shmem_abi=crucible-shmem-abi-v$shmem_abi_version";
      }
      {
        label = "CLI compatibility ABI marker";
        needle = "plugin_abi=crucible-shmem-abi-v$shmem_abi_version";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPackageNix [
      {
        label = "nixpkgs import";
        needle = "<nixpkgs>";
      }
      {
        label = "host tools pattern";
        needle = "hostTools";
      }
      {
        label = "host shell path";
        needle = "/bin/sh";
      }
      {
        label = "env shebang";
        needle = "/usr/bin/env";
      }
    ]
    ++ failuresFor "pkgs/emulation/qemu.nix" qemuPackageNix [
      {
        label = "QEMU plugin header installed";
        needle = "install -m 644 include/qemu/qemu-plugin.h \"$out/include/qemu/qemu-plugin.h\"";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible/crucible.nix" cruciblePackageNix [
      {
        label = "CLI package carries matched QEMU/plugin runtime deps";
        needle = "runtimeDeps = [qemu-crucible crucible-qemu-plugin];";
      }
      {
        label = "CLI package pins AOS QEMU hint";
        needle = "CRUCIBLE_AOS_QEMU = \"" + "$" + "{qemu-crucible}/bin/qemu-system-x86_64\";";
      }
      {
        label = "CLI package pins AOS plugin hint";
        needle = "CRUCIBLE_AOS_PLUGIN = \"" + "$" + "{crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so\";";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-aos-workspace-build.nix" workspaceBuildCheck [
      {
        label = "output smoke checks canonical plugin library";
        needle = "test -f " + "$" + "{packages.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so";
      }
      {
        label = "output smoke checks QEMU plugin search-path entry";
        needle = "test -e " + "$" + "{packages.crucible-qemu-plugin}/lib/qemu/plugins/crucible-qemu-plugin.so";
      }
      {
        label = "output smoke checks QEMU API version metadata";
        needle = "grep -q '^qemu_plugin_api_version=${qemuPluginApiVersion}$'";
      }
      {
        label = "output smoke checks QEMU plugin ABI metadata";
        needle = "grep -q '^qemu_plugin_abi=qemu-plugin-api-v${qemuPluginApiVersion}$'";
      }
      {
        label = "output smoke checks shmem ABI version metadata";
        needle = "grep -q '^shmem_abi_version=${shmemAbiVersion}$'";
      }
      {
        label = "output smoke checks shmem ABI metadata";
        needle = "grep -q '^shmem_abi=crucible-shmem-abi-v${shmemAbiVersion}$'";
      }
      {
        label = "output smoke preserves CLI compatibility ABI metadata";
        needle = "grep -q '^plugin_abi=crucible-shmem-abi-v${shmemAbiVersion}$'";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi.rs" pluginAbi [
      {
        label = "plugin API version constant";
        needle = qemuPluginApiVersionPrefix + qemuPluginApiVersion + ";";
      }
      {
        label = "plugin exports version symbol";
        needle = "pub static qemu_plugin_version: c_int = QEMU_PLUGIN_API_VERSION;";
      }
    ]
    ++ failuresFor "crates/crucible-shmem/src/lib.rs" shmemLib [
      {
        label = "shmem ABI version constant";
        needle = shmemAbiVersionPrefix + shmemAbiVersion + ";";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 plugin package check imported";
        needle = "crucibleQemuPluginPackage = import ./phase7-crucible-qemu-plugin-package.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 QEMU plugin package check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase7-crucible-qemu-plugin-package";
      version = "0";
      src = null;

      buildDeps = [
        pkgs.coreutils
      ];

      QEMU_PLUGIN_API_VERSION = qemuPluginApiVersion;
      SHMEM_ABI_VERSION = shmemAbiVersion;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
      ATTR_PATH = attrPath;
      passthru = {
        pluginPackage = pkgs.crucible-qemu-plugin;
        qemuPackage = pkgs.qemu-crucible;
      };

      phases = [
        {
          name = "write-result";
          script = ''
            set -eu

            mkdir -p "$out"
            cat > "$out/result" <<RESULT
            PASS
            check=$ATTR_PATH
            tasks=$TASK_IDS
            package=crucible-qemu-plugin
            package_passthru=pkgs.crucible-qemu-plugin
            qemu_package_passthru=pkgs.qemu-crucible
            gate_kind=source-and-output-smoke-wiring
            build_system=mkCargoPackage
            qemu_package=qemu-crucible
            matched_pair_hints=pkgs.crucible
            qemu_plugin_api_version=$QEMU_PLUGIN_API_VERSION
            qemu_plugin_abi=qemu-plugin-api-v$QEMU_PLUGIN_API_VERSION
            shmem_abi_version=$SHMEM_ABI_VERSION
            shmem_abi=crucible-shmem-abi-v$SHMEM_ABI_VERSION
            output_smoke=checks.crucible.phase1.aosWorkspaceBuild
            RESULT
          '';
        }
      ];
    }
