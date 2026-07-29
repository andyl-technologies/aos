{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.cruciblePackageHermeticDiscovery",
  taskIds ? ["T-PKG-9"],
}: let
  packagingDoc = builtins.readFile ../../docs/rfcs/0010-crucible/26-packaging-aos-integration.md;
  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  cruciblePackageNix = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;
  cliHermeticDiscoveryCheck = builtins.readFile ./phase5-cli-hermetic-discovery.nix;
  workspaceBuildCheck = builtins.readFile ./phase1-aos-workspace-build.nix;
  cliMain = import ./_cli-source.nix {inherit lib;};
  defaultChecks = builtins.readFile ./default.nix;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/26-packaging-aos-integration.md" packagingDoc [
      {
        label = "T-PKG-9 checklist complete";
        needle = "- [x] **T-PKG-9**";
      }
      {
        label = "T-PKG-9 completion note";
        needle = "Completed by `checks.crucible.phase7.cruciblePackageHermeticDiscovery`";
      }
      {
        label = "phase5 behavior proof reference";
        needle = "`checks.crucible.phase5.cliHermeticDiscovery`";
      }
      {
        label = "phase1 output-smoke reference";
        needle = "`checks.crucible.phase1.aosWorkspaceBuild`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "CLI hermetic discovery task complete";
        needle = "Completed by `checks.crucible.phase5.cliHermeticDiscovery`";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible/crucible.nix" cruciblePackageNix [
      {
        label = "QEMU package argument";
        needle = "qemu-crucible";
      }
      {
        label = "plugin package argument";
        needle = "crucible-qemu-plugin";
      }
      {
        label = "matched QEMU/plugin runtime closure";
        needle = "runtimeDeps = [qemu-crucible crucible-qemu-plugin];";
      }
      {
        label = "compile-time AOS QEMU hint";
        needle = "CRUCIBLE_AOS_QEMU = \"" + "$" + "{qemu-crucible}/bin/qemu-system-x86_64\";";
      }
      {
        label = "compile-time AOS plugin hint";
        needle = "CRUCIBLE_AOS_PLUGIN = \"" + "$" + "{crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so\";";
      }
      {
        label = "QEMU package build-info field";
        needle = "qemu_package=qemu-crucible";
      }
      {
        label = "QEMU path build-info field";
        needle = "qemu_path=" + "$" + "{qemu-crucible}/bin/qemu-system-x86_64";
      }
      {
        label = "plugin package build-info field";
        needle = "plugin_package=crucible-qemu-plugin";
      }
      {
        label = "plugin path build-info field";
        needle = "plugin_path=" + "$" + "{crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so";
      }
      {
        label = "discovery hint build-info field";
        needle = "discovery_hint=compile-time-aos-package-set";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "flag QEMU option";
        needle = "qemu: Option<PathBuf>";
      }
      {
        label = "flag plugin option";
        needle = "plugin: Option<PathBuf>";
      }
      {
        label = "QEMU env constant";
        needle = "const CRUCIBLE_QEMU_ENV: &str = \"CRUCIBLE_QEMU\";";
      }
      {
        label = "plugin env constant";
        needle = "const CRUCIBLE_PLUGIN_ENV: &str = \"CRUCIBLE_PLUGIN\";";
      }
      {
        label = "compile-time AOS QEMU hint read";
        needle = "option_env!(\"CRUCIBLE_AOS_QEMU\")";
      }
      {
        label = "compile-time AOS plugin hint read";
        needle = "option_env!(\"CRUCIBLE_AOS_PLUGIN\")";
      }
      {
        label = "flag discovery precedence";
        needle = "QemuDiscoverySource::Flag";
      }
      {
        label = "env discovery precedence";
        needle = "QemuDiscoverySource::Environment";
      }
      {
        label = "AOS package-set discovery precedence";
        needle = "QemuDiscoverySource::AosPackageSet";
      }
      {
        label = "patched QEMU marker validation";
        needle = "qemu_crucible_patches_applied";
      }
      {
        label = "plugin support marker validation";
        needle = "qemu_plugins_enabled";
      }
      {
        label = "plugin ABI mismatch failure";
        needle = "plugin_marker.plugin_abi != required_plugin_abi";
      }
      {
        label = "QEMU/plugin build identity mismatch failure";
        needle = "plugin_marker.qemu_build_id != qemu_marker.raw_build_id";
      }
      {
        label = "host PATH fallback diagnostic";
        needle = "host $PATH QEMU is never used";
      }
      {
        label = "discovery precedence regression test";
        needle = "cli_hermetic_qemu_discovery_prefers_flags_then_env_then_aos_package_set";
      }
      {
        label = "compile-time hint regression test";
        needle = "cli_hermetic_qemu_discovery_uses_compile_time_aos_package_hints";
      }
      {
        label = "absence and mismatch regression test";
        needle = "cli_hermetic_qemu_discovery_fails_absent_or_mismatched_artifacts_with_exit_4";
      }
    ]
    ++ forbiddenFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "host PATH QEMU discovery";
        needle = "std::env::var(\"PATH\")";
      }
      {
        label = "host which discovery";
        needle = "Command::new(\"which\")";
      }
      {
        label = "host PATH QEMU launch";
        needle = "Command::new(\"qemu";
      }
    ]
    ++ failuresFor "tests/crucible/phase5-cli-hermetic-discovery.nix" cliHermeticDiscoveryCheck [
      {
        label = "phase5 gate checks package QEMU hint";
        needle = "CRUCIBLE_AOS_QEMU";
      }
      {
        label = "phase5 gate checks package plugin hint";
        needle = "CRUCIBLE_AOS_PLUGIN";
      }
      {
        label = "phase5 gate runs hermetic discovery tests";
        needle = "cli_hermetic_qemu_discovery";
      }
      {
        label = "phase5 gate forbids host PATH QEMU discovery";
        needle = "host PATH QEMU discovery";
      }
    ]
    ++ failuresFor "tests/crucible/phase1-aos-workspace-build.nix" workspaceBuildCheck [
      {
        label = "output smoke checks QEMU package metadata";
        needle = "grep -q '^qemu_package=qemu-crucible$'";
      }
      {
        label = "output smoke checks QEMU path metadata";
        needle = "grep -q '^qemu_path=" + "$" + "{packages.qemu-crucible}/bin/qemu-system-x86_64$'";
      }
      {
        label = "output smoke checks plugin package metadata";
        needle = "grep -q '^plugin_package=crucible-qemu-plugin$'";
      }
      {
        label = "output smoke checks plugin path metadata";
        needle = "grep -q '^plugin_path=" + "$" + "{packages.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so$'";
      }
      {
        label = "output smoke checks discovery hint metadata";
        needle = "grep -q '^discovery_hint=compile-time-aos-package-set$'";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase7 hermetic discovery package check imported";
        needle = "cruciblePackageHermeticDiscovery = import ./phase7-crucible-package-hermetic-discovery.nix";
      }
      {
        label = "phase5 hermetic discovery behavior check imported";
        needle = "cliHermeticDiscovery = import ./phase5-cli-hermetic-discovery.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase7 package hermetic discovery check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    builtins.derivation {
      name = "crucible-phase7-package-hermetic-discovery-0";
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
            printf '%s\n' 'qemu_package=qemu-crucible'
            printf '%s\n' 'plugin_package=crucible-qemu-plugin'
            printf '%s\n' 'discovery_hint=compile-time-aos-package-set'
            printf '%s\n' 'behavior_gate=checks.crucible.phase5.cliHermeticDiscovery'
            printf '%s\n' 'output_smoke=checks.crucible.phase1.aosWorkspaceBuild'
            printf '%s\n' 'host_path_fallback=false'
          } > "$out/result"
        ''
      ];
      ATTR_PATH = attrPath;
      TASK_IDS = builtins.concatStringsSep "," taskIds;
    }
