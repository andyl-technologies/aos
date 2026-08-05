{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase5.cliHermeticDiscovery",
  taskIds ? ["T-CLI-5"],
  dependencies ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  cliDoc = builtins.readFile ../../docs/rfcs/0010-crucible/23-cli.md;
  planDoc = builtins.readFile ../../docs/rfcs/0010-crucible/32-implementation-plan.md;
  cliMain = import ./_cli-source.nix {inherit lib;};
  cliCargo = builtins.readFile ../../crates/crucible-cli/Cargo.toml;
  defaultChecks = builtins.readFile ./default.nix;
  cruciblePkg = builtins.readFile ../../pkgs/tools/crucible/crucible.nix;
  pluginPkg = builtins.readFile ../../pkgs/emulation/crucible-qemu-plugin.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/23-cli.md" cliDoc [
      {
        label = "T-CLI-5 completion note";
        needle = "Completed by `checks.crucible.phase5.cliHermeticDiscovery`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/32-implementation-plan.md" planDoc [
      {
        label = "phase5 CLI hermetic discovery status note";
        needle = "`T-CLI-5` is green through `checks.crucible.phase5.cliHermeticDiscovery`";
      }
    ]
    ++ failuresFor "crates/crucible-cli/src/main.rs" cliMain [
      {
        label = "QEMU env constant";
        needle = "const CRUCIBLE_QEMU_ENV: &str = \"CRUCIBLE_QEMU\";";
      }
      {
        label = "plugin env constant";
        needle = "const CRUCIBLE_PLUGIN_ENV: &str = \"CRUCIBLE_PLUGIN\";";
      }
      {
        label = "AOS package QEMU hint";
        needle = "option_env!(\"CRUCIBLE_AOS_QEMU\")";
      }
      {
        label = "AOS package plugin hint";
        needle = "option_env!(\"CRUCIBLE_AOS_PLUGIN\")";
      }
      {
        label = "plugin ABI prefix";
        needle = "const CRUCIBLE_QEMU_PLUGIN_ABI_PREFIX";
      }
      {
        label = "plugin ABI derives from shmem";
        needle = "crucible::SHMEM_ABI_VERSION";
      }
      {
        label = "required plugin ABI helper";
        needle = "fn required_qemu_plugin_abi";
      }
      {
        label = "discovery source enum";
        needle = "enum QemuDiscoverySource";
      }
      {
        label = "QEMU discovery environment seam";
        needle = "trait QemuDiscoveryEnvironment";
      }
      {
        label = "AOS package-set seam";
        needle = "trait AosQemuPackageSet";
      }
      {
        label = "discovery planner";
        needle = "fn discover_qemu_artifacts";
      }
      {
        label = "explicit qemu requirement";
        needle = "fn require_qemu_artifacts";
      }
      {
        label = "discovery precedence";
        needle = "QemuDiscoverySource::Flag";
      }
      {
        label = "environment discovery source";
        needle = "QemuDiscoverySource::Environment";
      }
      {
        label = "AOS package-set discovery source";
        needle = "QemuDiscoverySource::AosPackageSet";
      }
      {
        label = "marker validation";
        needle = "fn read_qemu_build_marker";
      }
      {
        label = "plugin marker validation";
        needle = "fn read_plugin_build_marker";
      }
      {
        label = "QEMU executable probe";
        needle = "fn probe_qemu_executable";
      }
      {
        label = "QEMU version process query";
        needle = ".arg(\"--version\")";
      }
      {
        label = "plugin shared-object probe";
        needle = "fn probe_qemu_plugin";
      }
      {
        label = "plugin install symbol query";
        needle = "qemu_plugin_install";
      }
      {
        label = "patched QEMU marker check";
        needle = "qemu_crucible_patches_applied";
      }
      {
        label = "plugin support marker check";
        needle = "qemu_plugins_enabled";
      }
      {
        label = "plugin ABI mismatch check";
        needle = "plugin_marker.plugin_abi != required_plugin_abi";
      }
      {
        label = "QEMU build identity mismatch check";
        needle = "plugin_marker.qemu_build_id != qemu_marker.raw_build_id";
      }
      {
        label = "artifact identity from resolved backend";
        needle = "fn expected_replay_identity_for_backend";
      }
      {
        label = "resolved backend carries QEMU build ID";
        needle = "qemu_build_id: String";
      }
      {
        label = "resolved backend carries QEMU patch series";
        needle = "qemu_patch_series_hash: String";
      }
      {
        label = "QEMU marker carries patch series";
        needle = "required_metadata_field(&fields, \"qemu_patch_series_hash\", &marker)";
      }
      {
        label = "resolved backend carries plugin ABI";
        needle = "plugin_abi: String";
      }
      {
        label = "T-CLI-5 proof predicate";
        needle = "fn proves_t_cli_5";
      }
      {
        label = "host PATH never used message";
        needle = "host $PATH QEMU is never used";
      }
      {
        label = "discovery precedence test";
        needle = "cli_hermetic_qemu_discovery_prefers_flags_then_env_then_aos_package_set";
      }
      {
        label = "compile-time AOS hint test";
        needle = "cli_hermetic_qemu_discovery_uses_compile_time_aos_package_hints";
      }
      {
        label = "absence and mismatch exit test";
        needle = "cli_hermetic_qemu_discovery_fails_absent_or_mismatched_artifacts_with_exit_4";
      }
      {
        label = "artifact identity pinning test";
        needle = "cli_hermetic_qemu_discovery_pins_identity_into_failure_artifacts";
      }
      {
        label = "text impersonation rejection test";
        needle = "cli_hermetic_qemu_discovery_rejects_text_artifact_impersonation";
      }
    ]
    ++ failuresFor "crates/crucible-cli/Cargo.toml" cliCargo [
      {
        label = "CLI depends on guest-host protocol ABI source";
        needle = "crucible-protocol = { path = \"../crucible-protocol\" }";
      }
    ]
    ++ failuresFor "pkgs/tools/crucible/crucible.nix" cruciblePkg [
      {
        label = "QEMU package argument";
        needle = "qemu-crucible";
      }
      {
        label = "plugin package argument";
        needle = "crucible-qemu-plugin";
      }
      {
        label = "runtime QEMU wrapper configuration";
        needle = "CRUCIBLE_QEMU:=";
      }
      {
        label = "runtime plugin wrapper configuration";
        needle = "CRUCIBLE_PLUGIN:=";
      }
      {
        label = "separate suite runtime closure";
        needle = "runtimeDeps = [controller qemu-crucible crucible-qemu-plugin qemu-crucible-source linux-crucible crucible-fixtures]";
      }
    ]
    ++ failuresFor "pkgs/emulation/crucible-qemu-plugin.nix" pluginPkg [
      {
        label = "plugin build-info reads shmem source";
        needle = "done < crucible-shmem/src/lib.rs";
      }
      {
        label = "plugin build-info ABI prefix";
        needle = "plugin_abi=crucible-shmem-abi-v$shmem_abi_version";
      }
      {
        label = "plugin build-info QEMU identity";
        needle = "qemu_build_id=\${qemu-crucible.passthru.qemuBuildIdentity}";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase5 exposes CLI hermetic discovery check";
        needle = "cliHermeticDiscovery = import ./phase5-cli-hermetic-discovery.nix";
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
      {
        label = "shell PATH search";
        needle = builtins.concatStringsSep " " ["which" "qemu"];
      }
    ];

  failureText = builtins.concatStringsSep "\n" failures;
in
  pkgs.mkDerivation {
    pname = "crucible-phase5-cli-hermetic-discovery";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.rust
      pkgs.sed
    ];

    CRUCIBLE_T_CLI_5_FAILURES = failureText;
    ATTR_PATH = attrPath;
    TASK_IDS = taskList;
    DEPENDENCY_COUNT = toString (builtins.length dependencies);
    DEPENDENCY_PATHS = builtins.concatStringsSep ":" dependencies;

    phases = [
      {
        name = "unpack";
        script = ''
          set -eu
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          mkdir -p "$CARGO_HOME" .cargo
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
        '';
      }
      {
        name = "run-cli-hermetic-discovery";
        script = ''
          set -eu

          if [ -n "$CRUCIBLE_T_CLI_5_FAILURES" ]; then
            printf '%s\n' "$CRUCIBLE_T_CLI_5_FAILURES" >&2
            exit 1
          fi

          if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
            cd source
          fi
          qemu_fixture="$TMPDIR/aos-package-set/qemu"
          plugin_fixture="$TMPDIR/aos-package-set/plugin"
          mkdir -p \
            "$qemu_fixture/bin" \
            "$qemu_fixture/share/aos/crucible" \
            "$plugin_fixture/lib" \
            "$plugin_fixture/nix-support"
          printf '%s\n' \
            '#include <stdio.h>' \
            'int main(void) { puts("qemu-crucible fixture"); return 0; }' \
            > "$TMPDIR/qemu-fixture.c"
          "$CC" "$TMPDIR/qemu-fixture.c" \
            -o "$qemu_fixture/bin/qemu-system-x86_64"
          printf '%s\n' \
            'int qemu_plugin_version = 1;' \
            'void qemu_plugin_install(void) {}' \
            > "$TMPDIR/plugin-fixture.c"
          "$CC" -shared -fPIC "$TMPDIR/plugin-fixture.c" \
            -o "$plugin_fixture/lib/libcrucible_qemu_plugin.so"
          {
            printf 'qemu_plugins_enabled=true\n'
            printf 'qemu_crucible_patches_applied=true\n'
            printf 'qemu_sim_capability=qemu-crucible\n'
            printf 'qemu_patch_series_hash=sha256-test-qemu-patch-series\n'
            printf 'qemu_shmem_abi_version=5\n'
            printf 'qemu_shmem_abi=crucible-shmem-abi-v5\n'
            printf 'qemu_shmem_header=include/aos/crucible/crucible_shmem_abi.h\n'
            printf 'qemu_shmem_header_hash=sha256-test-shmem-header\n'
            printf 'qemu_build_id=gate-aos-qemu-build\n'
          } > "$qemu_fixture/share/aos/crucible/qemu-build-identity.env"
          {
            printf 'package=crucible-qemu-plugin\n'
            printf 'qemu_package=qemu-crucible\n'
            printf 'qemu_build_id=gate-aos-qemu-build\n'
            printf 'shmem_abi_version=5\n'
            printf 'shmem_abi=crucible-shmem-abi-v5\n'
            printf 'shmem_generated_header_hash=sha256-test-shmem-header\n'
            printf 'plugin_abi=crucible-shmem-abi-v5\n'
          } > "$plugin_fixture/nix-support/crucible-qemu-plugin-build-info"
          export CRUCIBLE_AOS_QEMU="$qemu_fixture/bin/qemu-system-x86_64"
          export CRUCIBLE_AOS_PLUGIN="$plugin_fixture/lib/libcrucible_qemu_plugin.so"

          cd crates
          cargo test \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/crucible-cli-hermetic-discovery-target" \
            -p crucible-cli \
            cli_hermetic_qemu_discovery \
            -- --test-threads=1
        '';
      }
    ];

    meta = {
      description = "RFC-0010 phase 5 CLI hermetic QEMU discovery gate for ${taskList}";
      passthru = {
        inherit attrPath dependencies failureText taskIds;
      };
    };
  }
