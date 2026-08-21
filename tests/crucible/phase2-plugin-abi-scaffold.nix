{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginAbiScaffold",
  taskIds ? ["T-PLUG-1"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  pluginCargo = builtins.readFile ../../crates/crucible-qemu-plugin/Cargo.toml;
  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginAbi = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi.rs;
  pluginAbiTests = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi/tests.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "crates/crucible-qemu-plugin/Cargo.toml" pluginCargo [
      {
        label = "exact cdylib crate type";
        needle = "crate-type = [\"cdylib\"]";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "plugin owns callbacks";
        needle = "The plugin MUST own the device and channel callbacks";
      }
      {
        label = "single-threaded RR model";
        needle = "single-threaded round-robin TCG";
      }
      {
        label = "reentrant callback state partition";
        needle = "device-callback pointers fixed once at";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "ABI module exported";
        needle = "pub mod abi;";
      }
      {
        label = "install entry point exported";
        needle = "qemu_plugin_install";
      }
      {
        label = "plugin API version exported";
        needle = "QEMU_PLUGIN_API_VERSION";
      }
      {
        label = "plugin version symbol exported";
        needle = "qemu_plugin_version";
      }
      {
        label = "callback table exported";
        needle = "RegisteredDeviceCallbacks";
      }
      {
        label = "state partition exported";
        needle = "PluginStatePartition";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi.rs" pluginAbi [
      {
        label = "install symbol constant";
        needle = "pub const QEMU_PLUGIN_INSTALL_SYMBOL: &str = \"qemu_plugin_install\";";
      }
      {
        label = "plugin API version constant";
        needle = "pub const QEMU_PLUGIN_API_VERSION: c_int = 4;";
      }
      {
        label = "version symbol constant";
        needle = "pub const QEMU_PLUGIN_VERSION_SYMBOL: &str = \"qemu_plugin_version\";";
      }
      {
        label = "Register compatibility symbol";
        needle = "pub const QEMU_PLUGIN_REGISTER_ENTRYPOINT_SYMBOL";
      }
      {
        label = "exported plugin version symbol";
        needle = "pub static qemu_plugin_version: c_int = QEMU_PLUGIN_API_VERSION;";
      }
      {
        label = "exported install symbol";
        needle = "#[unsafe(no_mangle)]";
      }
      {
        label = "unsafe C ABI install function";
        needle = "pub unsafe extern \"C\" fn qemu_plugin_install";
      }
      {
        label = "raw install boundary validation";
        needle = "pub fn validate_install_boundary";
      }
      {
        label = "execution model type";
        needle = "pub struct QemuPluginExecutionModel";
      }
      {
        label = "QEMU info ABI layout";
        needle = "pub struct QemuPluginInfo";
      }
      {
        label = "QEMU info execution-model extraction";
        needle = "pub fn execution_model_from_qemu_info";
      }
      {
        label = "safe QEMU info install scaffold";
        needle = "pub fn install_inert_scaffold_from_qemu_info";
      }
      {
        label = "single-threaded RR threading mode";
        needle = "SingleThreadedRoundRobin";
      }
      {
        label = "MTTCG rejection";
        needle = "MultiThreadedTcg";
      }
      {
        label = "live execution-mode proof symbol";
        needle = "QEMU_PLUGIN_SINGLE_THREADED_RR_SYMBOL";
      }
      {
        label = "device callback kind registry";
        needle = "pub enum PluginDeviceCallbackKind";
      }
      {
        label = "owned callback families";
        needle = "pub const OWNED_DEVICE_CALLBACK_KINDS";
      }
      {
        label = "immutable callback table";
        needle = "pub struct RegisteredDeviceCallbacks";
      }
      {
        label = "state partition";
        needle = "pub struct PluginStatePartition";
      }
      {
        label = "lifecycle core";
        needle = "pub struct PluginLifecycleCore";
      }
      {
        label = "network tx callback";
        needle = "crucible_qemu_plugin_inert_network_tx_cb";
      }
      {
        label = "network rx callback";
        needle = "crucible_qemu_plugin_inert_network_rx_cb";
      }
      {
        label = "block submit callback";
        needle = "crucible_qemu_plugin_inert_block_submit_cb";
      }
      {
        label = "block poll callback";
        needle = "crucible_qemu_plugin_inert_block_poll_cb";
      }
      {
        label = "9p submit callback";
        needle = "crucible_qemu_plugin_inert_9p_submit_cb";
      }
      {
        label = "9p poll callback";
        needle = "crucible_qemu_plugin_inert_9p_poll_cb";
      }
      {
        label = "whitebox doorbell callback";
        needle = "crucible_qemu_plugin_inert_whitebox_doorbell_cb";
      }
      {
        label = "vCPU lifecycle callbacks";
        needle = "crucible_qemu_plugin_inert_vcpu_idle_cb";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi/tests.rs" pluginAbiTests [
      {
        label = "supports N vCPUs under RR";
        needle = "multi-vCPU RR-TCG should validate";
      }
      {
        label = "install boundary test";
        needle = "abi_install_entrypoint_validates_raw_boundary_and_builds_inert_model";
      }
      {
        label = "QEMU-facing install model validation test";
        needle = "abi_qemu_install_path_validates_execution_model_before_success";
      }
      {
        label = "execution model test";
        needle = "abi_execution_model_requires_single_threaded_tcg_not_single_vcpu_only";
      }
      {
        label = "safe scaffold invalid-model test";
        needle = "abi_safe_scaffold_shim_rejects_invalid_models";
      }
      {
        label = "state partition test";
        needle = "abi_state_partition_keeps_device_callbacks_immutable_and_reentrant_safe";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin ABI scaffold check";
        needle = "qemuPluginAbiScaffold = import ./phase2-plugin-abi-scaffold.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin ABI scaffold check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-abi-scaffold";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
        pkgs.binutils
        pkgs.grep
        pkgs.qemu-crucible
        pkgs.rust
        pkgs.sed
      ];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "configure";
          script = ''
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
          name = "run-plugin-abi-scaffold";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            target_dir="$TMPDIR/crucible-plugin-abi-scaffold-target"
            qemu_header="${pkgs.qemu-crucible}/include/qemu/qemu-plugin.h"
            test -f "$qemu_header"
            grep -q '#define QEMU_PLUGIN_VERSION 4' "$qemu_header"
            grep -q 'extern QEMU_PLUGIN_EXPORT int qemu_plugin_version;' "$qemu_header"
            grep -q 'qemu_plugin_crucible_single_threaded_rr' "$qemu_header"
            cargo test \
              --frozen \
              --offline \
              --target-dir "$target_dir" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin \
              abi \
              -- --test-threads=1
            cargo build \
              --frozen \
              --offline \
              --target-dir "$target_dir" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu-plugin
            plugin_so="$target_dir/debug/libcrucible_qemu_plugin.so"
            test -f "$plugin_so"
            nm -D --defined-only "$plugin_so" > "$TMPDIR/crucible-plugin-abi-symbols"
            grep -Eq ' T qemu_plugin_install$' "$TMPDIR/crucible-plugin-abi-symbols"
            grep -Eq ' [BDGRS] qemu_plugin_version$' "$TMPDIR/crucible-plugin-abi-symbols"
          '';
        }
        {
          name = "write-result";
          script = ''
            set -eu
            mkdir -p "$out"
            cat > "$out/result" <<'RESULT'
            PASS
            check=${attrPath}
            tasks=${taskList}
            open_tasks=${openTaskList}
            status=complete
            crate_type=cdylib
            qemu_plugin_api_version=4
            qemu_entrypoint=qemu_plugin_install
            qemu_version_symbol=qemu_plugin_version
            exported_symbols=qemu_plugin_install,qemu_plugin_version
            install_scaffold=fail-closed-with-live-callback-adapters
            live_execution_mode_proof=qemu_plugin_crucible_single_threaded_rr
            tcg_threading=single-threaded-round-robin
            smp_vcpus_supported=N>=1
            mttcg_rejected=true
            callback_owner=crucible-qemu-plugin
            callback_table=registration-time-initialized-never-mutated
            callback_families=net-tx,net-rx,block-submit,block-poll,9p-submit,9p-poll,whitebox-doorbell
            RESULT
          '';
        }
      ];
    }
