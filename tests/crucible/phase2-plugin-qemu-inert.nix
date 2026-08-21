{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginQemuInert",
  taskIds ? ["T-PLUG-23"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  pluginInertness = builtins.readFile ../../crates/crucible-qemu-plugin/src/inertness.rs;
  pluginGate = builtins.readFile ../../crates/crucible-qemu-plugin/tests/gate_qemu_inert.rs;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  harnessSpec = builtins.readFile ../../docs/rfcs/0010-crucible/24-determinism-harness-testing.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor;

  failures =
    failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "plugin-half scope wording";
        needle = "contributes plugin-half evidence for [PLUG-49]";
      }
      {
        label = "full qemu inert corpus implemented by T-PATCH-3";
        needle = "full real-QEMU corpus is";
      }
      {
        label = "PLUG-49 text";
        needle = "When sim mode is off the plugin is not loaded at all";
      }
      {
        label = "plugin argument absence";
        needle = "no `-plugin`";
      }
      {
        label = "zero effect wording";
        needle = "zero effect on a QEMU process launched without it";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/24-determinism-harness-testing.md" harnessSpec [
      {
        label = "full qemu inert gate remains harness-owned";
        needle = "T-HARN-21";
      }
      {
        label = "full qemu inert corpus is real-QEMU comparison";
        needle = "behaviorally identical to an unpatched reference build";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "inertness module exported";
        needle = "pub mod inertness;";
      }
      {
        label = "inertness API re-exported";
        needle = "assert_plugin_inert";
      }
      {
        label = "module map documents plugin inertness";
        needle = "`inertness` owns plugin-side sim-off load and effect assertions";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/inertness.rs" pluginInertness [
      {
        label = "sim-off observation constructor";
        needle = "pub const fn sim_off() -> Self";
      }
      {
        label = "plugin argument sim-off error";
        needle = "PluginArgumentWhenSimulationOff";
      }
      {
        label = "install entrypoint sim-off error";
        needle = "InstallEntrypointCalledWhenSimulationOff";
      }
      {
        label = "control socket sim-off error";
        needle = "ControlSocketOpenedWhenSimulationOff";
      }
      {
        label = "shared memory sim-off error";
        needle = "SharedMemoryMappedWhenSimulationOff";
      }
      {
        label = "callback registration sim-off error";
        needle = "CallbacksRegisteredWhenSimulationOff";
      }
      {
        label = "patched capability sim-off error";
        needle = "PatchCapabilitiesInvokedWhenSimulationOff";
      }
      {
        label = "time-control request effect";
        needle = "time_control_requests";
      }
      {
        label = "time-control status effect";
        needle = "time_control_status_queries";
      }
      {
        label = "virtual clock update effect";
        needle = "virtual_clock_updates";
      }
      {
        label = "preemption injection effect";
        needle = "preemption_injections";
      }
      {
        label = "vCPU register read effect";
        needle = "vcpu_register_reads";
      }
      {
        label = "RR cursor read effect";
        needle = "rr_cursor_reads";
      }
      {
        label = "network capacity query effect";
        needle = "network_receive_capacity_queries";
      }
      {
        label = "coverage registration effect";
        needle = "coverage_callback_registrations";
      }
      {
        label = "whitebox trap registration effect";
        needle = "whitebox_trap_registrations";
      }
      {
        label = "callback family count tied to plugin ABI";
        needle = "OWNED_DEVICE_CALLBACK_KINDS.len()";
      }
      {
        label = "zero effect test";
        needle = "plugin_sim_off_observation_has_no_load_or_effects";
      }
      {
        label = "effect vector rejection test";
        needle = "plugin_sim_off_rejects_every_load_or_effect_vector";
      }
      {
        label = "sim-on observation control";
        needle = "plugin_sim_on_observation_records_loaded_plugin_effects";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/tests/gate_qemu_inert.rs" pluginGate [
      {
        label = "plugin-half gate test";
        needle = "gate_qemu_inert_plugin_half_is_backed_by_phase_check";
      }
      {
        label = "full gate consumes the completed live corpus";
        needle = "full_real_qemu_corpus=checks.crucible.phase2.gates.qemuInert";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin qemu-inert check";
        needle = "qemuPluginQemuInert = import ./phase2-plugin-qemu-inert.nix";
      }
      {
        label = "phase2 exposes full qemu-inert gate";
        needle = "qemuInert = import ./phase2-qemu-inert.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin qemu-inert check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-qemu-inert";
      version = "0";
      src = crucibleSrc;

      buildDeps = [
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
          name = "run-plugin-qemu-inert";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            target_dir="$TMPDIR/crucible-plugin-qemu-inert-target"
            run_exact_test() {
              filter="$1"
              expected="$2"
              list_file="$TMPDIR/test-list"
              output_file="$TMPDIR/test-output"

              cargo test \
                --frozen \
                --offline \
                --target-dir "$target_dir" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
                -- --list > "$list_file"
              if [ "$(grep -Fx "$expected: test" "$list_file" | wc -l | tr -d ' ')" != 1 ]; then
                echo "expected exactly one listed test: $expected" >&2
                cat "$list_file" >&2
                exit 1
              fi

              cargo test \
                --frozen \
                --offline \
                --target-dir "$target_dir" \
                --manifest-path crates/Cargo.toml \
                -p crucible-qemu-plugin \
                "$filter" \
                -- --exact --test-threads=1 > "$output_file"
              if ! grep -q 'test result: ok. 1 passed;' "$output_file"; then
                echo "expected exactly one passed test: $expected" >&2
                cat "$output_file" >&2
                exit 1
              fi
            }

            run_exact_test \
              inertness::tests::plugin_sim_off_observation_has_no_load_or_effects \
              inertness::tests::plugin_sim_off_observation_has_no_load_or_effects
            run_exact_test \
              inertness::tests::plugin_sim_off_rejects_every_load_or_effect_vector \
              inertness::tests::plugin_sim_off_rejects_every_load_or_effect_vector
            run_exact_test \
              inertness::tests::plugin_sim_on_observation_records_loaded_plugin_effects \
              inertness::tests::plugin_sim_on_observation_records_loaded_plugin_effects
            run_exact_test \
              gate_qemu_inert_plugin_half_is_backed_by_phase_check \
              gate_qemu_inert_plugin_half_is_backed_by_phase_check
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
            gate=gate:qemu-inert
            plugin_half=contributes-to-PLUG-49-sim-off-no-plugin-arg-no-load-no-effects
            full_PLUG49_gate=complete-with-live-corpus
            full_real_qemu_corpus=checks.crucible.phase2.gates.qemuInert
            RESULT
          '';
        }
      ];
    }
