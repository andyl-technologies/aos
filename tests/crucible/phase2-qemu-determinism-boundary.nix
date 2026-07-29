{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuDeterminismBoundary",
  taskIds ? ["T-QEMU-10"],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  qemuLib = builtins.readFile ../../crates/crucible-qemu/src/lib.rs;
  boundaryLib = builtins.readFile ../../crates/crucible-qemu/src/determinism_boundary.rs;
  qemuSpec = builtins.readFile ../../docs/rfcs/0010-crucible/10-qemu-integration.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;

  inherit (import ./_lib.nix {inherit lib;}) hasInfix failuresFor forbiddenFor;



  failures =
    failuresFor "docs/rfcs/0010-crucible/10-qemu-integration.md" qemuSpec [
      {
        label = "T-QEMU-10 checklist complete";
        needle = "- [x] **T-QEMU-10**";
      }
      {
        label = "completion note names determinism boundary";
        needle = "determinism-boundary validator";
      }
      {
        label = "completion note names black-box fingerprint";
        needle = "black-box plugin fingerprint definition";
      }
      {
        label = "completion note points at implemented qemu-inert corpus";
        needle = "checks.crucible.phase2.gates.qemuInert";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/lib.rs" qemuLib [
      {
        label = "determinism boundary module";
        needle = "mod determinism_boundary;";
      }
      {
        label = "determinism boundary exports";
        needle = "pub use determinism_boundary::{";
      }
      {
        label = "boundary validator export";
        needle = "validate_qemu_determinism_boundary";
      }
      {
        label = "fingerprint definition export";
        needle = "QemuExecutionFingerprintDefinition";
      }
    ]
    ++ failuresFor "crates/crucible-qemu/src/determinism_boundary.rs" boundaryLib [
      {
        label = "module docs";
        needle = "QEMU determinism-boundary validation";
      }
      {
        label = "fixed cadence constant";
        needle = "QEMU_EXECUTION_FINGERPRINT_CADENCE_ICOUNT";
      }
      {
        label = "required fingerprint components";
        needle = "REQUIRED_QEMU_FINGERPRINT_COMPONENTS";
      }
      {
        label = "aggregate icount component";
        needle = "AggregateIcount";
      }
      {
        label = "register component";
        needle = "ArchitecturalRegisters";
      }
      {
        label = "memory component";
        needle = "GuestMemory";
      }
      {
        label = "device component";
        needle = "DeviceState";
      }
      {
        label = "plugin introspection requirement";
        needle = "PluginIntrospectionDisabled";
      }
      {
        label = "black-box no guest cooperation";
        needle = "GuestCooperationRequired";
      }
      {
        label = "content-addressed fingerprint digest";
        needle = "definition_digest";
      }
      {
        label = "single-VM scenario bridge";
        needle = "SingleVmFingerprintScenario::new";
      }
      {
        label = "launch material validation";
        needle = "validate_launch_boundary_material";
      }
      {
        label = "sim-mode inertness validation";
        needle = "assert_qemu_control_plane_inert";
      }
      {
        label = "sim-mode launch activation validation";
        needle = "validate_sim_mode_activation";
      }
      {
        label = "exact plugin option validation";
        needle = "plugin_option_matches";
      }
      {
        label = "whitebox plugin activation required";
        needle = "plugin whitebox introspection";
      }
      {
        label = "entropy elimination enum";
        needle = "pub enum QemuEntropyElimination";
      }
      {
        label = "negative case enum";
        needle = "pub enum QemuEntropyEliminationNegativeCase";
      }
      {
        label = "required entropy eliminations";
        needle = "REQUIRED_QEMU_ENTROPY_ELIMINATIONS";
      }
      {
        label = "microtest matrix function";
        needle = "qemu_entropy_elimination_microtests";
      }
      {
        label = "executable negative microtests";
        needle = "run_negative_microtest";
      }
      {
        label = "negative microtest failure semantics";
        needle = "NegativeMicrotestDidNotFail";
      }
      {
        label = "qemu-inert microtest gate";
        needle = "\"gate:qemu-inert\"";
      }
      {
        label = "boundary acceptance test";
        needle = "qemu_determinism_boundary_accepts_canonical_contract";
      }
      {
        label = "missing sim-mode activation rejection test";
        needle = "qemu_determinism_boundary_rejects_missing_sim_mode_launch_activation";
      }
      {
        label = "non-inert sim-on traffic rejection test";
        needle = "qemu_determinism_boundary_rejects_non_inert_sim_on_runtime_control_traffic";
      }
      {
        label = "fingerprint content-address test";
        needle = "qemu_execution_fingerprint_definition_is_content_addressed";
      }
      {
        label = "single-VM scenario test";
        needle = "qemu_execution_fingerprint_definition_builds_single_vm_scenario";
      }
      {
        label = "missing device state test";
        needle = "qemu_boundary_rejects_fingerprint_without_black_box_device_state";
      }
      {
        label = "microtest coverage test";
        needle = "qemu_boundary_rejects_incomplete_or_non_failing_microtest_matrix";
      }
      {
        label = "negative case backing test";
        needle = "qemu_entropy_elimination_negative_cases_are_backed_by_launch_or_inertness_checks";
      }
      {
        label = "whitebox plugin activation test";
        needle = "qemu_boundary_rejects_sim_on_without_whitebox_plugin_introspection";
      }
      {
        label = "prefix-matched plugin activation rejection test";
        needle = "qemu_boundary_rejects_prefix_matched_plugin_activation_values";
      }
    ]
    ++ forbiddenFor "crates/crucible-qemu/src/determinism_boundary.rs" boundaryLib [
      {
        label = "production unwrap";
        needle = ".unwrap()";
      }
      {
        label = "production expect";
        needle = ".expect(";
      }
      {
        label = "hard-coded host shell";
        needle = "/bin/sh";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes qemu determinism boundary check";
        needle = "qemuDeterminismBoundary = import ./phase2-qemu-determinism-boundary.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 qemu determinism-boundary check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-determinism-boundary";
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
          name = "run-qemu-determinism-boundary";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi
            cargo test \
              --frozen \
              --offline \
              --target-dir "$TMPDIR/crucible-qemu-determinism-boundary-target" \
              --manifest-path crates/Cargo.toml \
              -p crucible-qemu \
              --lib \
              determinism_boundary::tests \
              -- --test-threads=1
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
            check_scope=task-level
            related_gates=gate:single-vm-fingerprint,gate:any-guest,gate:qemu-inert,gate:layer0-determinism
            rust_test=crucible-qemu::determinism_boundary::tests
            boundary_inputs=deterministic-launch-profile,sim-mode-inertness,black-box-plugin-fingerprint
            fingerprint_components=periodic-icount,architectural-registers,guest-memory,device-state
            entropy_elimination_microtests=tcg-icount,cpu-entropy,rtc,guest-entropy,run-seed,input,cow-backing,idle-warp,device-delivery,sim-mode
            full_qemu_inert_gate=checks.crucible.phase2.gates.qemuInert
            n_vcpu_fingerprint=checks.crucible.phase2.qemuNvcpuFingerprint
            RESULT
          '';
        }
      ];
    }
