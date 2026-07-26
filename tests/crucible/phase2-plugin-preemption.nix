{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuPluginPreemption",
  taskIds ? ["T-PLUG-25"],
  openTaskIds ? [],
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = "sha256-FOPwUc3isoWPEWq+/wsR5Jni2ecaW9AUU7EuHSMBq24=";
  };

  pluginLib = builtins.readFile ../../crates/crucible-qemu-plugin/src/lib.rs;
  protocolPreemption = builtins.readFile ../../crates/crucible-protocol/src/preemption.rs;
  pluginPreemption =
    builtins.readFile ../../crates/crucible-qemu-plugin/src/preemption.rs
    + builtins.readFile ../../crates/crucible-qemu-plugin/src/preemption/injector.rs;
  pluginRoundRobin = builtins.readFile ../../crates/crucible-qemu-plugin/src/round_robin.rs;
  pluginAbi = builtins.readFile ../../crates/crucible-qemu-plugin/src/abi.rs;
  pluginAbiTests =
    builtins.readFile ../../crates/crucible-qemu-plugin/src/abi/tests.rs
    + builtins.readFile ../../crates/crucible-qemu-plugin/src/abi/tests/capabilities.rs;
  pluginInertness = builtins.readFile ../../crates/crucible-qemu-plugin/src/inertness.rs;
  determinismSpec = builtins.readFile ../../docs/rfcs/0010-crucible/04-determinism-contract.md;
  pluginSpec = builtins.readFile ../../docs/rfcs/0010-crucible/12-qemu-plugin.md;
  patchSpec = builtins.readFile ../../docs/rfcs/0010-crucible/11-qemu-patches.md;
  defaultChecks = builtins.readFile ./default.nix;

  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

  failuresFor = fileLabel: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${fileLabel}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  failures =
    failuresFor "docs/rfcs/0010-crucible/04-determinism-contract.md" determinismSpec [
      {
        label = "T-DET-30 is complete";
        needle = "- [x] **T-DET-30**";
      }
      {
        label = "T-DET-30 completion note names preemption check";
        needle = "`checks.crucible.phase2.qemuPluginPreemption`";
      }
      {
        label = "T-DET-30 completion note names fixed IPI latency";
        needle = "fixed modeled IPI latency";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/12-qemu-plugin.md" pluginSpec [
      {
        label = "T-PLUG-25 is complete with live QEMU callback integration";
        needle = "- [x] **T-PLUG-25**";
      }
      {
        label = "Decision::Preemption obligation";
        needle = "Decision::Preemption";
      }
      {
        label = "commanded icount wording";
        needle = "commanded node-icount";
      }
      {
        label = "authorized window wording";
        needle = "authorized window `[deadline, ceiling]`";
      }
      {
        label = "no clamp/defer wording";
        needle = "rather than clamp, defer, or apply it at a different";
      }
      {
        label = "live preemption completion gate";
        needle = "`checks.crucible.phase2.qemuLivePluginPreemption`";
      }
    ]
    ++ failuresFor "docs/rfcs/0010-crucible/11-qemu-patches.md" patchSpec [
      {
        label = "patch preemption export";
        needle = "qemu_plugin_inject_preemption";
      }
      {
        label = "patch reject out-of-window";
        needle = "authorized `[deadline, ceiling]` window MUST be rejected loudly";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/lib.rs" pluginLib [
      {
        label = "preemption module exported";
        needle = "pub mod preemption;";
      }
      {
        label = "preemption API re-exported";
        needle = "PluginPreemptionInjector";
      }
      {
        label = "deterministic IPI planner re-exported";
        needle = "plan_deterministic_ipi_delivery";
      }
      {
        label = "deterministic IPI plan type re-exported";
        needle = "DeterministicIpiDelivery";
      }
      {
        label = "module map documents preemption";
        needle = "`preemption` owns scheduler-commanded vCPU switch and interrupt injection";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/preemption.rs" pluginPreemption [
      {
        label = "QEMU preemption symbol";
        needle = "QEMU_PLUGIN_INJECT_PREEMPTION_SYMBOL";
      }
      {
        label = "QEMU preemption function type";
        needle = "pub type QemuInjectPreemptionFn";
      }
      {
        label = "required injector";
        needle = "pub struct PluginPreemptionInjector";
      }
      {
        label = "capability require path";
        needle = "pub fn require";
      }
      {
        label = "application API";
        needle = "pub fn apply_decision";
      }
      {
        label = "plugin preemption decision";
        needle = "pub struct PluginPreemptionDecision";
      }
      {
        label = "vCPU switch decision";
        needle = "pub const fn vcpu_switch";
      }
      {
        label = "interrupt decision";
        needle = "pub const fn interrupt_at";
      }
      {
        label = "authorization window";
        needle = "pub struct PreemptionWindow";
      }
      {
        label = "deterministic IPI planner";
        needle = "pub fn plan_deterministic_ipi_delivery";
      }
      {
        label = "deterministic IPI delivery plan";
        needle = "pub struct DeterministicIpiDelivery";
      }
      {
        label = "shared IPI boundary rounding helper";
        needle = "deterministic_ipi_delivery_icount";
      }
      {
        label = "same-vCPU IPI rejection";
        needle = "SameVcpuIpi";
      }
      {
        label = "IPI delivery overflow rejection";
        needle = "IpiDeliveryIcountOverflow";
      }
      {
        label = "before-deadline failure";
        needle = "CommandBeforeDeadline";
      }
      {
        label = "beyond-ceiling failure";
        needle = "CommandBeyondCeiling";
      }
      {
        label = "QEMU rejection failure";
        needle = "CapabilityRejected";
      }
      {
        label = "QEMU raw switch tag";
        needle = "QEMU_PREEMPTION_KIND_VCPU_SWITCH";
      }
      {
        label = "QEMU raw interrupt tag";
        needle = "QEMU_PREEMPTION_KIND_INTERRUPT_AT";
      }
      {
        label = "no pre-call on invalid command test";
        needle = "preemption_injector_rejects_out_of_window_without_clamping_or_calling_qemu";
      }
      {
        label = "switch dispatch test";
        needle = "preemption_injector_dispatches_vcpu_switch_at_commanded_icount";
      }
      {
        label = "interrupt dispatch test";
        needle = "preemption_injector_dispatches_interrupt_without_round_robin_switch";
      }
      {
        label = "rejection localization test";
        needle = "preemption_injector_localizes_malformed_or_rejected_commands";
      }
      {
        label = "deterministic IPI delivery test";
        needle = "deterministic_ipi_delivery_uses_fixed_latency_and_next_rr_switch";
      }
      {
        label = "deterministic IPI error test";
        needle = "deterministic_ipi_delivery_rejects_bad_vcpu_pairs_and_overflow";
      }
    ]
    ++ failuresFor "crates/crucible-protocol/src/preemption.rs" protocolPreemption [
      {
        label = "shared deterministic IPI boundary function";
        needle = "pub const fn deterministic_ipi_delivery_icount";
      }
      {
        label = "fixed latency and RR rounding unit proof";
        needle = "ipi_delivery_adds_fixed_latency_and_rounds_to_rr_boundary";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/round_robin.rs" pluginRoundRobin [
      {
        label = "commanded switch validation";
        needle = "pub const fn validate_commanded_switch";
      }
      {
        label = "commanded switch application";
        needle = "pub fn force_commanded_switch";
      }
      {
        label = "wrong-current protection";
        needle = "WrongCurrentVcpu";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi.rs" pluginAbi [
      {
        label = "preemption resolver";
        needle = "pub fn resolve_qemu_inject_preemption_symbol";
      }
      {
        label = "preemption install scaffold";
        needle = "pub fn install_required_preemption_scaffold";
      }
      {
        label = "preemption install from qemu info";
        needle = "pub fn install_required_preemption_scaffold_from_qemu_info";
      }
      {
        label = "ABI preemption capability error";
        needle = "PreemptionInjectionCapability";
      }
      {
        label = "state partition stores preemption injector";
        needle = "preemption_injector";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/abi/tests.rs" pluginAbiTests [
      {
        label = "ABI preemption capability test";
        needle = "abi_install_requires_preemption_injection_symbol";
      }
    ]
    ++ failuresFor "crates/crucible-qemu-plugin/src/inertness.rs" pluginInertness [
      {
        label = "preemption capability included in inertness";
        needle = "preemption_injections";
      }
    ]
    ++ failuresFor "tests/crucible/default.nix" defaultChecks [
      {
        label = "phase2 exposes plugin preemption check";
        needle = "qemuPluginPreemption = import ./phase2-plugin-preemption.nix";
      }
    ];
in
  if failures != []
  then throw "crucible phase2 plugin preemption check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-plugin-preemption";
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
          name = "run-plugin-preemption";
          script = ''
            set -eu
            if [ -d source ] && [ -f source/crates/Cargo.toml ]; then
              cd source
            fi

            target_dir="$TMPDIR/crucible-plugin-preemption-target"
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
              preemption::tests::preemption_injector_requires_qemu_capability_and_valid_window \
              preemption::tests::preemption_injector_requires_qemu_capability_and_valid_window
            run_exact_test \
              preemption::tests::preemption_injector_dispatches_vcpu_switch_at_commanded_icount \
              preemption::tests::preemption_injector_dispatches_vcpu_switch_at_commanded_icount
            run_exact_test \
              preemption::tests::preemption_injector_dispatches_interrupt_without_round_robin_switch \
              preemption::tests::preemption_injector_dispatches_interrupt_without_round_robin_switch
            run_exact_test \
              preemption::tests::preemption_injector_rejects_out_of_window_without_clamping_or_calling_qemu \
              preemption::tests::preemption_injector_rejects_out_of_window_without_clamping_or_calling_qemu
            run_exact_test \
              preemption::tests::preemption_injector_localizes_malformed_or_rejected_commands \
              preemption::tests::preemption_injector_localizes_malformed_or_rejected_commands
            run_exact_test \
              preemption::tests::deterministic_ipi_delivery_uses_fixed_latency_and_next_rr_switch \
              preemption::tests::deterministic_ipi_delivery_uses_fixed_latency_and_next_rr_switch
            run_exact_test \
              preemption::tests::deterministic_ipi_delivery_rejects_bad_vcpu_pairs_and_overflow \
              preemption::tests::deterministic_ipi_delivery_rejects_bad_vcpu_pairs_and_overflow
            run_exact_test \
              abi::tests::capabilities::abi_install_requires_preemption_injection_symbol \
              abi::tests::capabilities::abi_install_requires_preemption_injection_symbol
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
            gate=gate:layer0-determinism
            preemption_capability=qemu_plugin_inject_preemption
            command_window=[deadline,ceiling]
            out_of_window_policy=fail-loud-no-clamp-no-defer
            dispatch=vCPU-switch-or-interrupt-at-commanded-icount
            deterministic_ipi_delivery=sender-icount-plus-fixed-latency-next-rr-switch
            ipi_latency_model=fixed-node-icount
            ipi_delivery_path=preemption-injector-commanded-icount
            ipi_realtime_delivery=false
            RESULT
          '';
        }
      ];
    }
