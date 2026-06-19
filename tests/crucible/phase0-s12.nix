{pkgs}: let
  qemuNixSource = builtins.readFile ../../pkgs/emulation/qemu.nix;
  pluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
  qemuPatchDir = builtins.path {
    path = ../../pkgs/emulation/qemu-patches;
    name = "qemu-crucible-patches";
  };
  cratesSource = builtins.path {
    path = ../../crates;
    name = "aos-crates";
  };
  rfcDocs = builtins.path {
    path = ../../docs/rfcs/0010-crucible;
    name = "crucible-rfc0010-docs";
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s12-preemption-decision";
    version = "0";
    src = null;

    qemuNix = qemuNixSource;
    plugin = pluginSource;
    passAsFile = [
      "qemuNix"
      "plugin"
    ];

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.grep
      pkgs.qemu-crucible
    ];

    QEMU_OUT = builtins.toString pkgs.qemu-crucible;
    QEMU_PATCH_DIR = builtins.toString qemuPatchDir;
    CRATES_SRC = builtins.toString cratesSource;
    RFC_DOCS = builtins.toString rfcDocs;

    phases = [
      {
        name = "run-s12-preemption-decision-fallback";
        script = ''
          set -eu

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          require_fixed() {
            file="$1"
            text="$2"
            grep -F -q -- "$text" "$file" || fail "missing '$text' in $file"
          }

          require_absent_regex() {
            path="$1"
            regex="$2"
            description="$3"
            [ -e "$path" ] || fail "S12 scan target missing: $path"
            set +e
            grep -E -R -q -- "$regex" "$path"
            status="$?"
            set -e
            if [ "$status" -eq 0 ]; then
              fail "S12 fallback expected no $description in $path"
            fi
            [ "$status" -eq 1 ] || fail "S12 failed to scan $description in $path"
          }

          cp "$qemuNixPath" qemu.nix
          cp -r "$QEMU_PATCH_DIR" qemu-patches
          chmod -R u+w qemu-patches
          cp -r "$CRATES_SRC" crates
          chmod -R u+w crates
          cp -r "$RFC_DOCS" rfc-docs
          chmod -R u+w rfc-docs
          cp "$pluginPath" crucible-qemu-trace-plugin.c

          [ -x "$QEMU_OUT/bin/qemu-system-x86_64" ] \
            || fail "qemu-crucible x86_64 system emulator is missing"
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0001-add-crucible-rr-fingerprint-helpers.patch}'
          require_fixed qemu-patches/0001-add-crucible-rr-fingerprint-helpers.patch 'qemu_plugin_crucible_rr_switch_quantum'
          require_fixed qemu-patches/0001-add-crucible-rr-fingerprint-helpers.patch 'qemu_plugin_crucible_pause_vm'

          preemption_regex='preempt|preemption|interrupt_at|vcpu_switch|crucible_.*inject|qemu_plugin_crucible_.*(irq|interrupt)'
          require_absent_regex qemu.nix "$preemption_regex" "preemption-injection patch wiring"
          require_absent_regex qemu-patches "$preemption_regex" "preemption-injection API"
          require_absent_regex crucible-qemu-trace-plugin.c "$preemption_regex" "production preemption-injection path"
          require_absent_regex crates "$preemption_regex" "implemented preemption explorer"

          decision_doc="rfc-docs/31-decision-register.md"
          require_fixed "$decision_doc" "RISK-4 / RISK-5 / T-RISK-1"
          require_fixed "$decision_doc" "checks.crucible.phase0.s1Fingerprint"
          require_fixed "$decision_doc" "\`s1_horizon_extended_hash=9d1e61606ac54920\`"
          require_fixed "$decision_doc" "\`s1_pause_retired=3200000005\`"
          require_fixed "$decision_doc" "RISK-25 / T-RISK-17"
          require_fixed "$decision_doc" "checks.crucible.phase0.s11MultiVcpuFingerprint"
          require_fixed "$decision_doc" "\`s11_vcpus=4\`"
          require_fixed "$decision_doc" "\`s11_block_devices=0\`"
          require_fixed "$decision_doc" "\`s11_rr_switch_quantum=4096\`"
          require_fixed "$decision_doc" "\`s11_extended_fingerprint_match=true\`"
          require_fixed "$decision_doc" "\`s11_horizon_fingerprint_match=true\`"

          mkdir -p "$out"
          cp qemu.nix "$out/qemu.nix"
          cp -r qemu-patches "$out/qemu-patches"
          cp crucible-qemu-trace-plugin.c "$out/crucible-qemu-trace-plugin.c"
          cp "$decision_doc" "$out/31-decision-register.md"
          {
            echo PASS_WITH_FALLBACK
            echo spike=decision-preemption
            echo check=checks.crucible.phase0.s12PreemptionDecision
            echo qemu_package=qemu-crucible
            echo preemption_surface_scan_scope=qemu_nix_all_qemu_patches_trace_plugin_crates
            echo known_preemption_injection_surface_found=false
            echo preemption_injection_api_available=not_detected
            echo preemption_patch_present=not_detected
            echo plugin_preemption_surface_present=not_detected
            echo vcpu_switch_injection_tested=false
            echo interrupt_timing_injection_tested=false
            echo commanded_preemption_choices_tested=0
            echo commanded_preemption_reproducible=not_tested
            echo commanded_preemption_discriminating=not_tested
            echo known_race_manifested_under_one_choice=not_tested
            echo known_race_absent_under_another_choice=not_tested
            echo single_vcpu_interrupt_variation_distinct=not_tested
            echo default_determinism_prereqs_green=true
            echo default_determinism_prereqs_source=decision_register_s1_s11
            echo s1_decision_entry_consumed=true
            echo s1_result_status=PASS
            echo s1_horizon_extended_hash=9d1e61606ac54920
            echo s1_pause_retired=3200000005
            echo s11_decision_entry_consumed=true
            echo s11_result_status=PASS
            echo s11_vcpus=4
            echo s11_block_devices=0
            echo s11_rr_switch_quantum=4096
            echo s11_extended_fingerprint_match=true
            echo s11_horizon_fingerprint_match=true
            echo s11_final_extended_hash=16e7a49bfce0eb0f
            echo decision_preemption_exploration_enabled=false
            echo fallback_adopted=default_deterministic_interleaving_only_until_preemption_injection
            echo s12_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S12 Decision::Preemption fallback spike";
    };
  }
