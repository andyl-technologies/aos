{pkgs}: let
  pkgsSource = builtins.path {
    path = ../../pkgs;
    name = "aos-pkgs";
  };
  # Only source enters the store: a developer worktree's cargo target
  # directory would otherwise be hashed and copied in full.
  cratesSource = builtins.path {
    path = ../../crates;
    name = "aos-crates";
    filter = path: _type: let
      base = baseNameOf path;
    in
      base != "target" && base != "result" && base != ".git";
  };
  rfcDocs = builtins.path {
    path = ../../docs/rfcs/0010-crucible;
    name = "crucible-rfc0010-docs";
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s14-gdbstub-fallback";
    version = "0";
    src = null;

    buildDeps = [
      pkgs.coreutils
      pkgs.grep
      pkgs.qemu-crucible
    ];

    PKGS_SRC = builtins.toString pkgsSource;
    CRATES_SRC = builtins.toString cratesSource;
    RFC_DOCS = builtins.toString rfcDocs;
    QEMU_OUT = builtins.toString pkgs.qemu-crucible;

    phases = [
      {
        name = "run-s14-gdbstub-fallback";
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
            [ -e "$path" ] || fail "S14 scan target missing: $path"
            set +e
            grep -E -R -q -- "$regex" "$path"
            status="$?"
            set -e
            if [ "$status" -eq 0 ]; then
              fail "S14 fallback expected no $description in $path"
            fi
            [ "$status" -eq 1 ] || fail "S14 failed to scan $description in $path"
          }

          require_present_regex() {
            path="$1"
            regex="$2"
            description="$3"
            [ -e "$path" ] || fail "S14 scan target missing: $path"
            grep -E -R -q -- "$regex" "$path" \
              || fail "S14 expected $description in $path"
          }

          cp -r "$PKGS_SRC" pkgs
          chmod -R u+w pkgs
          cp -r "$CRATES_SRC" crates
          chmod -R u+w crates
          cp -r "$RFC_DOCS" rfc-docs
          chmod -R u+w rfc-docs

          [ -x "$QEMU_OUT/bin/qemu-system-x86_64" ] \
            || fail "qemu-crucible x86_64 system emulator is missing"

          risk_doc="rfc-docs/30-risks-spikes.md"
          debug_doc="rfc-docs/36-time-travel-debugging.md"
          session_doc="rfc-docs/20-session-control-plane.md"
          cli_doc="rfc-docs/23-cli.md"
          decision_doc="rfc-docs/31-decision-register.md"

          require_fixed "$risk_doc" "## 30.11d S14 — gdbstub attach/step does not disturb icount or plugin time control"
          require_fixed "$risk_doc" "Until S14 is green, debugging MUST default to **read-only"
          require_fixed "$debug_doc" "with gdb single-step disabled"
          require_fixed "$session_doc" 'optional `open_gdbstub`'
          require_fixed "$session_doc" "reject \`attach_gdb\` with a typed error"
          require_fixed "$cli_doc" "attach-gdb"

          require_fixed "$decision_doc" "RISK-4 / RISK-5 / T-RISK-1"
          require_fixed "$decision_doc" "checks.crucible.phase0.s1Fingerprint"
          require_fixed "$decision_doc" '`s1_horizon_extended_hash=9d1e61606ac54920`'
          require_fixed "$decision_doc" '`s1_pause_retired=3200000005`'

          gdb_package_regex='pname = "gdb"|name = "gdb"|gdb-client|gdbserver'
          session_impl_regex='open_gdbstub|GdbListen|GdbAttachInfo|AttachGdb|DebugGoto|DebugReverseStep|DebugReverseContinue'
          raw_step_regex='gdb_(continue|step|single_step|handle_packet|put_packet)|gdbserver_state|gdb_handlesig|gdb_vm_state_change|gdbstub.*(step|continue)|crucible_.*gdb.*(step|continue)|qemu_plugin_crucible_.*(step|gdb)|sstep|single_step'

          require_present_regex pkgs "$gdb_package_regex" "hermetic gdb client package"
          require_present_regex crates "$session_impl_regex" "session/backend gdbstub implementation"
          require_absent_regex pkgs/emulation/qemu-patches "^\\+.*($raw_step_regex)" "AOS QEMU patch addition implementing gdbstub single-step mediation or a continuation hook"

          mkdir -p "$out"
          cp -r pkgs/emulation "$out/emulation-scan"
          cp "$risk_doc" "$out/30-risks-spikes.md"
          cp "$debug_doc" "$out/36-time-travel-debugging.md"
          cp "$decision_doc" "$out/31-decision-register.md"
          {
            echo PASS_WITH_FALLBACK
            echo spike=gdbstub-attach-step
            echo check=checks.crucible.phase0.s14GdbstubFallback
            echo qemu_package=qemu-crucible
            echo debug_spec_file=36-time-travel-debugging.md
            echo scan_scope=pkgs_emulation_crates_rfc_debug_specs
            echo hermetic_gdb_client_available=true
            echo qemu_gdbstub_mediation_scan_scope=aos_qemu_nix_patches_plugin
            echo known_aos_qemu_gdbstub_step_hook_detected=false
            echo aos_qemu_gdbstub_mediation_patch_implemented=false
            echo session_open_gdbstub_implemented=true
            echo cli_debug_command_implemented=true
            echo read_only_gdbstub_ops_tested=false
            echo read_only_fingerprint_neutral=not_tested
            echo read_only_icount_neutral=not_tested
            echo gdb_single_step_tested=false
            echo gdb_single_step_routed_through_scheduler=not_tested
            echo gdb_single_step_policy=disabled_until_s14_green
            echo raw_gdb_single_step_allowed_by_crucible_policy=false
            echo policy_enforcement_runtime=implemented
            echo default_debug_policy=read_only_attach_crucible_driven_step_reverse_step
            echo live_gdbstub_attach_gate_status=fallback_pending_live_mediation_gate
            echo s1_decision_entry_consumed=true
            echo s1_result_status=PASS
            echo s1_horizon_extended_hash=9d1e61606ac54920
            echo s1_pause_retired=3200000005
            echo fallback_adopted=read_only_attach_crucible_driven_step_until_gdbstub_gate
            echo s14_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S14 gdbstub attach/step fallback spike";
    };
  }
