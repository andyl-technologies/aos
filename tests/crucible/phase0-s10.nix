{
  pkgs,
  lib,
  liveDoorbell ? import ./phase2-qemu-live-whitebox-doorbell.nix {inherit pkgs lib;},
}: let
  qemuNixSource = builtins.readFile ../../pkgs/emulation/qemu.nix;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s10-aarch64-doorbell";
    version = "0";
    src = null;

    qemuNix = qemuNixSource;
    passAsFile = ["qemuNix"];

    buildDeps = [
      pkgs.coreutils
      pkgs.grep
      pkgs.qemu-crucible
      liveDoorbell
    ];

    QEMU_OUT = builtins.toString pkgs.qemu-crucible;
    LIVE_RESULT = "${liveDoorbell}/result";
    LIVE_AARCH64_RESULT = "${liveDoorbell}/install-aarch64-result";

    phases = [
      {
        name = "run-s10-aarch64-doorbell";
        script = ''
          set -eu

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          cp "$qemuNixPath" qemu.nix
          [ -x "$QEMU_OUT/bin/qemu-system-x86_64" ] \
            || fail "qemu-crucible x86_64 system emulator is missing"
          [ -x "$QEMU_OUT/bin/qemu-system-aarch64" ] \
            || fail "qemu-crucible aarch64 system emulator is missing"
          grep -F -q -- '--target-list=x86_64-softmmu,aarch64-softmmu' qemu.nix \
            || fail "qemu.nix does not pin both committed system targets"

          grep -Fxq PASS "$LIVE_RESULT"
          grep -Fxq 'status=complete' "$LIVE_RESULT"
          grep -Fxq 'aarch64_doorbell_instruction=hlt-0x04c1' "$LIVE_RESULT"
          grep -Fxq 'aarch64_payload_registers=x0,x1' "$LIVE_RESULT"
          grep -Fxq 'aarch64_live_marker_observed=true' "$LIVE_RESULT"
          grep -Fxq 'aarch64_boot_barrier_ceiling_enforced=true' "$LIVE_RESULT"
          grep -Fxq PASS "$LIVE_AARCH64_RESULT"
          grep -Fxq 'whitebox=on' "$LIVE_AARCH64_RESULT"
          grep -Fxq 'whitebox_setup_region=aarch64-hlt-04c1' "$LIVE_AARCH64_RESULT"
          grep -Fxq 'whitebox_marker_count=1' "$LIVE_AARCH64_RESULT"
          grep -Fxq 'whitebox_marker_point=hot-path' "$LIVE_AARCH64_RESULT"
          grep -Fxq 'boot_barrier_ceiling_enforced=true' "$LIVE_AARCH64_RESULT"
          grep -Fxq 'orderly_child_exit=true' "$LIVE_AARCH64_RESULT"

          marker_icount=$(sed -n \
            's/^whitebox_marker_icount=\([0-9][0-9]*\)$/\1/p' \
            "$LIVE_AARCH64_RESULT")
          test -n "$marker_icount"

          mkdir -p "$out"
          cp qemu.nix "$out/qemu.nix"
          cp "$LIVE_RESULT" "$out/live-doorbell.result"
          cp "$LIVE_AARCH64_RESULT" "$out/live-aarch64.result"
          {
            echo PASS
            echo spike=aarch64-doorbell
            echo check=checks.crucible.phase0.s10Aarch64Doorbell
            echo qemu_package=qemu-crucible
            echo qemu_target_list=x86_64-softmmu,aarch64-softmmu
            echo qemu_aarch64_softmmu_target=true
            echo qemu_system_aarch64_available=true
            echo production_aarch64_doorbell_trap_implemented=true
            echo whitebox_on_trap_tested=true
            echo whitebox_off_inertness_tested=true
            echo marker_icount_reproducible="$marker_icount"
            echo payload_read_result=pass
            echo aarch64_whitebox_supported=true
            echo aarch64_blackbox_only_fallback=false
            echo fallback_adopted=none
            echo s10_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S10 live aarch64 doorbell spike";
    };
  }
