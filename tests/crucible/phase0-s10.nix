{pkgs}: let
  qemuNixSource = builtins.readFile ../../pkgs/emulation/qemu.nix;
  cratesManifestSource = builtins.readFile ../../crates/Cargo.toml;
  pluginSource = builtins.readFile ../../pkgs/emulation/crucible-qemu-trace-plugin.c;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s10-aarch64-doorbell";
    version = "0";
    src = null;

    qemuNix = qemuNixSource;
    cratesManifest = cratesManifestSource;
    plugin = pluginSource;
    passAsFile = [
      "qemuNix"
      "cratesManifest"
      "plugin"
    ];

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.grep
      pkgs.qemu-crucible
    ];

    QEMU_OUT = builtins.toString pkgs.qemu-crucible;

    phases = [
      {
        name = "run-s10-aarch64-doorbell-preflight";
        script = ''
          set -eu

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          cp "$qemuNixPath" qemu.nix
          cp "$cratesManifestPath" Cargo.toml
          cp "$pluginPath" crucible-qemu-trace-plugin.c

          [ -x "$QEMU_OUT/bin/qemu-system-x86_64" ] \
            || fail "qemu-crucible x86_64 system emulator is missing"
          if [ -e "$QEMU_OUT/bin/qemu-system-aarch64" ]; then
            fail "S10 fallback expected qemu-system-aarch64 to be absent"
          fi

          grep -F -q -- '--target-list=x86_64-softmmu' qemu.nix \
            || fail "qemu.nix no longer pins x86_64-softmmu"
          if grep -F -q -- 'aarch64-softmmu' qemu.nix; then
            fail "S10 fallback expected qemu.nix to omit aarch64-softmmu"
          fi

          # The white-box guest emitter has landed since the original spike
          # run: it is a workspace member and encodes the aarch64 doorbell
          # instruction ABI. The aarch64 fallback now rests solely on the
          # missing aarch64 QEMU target and doorbell trap.
          grep -F -q -- 'crucible-guest' Cargo.toml \
            || fail "S10 expected the crucible-guest workspace member"
          if grep -E -q 'whitebox|doorbell|aarch64|BRK|HLT|hvc' crucible-qemu-trace-plugin.c; then
            fail "S10 fallback expected production trace plugin to omit aarch64 doorbell handling"
          fi

          qemu_aarch64_softmmu_target=false
          qemu_system_aarch64_available=false
          crucible_guest_workspace_member=true
          production_aarch64_doorbell_trap_implemented=false
          whitebox_on_trap_tested=false
          whitebox_off_inertness_tested=false
          marker_icount_reproducible=not_tested
          payload_read_result=not_tested
          aarch64_whitebox_supported=false
          aarch64_blackbox_only_fallback=true
          fallback_adopted=aarch64_black_box_only_until_qemu_target_and_doorbell

          mkdir -p "$out"
          cp qemu.nix "$out/qemu.nix"
          cp Cargo.toml "$out/Cargo.toml"
          cp crucible-qemu-trace-plugin.c "$out/crucible-qemu-trace-plugin.c"
          {
            echo PASS_WITH_FALLBACK
            echo spike=aarch64-doorbell
            echo check=checks.crucible.phase0.s10Aarch64Doorbell
            echo qemu_package=qemu-crucible
            echo qemu_target_list=x86_64-softmmu
            echo qemu_aarch64_softmmu_target="$qemu_aarch64_softmmu_target"
            echo qemu_system_aarch64_available="$qemu_system_aarch64_available"
            echo crucible_guest_workspace_member="$crucible_guest_workspace_member"
            echo production_aarch64_doorbell_trap_implemented="$production_aarch64_doorbell_trap_implemented"
            echo whitebox_on_trap_tested="$whitebox_on_trap_tested"
            echo whitebox_off_inertness_tested="$whitebox_off_inertness_tested"
            echo marker_icount_reproducible="$marker_icount_reproducible"
            echo payload_read_result="$payload_read_result"
            echo aarch64_whitebox_supported="$aarch64_whitebox_supported"
            echo aarch64_blackbox_only_fallback="$aarch64_blackbox_only_fallback"
            echo fallback_adopted="$fallback_adopted"
            echo s10_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S10 aarch64 doorbell spike";
    };
  }
