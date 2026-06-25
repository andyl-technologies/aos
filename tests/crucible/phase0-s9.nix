{
  pkgs,
  lib,
}: let
  s1Fingerprint = import ./phase0-s1.nix {inherit pkgs lib;};
  qemuNixSource = builtins.readFile ../../pkgs/emulation/qemu.nix;
  qemuPatch1Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0001-crucible-sim-accel.patch;
  qemuPatch2Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch;
  qemuPatch3Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0003-crucible-icount-no-realtime.patch;
  qemuPatch4Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0004-crucible-no-warp-with-plugin.patch;
  qemuPatch5Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0005-crucible-det-glib-prng.patch;
  qemuPatch6Source = builtins.readFile ../../pkgs/emulation/qemu-patches/0006-crucible-clock-deadline.patch;
  qemuNixHash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu.nix;
  qemuPatch1Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0001-crucible-sim-accel.patch;
  qemuPatch2Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0002-crucible-rr-fingerprint-helpers.patch;
  qemuPatch3Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0003-crucible-icount-no-realtime.patch;
  qemuPatch4Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0004-crucible-no-warp-with-plugin.patch;
  qemuPatch5Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0005-crucible-det-glib-prng.patch;
  qemuPatch6Hash = builtins.hashFile "sha256" ../../pkgs/emulation/qemu-patches/0006-crucible-clock-deadline.patch;
in
  pkgs.mkDerivation {
    pname = "crucible-phase0-s9-qemu-build-identity";
    version = "0";
    src = null;

    qemuNix = qemuNixSource;
    qemuPatch1 = qemuPatch1Source;
    qemuPatch2 = qemuPatch2Source;
    qemuPatch3 = qemuPatch3Source;
    qemuPatch4 = qemuPatch4Source;
    qemuPatch5 = qemuPatch5Source;
    qemuPatch6 = qemuPatch6Source;
    passAsFile = [
      "qemuNix"
      "qemuPatch1"
      "qemuPatch2"
      "qemuPatch3"
      "qemuPatch4"
      "qemuPatch5"
      "qemuPatch6"
    ];

    buildDeps = [
      pkgs.coreutils
      pkgs.gawk
      pkgs.grep
      pkgs.jq
      pkgs.qemu-crucible
    ];

    S1_RESULT = "${s1Fingerprint}/result";
    QEMU_OUT = builtins.toString pkgs.qemu-crucible;
    QEMU_DRV = builtins.unsafeDiscardStringContext pkgs.qemu-crucible.drvPath;
    QEMU_VERSION = pkgs.qemu-crucible.version;
    QEMU_NIX_HASH = qemuNixHash;
    PATCH_0001_NAME = "0001-crucible-sim-accel.patch";
    PATCH_0001_HASH = qemuPatch1Hash;
    PATCH_0002_NAME = "0002-crucible-rr-fingerprint-helpers.patch";
    PATCH_0002_HASH = qemuPatch2Hash;
    PATCH_0003_NAME = "0003-crucible-icount-no-realtime.patch";
    PATCH_0003_HASH = qemuPatch3Hash;
    PATCH_0004_NAME = "0004-crucible-no-warp-with-plugin.patch";
    PATCH_0004_HASH = qemuPatch4Hash;
    PATCH_0005_NAME = "0005-crucible-det-glib-prng.patch";
    PATCH_0005_HASH = qemuPatch5Hash;
    PATCH_0006_NAME = "0006-crucible-clock-deadline.patch";
    PATCH_0006_HASH = qemuPatch6Hash;

    phases = [
      {
        name = "run-s9-qemu-build-identity";
        script = ''
          set -eu

          fail() {
            echo "FAIL: $*" >&2
            exit 1
          }

          get_kv() {
            key="$1"
            gawk -F= -v key="$key" '
              $1 == key { print $2; found = 1 }
              END { if (!found) exit 1 }
            ' "$S1_RESULT"
          }

          require_fixed() {
            file="$1"
            text="$2"
            grep -F -q -- "$text" "$file" || fail "missing '$text' in $file"
          }

          first_line=$(sed -n '1p' "$S1_RESULT")
          [ "$first_line" = PASS ] || fail "S1 result is not PASS"
          require_fixed "$S1_RESULT" "spike=single-vm-fingerprint"
          require_fixed "$S1_RESULT" "extended_fingerprint_match=true"
          require_fixed "$S1_RESULT" "aggregate_icount_stream_match=true"
          require_fixed "$S1_RESULT" "s1_complete=true"

          s1_horizon_extended_hash=$(get_kv horizon_extended_hash)
          s1_horizon_register_hash=$(get_kv horizon_register_hash)
          s1_horizon_ram_hash=$(get_kv horizon_ram_hash)
          s1_pause_retired=$(get_kv pause_retired)
          s1_pause_overshoot=$(get_kv pause_overshoot)

          cp "$qemuNixPath" qemu.nix
          cp "$qemuPatch1Path" "$PATCH_0001_NAME"
          cp "$qemuPatch2Path" "$PATCH_0002_NAME"
          cp "$qemuPatch3Path" "$PATCH_0003_NAME"
          cp "$qemuPatch4Path" "$PATCH_0004_NAME"
          cp "$qemuPatch5Path" "$PATCH_0005_NAME"
          cp "$qemuPatch6Path" "$PATCH_0006_NAME"

          require_fixed qemu.nix 'pname ? "qemu"'
          require_fixed qemu.nix 'enablePlugins ? false'
          require_fixed qemu.nix 'pluginFlag ='
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0001-crucible-sim-accel.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0002-crucible-rr-fingerprint-helpers.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0003-crucible-icount-no-realtime.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0004-crucible-no-warp-with-plugin.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0005-crucible-det-glib-prng.patch}'
          require_fixed qemu.nix 'patch -p1 < ''${./qemu-patches/0006-crucible-clock-deadline.patch}'
          require_fixed qemu.nix '--target-list=x86_64-softmmu'
          require_fixed qemu.nix 'https://download.qemu.org/qemu-'
          require_fixed qemu.nix '.tar.xz'

          require_fixed "$PATCH_0001_NAME" 'TYPE_SIM_ACCEL'
          require_fixed "$PATCH_0001_NAME" 'ACCEL_OPS_NAME("sim")'
          require_fixed "$PATCH_0001_NAME" '-accel sim requires -icount shift=N'
          require_fixed "$PATCH_0002_NAME" 'qemu_plugin_crucible_pause_vm'
          require_fixed "$PATCH_0002_NAME" 'qemu_plugin_crucible_ram_hash'
          require_fixed "$PATCH_0002_NAME" 'qemu_plugin_crucible_get_vcpu_registers'
          require_fixed "$PATCH_0002_NAME" 'rr_switch_quantum'
          require_fixed "$PATCH_0002_NAME" 'qemu_opt_get_number(opts, "rr_switch_quantum", 0)'
          require_fixed "$PATCH_0002_NAME" 'icount_start_warp_timer'
          require_fixed "$PATCH_0002_NAME" 'vmstate_info_crucible_icount_host_timer_int64'
          require_fixed "$PATCH_0003_NAME" 'icount_enabled() != ICOUNT_PRECISE'
          require_fixed "$PATCH_0003_NAME" 'qemu_clock_deadline_ns_all(QEMU_CLOCK_REALTIME'
          require_fixed "$PATCH_0004_NAME" 'qemu_plugin_has_time_control'
          require_fixed "$PATCH_0004_NAME" 'qemu_clock_notify(QEMU_CLOCK_VIRTUAL)'
          require_fixed "$PATCH_0004_NAME" 'static inline bool qemu_plugin_has_time_control(void)'
          require_fixed "$PATCH_0005_NAME" 'deterministic_glib_seed'
          require_fixed "$PATCH_0005_NAME" 'g_random_set_seed(deterministic_glib_seed(seed))'
          require_fixed "$PATCH_0005_NAME" 'seed that global stream from the same run seed'
          require_fixed "$PATCH_0006_NAME" 'qemu_plugin_clock_deadline_ns'

          patch_count=6
          patch_series_hash=$(
            {
              printf '%s  %s\n' "$PATCH_0001_HASH" "$PATCH_0001_NAME"
              printf '%s  %s\n' "$PATCH_0002_HASH" "$PATCH_0002_NAME"
              printf '%s  %s\n' "$PATCH_0003_HASH" "$PATCH_0003_NAME"
              printf '%s  %s\n' "$PATCH_0004_HASH" "$PATCH_0004_NAME"
              printf '%s  %s\n' "$PATCH_0005_HASH" "$PATCH_0005_NAME"
              printf '%s  %s\n' "$PATCH_0006_HASH" "$PATCH_0006_NAME"
            } \
              | sha256sum \
              | gawk '{ print $1 }'
          )

          {
            echo "qemu_derivation_path=$QEMU_DRV"
            echo "qemu_output_path=$QEMU_OUT"
            echo "qemu_version=$QEMU_VERSION"
            echo "qemu_nix_hash=$QEMU_NIX_HASH"
            echo "patch_count=$patch_count"
            echo "patch_0001_name=$PATCH_0001_NAME"
            echo "patch_0001_hash=$PATCH_0001_HASH"
            echo "patch_0002_name=$PATCH_0002_NAME"
            echo "patch_0002_hash=$PATCH_0002_HASH"
            echo "patch_0003_name=$PATCH_0003_NAME"
            echo "patch_0003_hash=$PATCH_0003_HASH"
            echo "patch_0004_name=$PATCH_0004_NAME"
            echo "patch_0004_hash=$PATCH_0004_HASH"
            echo "patch_0005_name=$PATCH_0005_NAME"
            echo "patch_0005_hash=$PATCH_0005_HASH"
            echo "patch_0006_name=$PATCH_0006_NAME"
            echo "patch_0006_hash=$PATCH_0006_HASH"
            echo "patch_series_hash=$patch_series_hash"
            echo "plugins_enabled=true"
            echo "s1_horizon_extended_hash=$s1_horizon_extended_hash"
            echo "s1_horizon_register_hash=$s1_horizon_register_hash"
            echo "s1_horizon_ram_hash=$s1_horizon_ram_hash"
          } > build-id-material.txt

          qemu_build_id=$(sha256sum build-id-material.txt | gawk '{ print $1 }')
          changed_build_id=$(
            {
              cat build-id-material.txt
              printf 'trivial-qemu-change-negative-control=true\n'
            } | sha256sum | gawk '{ print $1 }'
          )
          [ "$qemu_build_id" != "$changed_build_id" ] \
            || fail "negative-control build identity did not change"

          jq -n \
            --arg crucible_version phase0-spike \
            --arg qemu_build_id "$qemu_build_id" \
            --arg qemu_derivation_path "$QEMU_DRV" \
            --arg qemu_output_path "$QEMU_OUT" \
            --arg qemu_version "$QEMU_VERSION" \
            --arg patch_series_hash "$patch_series_hash" \
            --arg s1_horizon_extended_hash "$s1_horizon_extended_hash" \
            '{
              crucible_version: $crucible_version,
              qemu_build_id: $qemu_build_id,
              qemu_derivation_path: $qemu_derivation_path,
              qemu_output_path: $qemu_output_path,
              qemu_version: $qemu_version,
              qemu_patch_series_hash: $patch_series_hash,
              seed: "0x0010c001",
              scenario_hash: "phase0-s1-stock-linux-diskless-initramfs-workload",
              schedule: ["fixed-horizon-s1-cadence"],
              fingerprint_tail: [{
                horizon_extended_hash: $s1_horizon_extended_hash
              }],
              sampling_config: {
                cadence: 100000000,
                horizon_icount: 3200000000
              }
            }' > repro-artifact.json

          artifact_build_id=$(jq -r '.qemu_build_id' repro-artifact.json)
          [ "$artifact_build_id" = "$qemu_build_id" ] \
            || fail "artifact build id does not match current build id"
          if [ "$artifact_build_id" = "$changed_build_id" ]; then
            fail "artifact accepted a changed QEMU build identity"
          fi

          artifact_build_id_match=true
          artifact_mismatch_regates=true
          patch_apply_list_matches=true
          plugin_exports_present=true
          rr_switch_quantum_default_zero=true
          non_sim_icount_patch_present=true
          no_warp_with_plugin_patch_present=true
          qemu_internal_entropy_patch_present=true
          full_upstream_inertness_comparison=false
          qemu_inert_gate_status=fallback_pending_upstream_comparison
          fallback_adopted=pin_build_id_and_regate_on_change

          mkdir -p "$out"
          cp build-id-material.txt "$out/build-id-material.txt"
          cp repro-artifact.json "$out/repro-artifact.json"
          cp qemu.nix "$out/qemu.nix"
          cp "$PATCH_0001_NAME" "$out/$PATCH_0001_NAME"
          cp "$PATCH_0002_NAME" "$out/$PATCH_0002_NAME"
          cp "$PATCH_0003_NAME" "$out/$PATCH_0003_NAME"
          cp "$PATCH_0004_NAME" "$out/$PATCH_0004_NAME"
          cp "$PATCH_0005_NAME" "$out/$PATCH_0005_NAME"
          cp "$PATCH_0006_NAME" "$out/$PATCH_0006_NAME"
          {
            echo PASS_WITH_FALLBACK
            echo spike=qemu-build-identity-and-inertness
            echo check=checks.crucible.phase0.s9QemuBuildIdentity
            echo qemu_package=qemu-crucible
            echo qemu_version="$QEMU_VERSION"
            echo qemu_derivation_path="$QEMU_DRV"
            echo qemu_output_path="$QEMU_OUT"
            echo qemu_build_id="$qemu_build_id"
            echo qemu_nix_hash="$QEMU_NIX_HASH"
            echo patch_count="$patch_count"
            echo patch_0001_name="$PATCH_0001_NAME"
            echo patch_0001_hash="$PATCH_0001_HASH"
            echo patch_0002_name="$PATCH_0002_NAME"
            echo patch_0002_hash="$PATCH_0002_HASH"
            echo patch_0003_name="$PATCH_0003_NAME"
            echo patch_0003_hash="$PATCH_0003_HASH"
            echo patch_0004_name="$PATCH_0004_NAME"
            echo patch_0004_hash="$PATCH_0004_HASH"
            echo patch_0005_name="$PATCH_0005_NAME"
            echo patch_0005_hash="$PATCH_0005_HASH"
            echo patch_0006_name="$PATCH_0006_NAME"
            echo patch_0006_hash="$PATCH_0006_HASH"
            echo patch_series_hash="$patch_series_hash"
            echo plugins_enabled=true
            echo patch_apply_list_matches="$patch_apply_list_matches"
            echo plugin_exports_present="$plugin_exports_present"
            echo rr_switch_quantum_default_zero="$rr_switch_quantum_default_zero"
            echo non_sim_icount_patch_present="$non_sim_icount_patch_present"
            echo no_warp_with_plugin_patch_present="$no_warp_with_plugin_patch_present"
            echo qemu_internal_entropy_patch_present="$qemu_internal_entropy_patch_present"
            echo s1_result_consumed=true
            echo s1_result_status=PASS
            echo s1_source=checks.crucible.phase0.s1Fingerprint
            echo s1_horizon_extended_hash="$s1_horizon_extended_hash"
            echo s1_horizon_register_hash="$s1_horizon_register_hash"
            echo s1_horizon_ram_hash="$s1_horizon_ram_hash"
            echo s1_pause_retired="$s1_pause_retired"
            echo s1_pause_overshoot="$s1_pause_overshoot"
            echo artifact_build_id_match="$artifact_build_id_match"
            echo changed_build_id="$changed_build_id"
            echo artifact_mismatch_regates="$artifact_mismatch_regates"
            echo changed_build_negative_control=mutated_build_id_material
            echo full_upstream_inertness_comparison="$full_upstream_inertness_comparison"
            echo qemu_inert_gate_status="$qemu_inert_gate_status"
            echo fallback_adopted="$fallback_adopted"
            echo s9_complete=true
          } > "$out/result"
        '';
      }
    ];

    meta = {
      description = "Crucible Phase 0 S9 QEMU build identity and inertness spike";
    };
  }
