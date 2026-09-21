{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase2.qemuLivePluginInstall",
  taskIds ? ["T-PLUG-3" "T-PLUG-16" "T-PLUG-17" "T-PLUG-18" "T-PLUG-19" "T-PROTO-6"],
  openTaskIds ? [],
  liveWhitebox ? import ./phase2-qemu-live-whitebox-doorbell.nix {inherit pkgs lib;},
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  taskList = builtins.concatStringsSep "," taskIds;
  openTaskList = builtins.concatStringsSep "," openTaskIds;
  runtimeInputs = [pkgs.coreutils pkgs.grep liveWhitebox];
  runtimeScript = ''
    set -eu
    cd "$TMPDIR"

    install_result=${liveWhitebox}/install-off-result
    grep -Fxq PASS "$install_result"
    grep -Fxq 'gate=gate:plugin-install-lifecycle' "$install_result"
    grep -Fxq 'plugin_loaded=rust-control-cdylib' "$install_result"
    grep -Fxq 'time_authority=rust-plugin' "$install_result"
    grep -Fxq 'setup_ack_ready=true' "$install_result"
    grep -Fxq 'handshake_slot=0' "$install_result"
    grep -Eq '^handshake_proto_version=[0-9]+$' "$install_result"
    grep -Eq '^handshake_abi_version=[0-9]+$' "$install_result"
    grep -Eq '^handshake_node_count=[1-9][0-9]*$' "$install_result"
    grep -Eq '^shmem_region_len=[1-9][0-9]*$' "$install_result"
    grep -Fxq 'boot_barrier_ceiling_enforced=true' "$install_result"
    grep -Eq '^completed_icount=[1-9][0-9]*$' "$install_result"
    grep -Eq '^execution_fingerprint=[0-9a-f]{64}$' "$install_result"
    grep -Fxq 'run_control_silent=true' "$install_result"
    grep -Fxq 'plugin_quit_consumed=true' "$install_result"
    grep -Fxq 'orderly_child_exit=true' "$install_result"
    grep -Fxq 'time_authority_is_rust_plugin=true' "$install_result"
    grep -Fxq 'whitebox=off' "$install_result"

    mkdir -p "$out"
    cp "$install_result" "$out/result"
    {
      printf 'attr_path=%s\n' '${attrPath}'
      printf 'task_ids=%s\n' '${taskList}'
      printf 'open_task_ids=%s\n' '${openTaskList}'
      printf 'scope=rust-plugin-install-lifecycle-live-not-fingerprint-migration\n'
      printf 'plugins_loaded=rust-control-plugin-only\n'
      printf 'time_authority=rust-plugin-sim-shmem-dispatch\n'
      printf 'host_resource_authority=cgroup-v2,project-quota,unprivileged-child\n'
      printf 'lifecycle=handshake-scmrights-shmem-setupack-bootbarrier-run-silent-quit-exit\n'
    } >> "$out/result"
  '';
  selectedFlight = liveWhitebox.passthru.flight;
  selectedGuest = liveWhitebox.passthru.guest;
  selectedRootImage = liveWhitebox.passthru.rootImage;
  selectedKernel = campaignComposition.system.config.system.build.kernel;
  selectedRuntimeInputs = [
    pkgs.coreutils
    pkgs.e2fsprogs
    pkgs.grep
    pkgs.util-linux
  ];
  selectedRuntimeScript = ''
    set -eu
    cd "$TMPDIR"

    for option in CFS_BANDWIDTH QUOTA QFMT_V2 QUOTACTL; do
      grep -Fxq "CONFIG_$option=y" ${selectedKernel}/boot/config-*
    done

    cleanup_attempt_mount() {
      ${pkgs.util-linux}/bin/umount /tmp/plugin-install-attempts \
        > /dev/null 2>&1 || true
    }
    trap cleanup_attempt_mount EXIT HUP INT TERM

    cgroup_root=/sys/fs/cgroup/crucible-phase9-plugin-install
    echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
    mkdir "$cgroup_root"
    echo '+cpu +memory +pids' > "$cgroup_root/cgroup.subtree_control"

    truncate -s 3G /tmp/plugin-install-attempts.img
    ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project \
      -E quotatype=prjquota /tmp/plugin-install-attempts.img
    mkdir /tmp/plugin-install-attempts
    ${pkgs.util-linux}/bin/mount -o loop,prjquota \
      /tmp/plugin-install-attempts.img /tmp/plugin-install-attempts
    mkdir -m 700 /tmp/plugin-install-attempts/run

    install_result="$TMPDIR/plugin-install.result"
    qemu_log="$TMPDIR/plugin-install.qemu.log"
    if ! CRUCIBLE_LIVE_PLUGIN_WHITEBOX=off \
      CRUCIBLE_LIVE_PLUGIN_FINGERPRINT=on \
      ${pkgs.coreutils}/bin/timeout -k 15 180 \
      ${selectedFlight}/bin/crucible-qemu-live-plugin-install \
      ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
      ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
      ${selectedGuest}/whitebox-guest.elf \
      ${selectedRootImage}/root.qcow2 \
      "$cgroup_root" \
      /tmp/plugin-install-attempts/run 65534 65534 \
      > "$install_result" 2> "$qemu_log"; then
      cat "$install_result" >&2
      cat "$qemu_log" >&2
      exit 1
    fi

    require_exact_line() {
      line="$1"
      test "$(grep -Fxc "$line" "$install_result")" -eq 1 || {
        echo "installer result must contain exactly one: $line" >&2
        cat "$install_result" >&2
        exit 1
      }
    }
    require_exact_pattern() {
      pattern="$1"
      test "$(grep -Ec "$pattern" "$install_result")" -eq 1 || {
        echo "installer result must match exactly once: $pattern" >&2
        cat "$install_result" >&2
        exit 1
      }
    }

    require_exact_line PASS
    require_exact_line 'gate=gate:plugin-install-lifecycle'
    require_exact_line 'plugin_loaded=rust-control-cdylib'
    require_exact_line 'time_authority=rust-plugin'
    require_exact_line 'setup_ack_ready=true'
    require_exact_line 'handshake_slot=0'
    require_exact_pattern '^handshake_proto_version=[0-9]+$'
    require_exact_pattern '^handshake_abi_version=[0-9]+$'
    require_exact_pattern '^handshake_node_count=[1-9][0-9]*$'
    require_exact_pattern '^shmem_region_len=[1-9][0-9]*$'
    require_exact_line 'boot_barrier_ceiling_enforced=true'
    require_exact_pattern '^completed_icount=[1-9][0-9]*$'
    require_exact_pattern '^execution_fingerprint=[0-9a-f]{64}$'
    require_exact_pattern '^fingerprint_sample_icount=[1-9][0-9]*$'
    require_exact_pattern '^fingerprint_vcpu_count=[1-9][0-9]*$'
    require_exact_pattern '^fingerprint_rr_current_vcpu=[0-9]+$'
    require_exact_pattern '^fingerprint_rr_position_in_quantum=[0-9]+$'
    require_exact_pattern '^fingerprint_rr_switch_quantum=[1-9][0-9]*$'
    require_exact_line 'fingerprint_component_failures=0'
    require_exact_pattern '^fingerprint_ram_bytes=[1-9][0-9]*$'
    require_exact_pattern '^fingerprint_ram_digest=[0-9a-f]{64}$'
    require_exact_pattern '^fingerprint_device_state_bytes=[1-9][0-9]*$'
    require_exact_pattern '^fingerprint_device_state_sections=[1-9][0-9]*$'
    require_exact_pattern '^fingerprint_device_state_digest=[0-9a-f]{64}$'
    require_exact_pattern '^fingerprint_device_state_schema_digest=[0-9a-f]{64}$'

    fingerprint_vcpu_count=$(grep '^fingerprint_vcpu_count=' "$install_result")
    fingerprint_vcpu_count="''${fingerprint_vcpu_count#*=}"
    vcpu=0
    while test "$vcpu" -lt "$fingerprint_vcpu_count"; do
      require_exact_pattern "^fingerprint_vcpu_''${vcpu}_register_digest=[0-9a-f]{64}$"
      require_exact_pattern "^fingerprint_vcpu_''${vcpu}_register_file_bytes=[1-9][0-9]*$"
      require_exact_pattern "^fingerprint_vcpu_''${vcpu}_retired_instruction_count=[1-9][0-9]*$"
      vcpu=$((vcpu + 1))
    done
    test "$(grep -Ec '^fingerprint_vcpu_[0-9]+_(register_digest|register_file_bytes|retired_instruction_count)=' "$install_result")" \
      -eq "$((fingerprint_vcpu_count * 3))"

    require_exact_line 'run_control_silent=true'
    require_exact_line 'plugin_quit_consumed=true'
    require_exact_line 'orderly_child_exit=true'
    require_exact_line 'time_authority_is_rust_plugin=true'
    require_exact_line 'whitebox=off'
    require_exact_line 'whitebox_setup_region=not-required'
    require_exact_line 'whitebox_marker_count=0'
    require_exact_line 'whitebox_marker_icount=not-observed'
    require_exact_line 'whitebox_last_marker_icount=not-observed'
    require_exact_line 'whitebox_marker_point=not-observed'
    require_exact_line 'app_random_decision_count=0'
    require_exact_line 'app_random_request_id=not-observed'
    require_exact_line 'app_random_values='
    require_exact_line 'app_random_width_bits=not-observed'
    require_exact_line 'fingerprint=on'
    test "$(wc -l < "$install_result")" -eq "$((40 + fingerprint_vcpu_count * 3))"

    mkdir -p "$out"
    cp "$install_result" "$out/result"
    cp "$qemu_log" "$out/qemu.log"
    {
      printf 'attr_path=%s\n' '${attrPath}'
      printf 'task_ids=%s\n' '${taskList}'
      printf 'open_task_ids=%s\n' '${openTaskList}'
      printf 'scope=rust-plugin-install-lifecycle-live-not-fingerprint-migration\n'
      printf 'plugins_loaded=rust-control-plugin-only\n'
      printf 'time_authority=rust-plugin-sim-shmem-dispatch\n'
      printf 'host_resource_authority=cgroup-v2,project-quota,unprivileged-child\n'
      printf 'lifecycle=handshake-scmrights-shmem-setupack-bootbarrier-run-silent-quit-exit\n'
    } >> "$out/result"
    cat "$out/result"

    ${pkgs.util-linux}/bin/umount /tmp/plugin-install-attempts
    trap - EXIT HUP INT TERM
  '';
  authoritativeGate = pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-live-plugin-install";
    version = "0";
    src = null;

    buildDeps = runtimeInputs;

    phases = [
      {
        name = "retain-authoritative-install-run";
        script = runtimeScript;
      }
    ];
  };
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing;
      inherit (campaignComposition) mode system;
      gateName = "gate:plugin-install-lifecycle";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "qemu-live-plugin-install";
      runtimeInputs = selectedRuntimeInputs;
      runtimeScript = selectedRuntimeScript;
      runtimeClosures = [
        selectedFlight
        selectedGuest
        selectedRootImage
        selectedKernel
        pkgs.qemu-crucible
        pkgs.crucible-qemu-plugin
      ];
      timeout = 3600;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else authoritativeGate
