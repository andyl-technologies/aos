# Public CLI composition flight; privileged setup stays in a disposable VM.
{
  pkgs,
  lib,
}: let
  source = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  gateway = pkgs.crucible.passthru.debugGateway;
  flight = pkgs.mkDerivation {
    pname = "crucible-packaged-campaign-flight";
    version = "0";
    src = source;
    buildDeps = [pkgs.coreutils pkgs.rust pkgs.sed pkgs.jq pkgs.pkg-config pkgs.protobuf];
    runtimeDeps = [pkgs.openssl];
    OPENSSL_DIR = "${pkgs.openssl}";
    OPENSSL_NO_VENDOR = "1";
    OPENSSL_STATIC = "0";
    PROTOC = "${pkgs.protobuf}/bin/protoc";
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
        name = "build";
        script = ''
          set -eu
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
          if ! cargo test --frozen --offline --release --no-run --message-format=json \
            --manifest-path crates/Cargo.toml --target-dir "$TMPDIR/target" \
            -p crucible-cli --test campaign_store_process --test legacy_campaign_process \
            > "$TMPDIR/artifacts.jsonl"; then
            jq -r 'select(.reason == "compiler-message") | .message.rendered // empty' "$TMPDIR/artifacts.jsonl"
            exit 1
          fi
          test_binary=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "campaign_store_process" and .executable != null) | .executable' "$TMPDIR/artifacts.jsonl")
          legacy_test_binary=$(jq -r 'select(.reason == "compiler-artifact" and .target.name == "legacy_campaign_process" and .executable != null) | .executable' "$TMPDIR/artifacts.jsonl")
          test -f "$test_binary"
          test -f "$legacy_test_binary"
          mkdir -p "$out/bin"
          cp "$test_binary" "$out/bin/campaign-process-flight"
          cp "$legacy_test_binary" "$out/bin/legacy-campaign-process-flight"
          cp "$TMPDIR/target/release/crucible" "$out/bin/crucible"
          # Genesis is captured before execution; the immutable blank disk still
          # follows the production store-path contract for guest assets.
          truncate -s 1M "$out/root.raw"
        '';
      }
    ];
  };
  deployment = builtins.toFile "campaign-executor.toml" ''
    schema = "crucible.campaign-packaged-executor"
    version = 1
    cgroup_root = "/sys/fs/cgroup/crucible"
    run_root = "/tmp/attempts/run"
    attempt_namespace = "packaged-flight"
    first_project_id = 30000
    project_id_count = 1
    child_user_id = 65534
    child_group_id = 65534
    maximum_tasks = 64
    maximum_inodes = 4096
    finish_timeout_ms = 15000
    maximum_slots = 1
    maximum_vcpus = 2
    maximum_resident_bytes = 536870912
    maximum_disk_bytes = 2147483648
    maximum_execution_quanta = 10000
    maximum_checkpoint_bytes = 1073741824
    worker_count = 1
    host_architecture = "x86_64"
    qemu_profile = "deterministic-tcg-v1"
  '';
  testing = import ../../lib/testing {inherit pkgs lib;};
in
  testing.mkVMTest {
    name = "crucible-packaged-campaign";
    memory = 2048;
    rootfsDeps = [flight deployment gateway pkgs.qemu-crucible pkgs.crucible-qemu-plugin pkgs.linux pkgs.e2fsprogs pkgs.coreutils pkgs.util-linux pkgs.grep];
    testScript = ''
      set -eu
      setup_log=/tmp/campaign-host-setup.log
      : > "$setup_log"

      cleanup_attempt_mount() {
        ${pkgs.util-linux}/bin/umount /tmp/attempts > /dev/null 2>&1 || true
      }

      setup_failure() {
        status="$1"
        stage="$2"
        echo "campaign-host-setup-failed=$stage status=$status"
        ${pkgs.coreutils}/bin/head -n 200 "$setup_log"
        exit "$status"
      }

      setup_step() {
        stage="$1"
        shift
        echo "campaign-host-setup-stage=$stage" >> "$setup_log"
        "$@" >> "$setup_log" 2>&1 || setup_failure "$?" "$stage"
      }

      trap cleanup_attempt_mount EXIT HUP INT TERM
      setup_step cgroup-root mkdir -p /sys/fs/cgroup
      setup_step cgroup-mount ${pkgs.util-linux}/bin/mount -t cgroup2 none /sys/fs/cgroup
      echo 'campaign-host-setup-stage=cgroup-root-controllers' >> "$setup_log"
      echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control 2>> "$setup_log" \
        || setup_failure "$?" cgroup-root-controllers
      setup_step cgroup-owner mkdir /sys/fs/cgroup/crucible
      echo 'campaign-host-setup-stage=cgroup-owner-controllers' >> "$setup_log"
      echo '+cpu +memory +pids' > /sys/fs/cgroup/crucible/cgroup.subtree_control 2>> "$setup_log" \
        || setup_failure "$?" cgroup-owner-controllers
      setup_step quota-image truncate -s 4G /tmp/attempts.img
      setup_step quota-format ${pkgs.e2fsprogs}/sbin/mkfs.ext4 -F -O quota,project -E quotatype=prjquota /tmp/attempts.img
      setup_step quota-mountpoint mkdir /tmp/attempts
      setup_step quota-mount ${pkgs.util-linux}/bin/mount -o loop,prjquota /tmp/attempts.img /tmp/attempts
      setup_step run-directories mkdir -m 700 /tmp/attempts/run /tmp/run-state
      setup_step deployment install -m 600 ${deployment} /tmp/executor.toml
      echo 'campaign-host-setup-complete=true'
      ${pkgs.coreutils}/bin/head -n 200 "$setup_log"
      export CRUCIBLE_PROCESS_FLIGHT_BINARY=${flight}/bin/crucible
      export CRUCIBLE_FLIGHT_QEMU=${pkgs.qemu-crucible}/bin/qemu-system-x86_64
      export CRUCIBLE_FLIGHT_PLUGIN=${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so
      export CRUCIBLE_FLIGHT_DEPLOYMENT=/tmp/executor.toml
      export CRUCIBLE_FLIGHT_RUN_ROOT=/tmp/attempts/run
      export CRUCIBLE_DEBUG_GATEWAY=${gateway}/bin/crucible-debug-gateway
      for kernel in ${pkgs.linux}/boot/vmlinuz-*; do export CRUCIBLE_KERNEL="$kernel"; done
      export CRUCIBLE_ROOT_IMAGE=${flight}/root.raw
      export CRUCIBLE_RUN_STATE_ROOT=/tmp/run-state
      export CRUCIBLE_NATIVE_GUEST_ARCHITECTURE=x86_64
      export CRUCIBLE_VALIDATE_GUEST_ASSET_REFERENCES=1
      if ! ${pkgs.coreutils}/bin/timeout -k 5 300 \
        ${flight}/bin/legacy-campaign-process-flight --ignored --exact \
        public_default_run_executes_through_an_authenticated_campaign \
        --nocapture > /tmp/legacy-default-run-flight.log 2>&1; then
        cat /tmp/legacy-default-run-flight.log
        exit 1
      fi
      cat /tmp/legacy-default-run-flight.log
      ${pkgs.grep}/bin/grep -Fxq \
        'legacy_default_run_campaign=true' \
        /tmp/legacy-default-run-flight.log
      if ! ${pkgs.coreutils}/bin/timeout -k 5 300 \
        ${flight}/bin/legacy-campaign-process-flight --ignored --exact \
        guarded_campaign_failure_artifact_replays_live_evidence \
        --nocapture > /tmp/legacy-failure-replay-flight.log 2>&1; then
        cat /tmp/legacy-failure-replay-flight.log
        exit 1
      fi
      cat /tmp/legacy-failure-replay-flight.log
      ${pkgs.grep}/bin/grep -Fxq \
        'legacy_guarded_failure_replay=true' \
        /tmp/legacy-failure-replay-flight.log
      if ! ${pkgs.coreutils}/bin/timeout -k 5 60 \
        ${flight}/bin/legacy-campaign-process-flight --ignored --exact \
        guarded_campaign_rejects_insufficient_capacity_before_guest_launch \
        --nocapture > /tmp/legacy-capacity-refusal-flight.log 2>&1; then
        cat /tmp/legacy-capacity-refusal-flight.log
        exit 1
      fi
      cat /tmp/legacy-capacity-refusal-flight.log
      ${pkgs.grep}/bin/grep -Fxq \
        'legacy_guarded_prelaunch_capacity_refusal=true' \
        /tmp/legacy-capacity-refusal-flight.log
      ${pkgs.coreutils}/bin/timeout -k 5 300 \
        ${flight}/bin/campaign-process-flight --ignored --exact \
        packaged::public_packaged_executor_captures_genesis_and_restarts --nocapture
      ${pkgs.coreutils}/bin/timeout -k 5 300 \
        ${flight}/bin/campaign-process-flight --ignored --exact \
        packaged::public_packaged_executor_completes_initial_discovery --nocapture
      ${pkgs.coreutils}/bin/timeout -k 5 300 \
        ${flight}/bin/campaign-process-flight --ignored --exact \
        packaged::public_packaged_executor_completes_guest_quantum --nocapture
      ${pkgs.coreutils}/bin/timeout -k 5 300 \
        ${flight}/bin/campaign-process-flight --ignored --exact \
        packaged::public_packaged_executor_observes_exact_trigger_deadlines --nocapture
      ${pkgs.coreutils}/bin/timeout -k 5 300 \
        ${flight}/bin/campaign-process-flight --ignored --exact \
        packaged::public_packaged_executor_synchronizes_exact_time_across_vms --nocapture
      ${pkgs.coreutils}/bin/timeout -k 5 300 \
        ${flight}/bin/campaign-process-flight --ignored --exact \
        packaged::public_packaged_executor_observes_zero_and_early_logical_deadlines --nocapture
      ${pkgs.util-linux}/bin/umount /tmp/attempts
      trap - EXIT HUP INT TERM
    '';
  }
