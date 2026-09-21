{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  sourceCheck ?
    import ./phase2-qemu-checkpoint-delta-source.nix {
      inherit pkgs qemuPackage;
    },
  attrPath ? "checks.crucible.phase2.qemuCheckpointDeltaFlight",
  taskIds ? ["T-CAM-5.3"],
  dependencies ? [],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = import ./_cargo-deps.nix {inherit pkgs lib;};
  checkpointPluginSource = builtins.path {
    path = ./phase2-qemu-checkpoint-delta-plugin.c;
    name = "phase2-qemu-checkpoint-delta-plugin.c";
  };
  checkpointGuestSource = builtins.path {
    path = ./phase2-qemu-fault-guest.S;
    name = "phase2-qemu-fault-guest.S";
  };
  checkpointGuestLinkerScript = builtins.path {
    path = ./phase2-qemu-fault-guest.ld;
    name = "phase2-qemu-fault-guest.ld";
  };
  taskList = builtins.concatStringsSep "," taskIds;
  exactTest = "live_direct_delta_restore_preserves_exact_bytes_and_dirty_epochs";
  ordinaryTest = "ordinary_mode_checkpoint_rejection_is_inert";
  runtimeInputs =
    [
      pkgs.binutils
      pkgs.coreutils
      pkgs.gcc
      pkgs.glib
      pkgs.glib.dev
      pkgs.grep
      pkgs.jq
      pkgs.pkg-config
      pkgs.rust
      pkgs.sed
      pkgs.socat
      qemuPackage
      sourceCheck
    ]
    ++ dependencies;
  campaignRuntimeEnvironment = {
    CC = "${pkgs.gcc}/bin/cc";
    PKG_CONFIG_PATH = "${pkgs.glib.dev}/lib/pkgconfig";
  };
  configureScript = ''
    set -eu
    export CARGO_HOME="$TMPDIR/cargo"
    mkdir -p "$CARGO_HOME" .cargo
    sed "s|@vendor@|${cargoDeps}|g" \
      "${cargoDeps}/.cargo/config.toml" > .cargo/config.toml
  '';
  buildFixturesScript = ''
    set -eu
    cc -shared -fPIC -Wall -Wextra -Werror \
      -I${qemuPackage}/include/qemu \
      -I${qemuPackage}/include \
      $(pkg-config --cflags glib-2.0) \
      ${checkpointPluginSource} \
      -o checkpoint-delta-plugin.so \
      $(pkg-config --libs glib-2.0)
    as --32 --defsym CRUCIBLE_CHECKPOINT_DELTA_GUEST=1 \
      ${checkpointGuestSource} -o checkpoint-delta-guest.o
    ld -m elf_i386 -T ${checkpointGuestLinkerScript} \
      checkpoint-delta-guest.o -o checkpoint-delta-guest.elf

    cargo test \
      --frozen \
      --offline \
      --target-dir "$TMPDIR/checkpoint-delta-target" \
      --manifest-path crates/Cargo.toml \
      -p crucible-qemu \
      --lib \
      --no-run
  '';
  runFlightScript = ''
    set -eu
    mkdir -p logs

    fail() {
      echo "FAIL: $*" >&2
      exit 1
    }

    wait_for_socket() {
      socket="$1"
      attempts=0
      while [ "$attempts" -lt 600 ]; do
        [ -S "$socket" ] && return 0
        kill -0 "$qemu_pid" 2>/dev/null || return 1
        sleep 0.1
        attempts=$((attempts + 1))
      done
      return 1
    }

    wait_for_marker() {
      marker="$1"
      log="$2"
      attempts=0
      while [ "$attempts" -lt 600 ]; do
        grep -Fq "$marker" "$log" && return 0
        kill -0 "$qemu_pid" 2>/dev/null || return 1
        sleep 0.1
        attempts=$((attempts + 1))
      done
      return 1
    }

    qmp_exchange() {
      socket="$1"
      request="$2"
      response="$3"
      {
        printf '%s\r\n' '{"execute":"qmp_capabilities"}'
        printf '%s\r\n' "$request"
        sleep 0.2
      } | socat -T 5 - "UNIX-CONNECT:$socket" > "$response"
    }

    wait_for_paused() {
      socket="$1"
      label="$2"
      attempts=0
      while [ "$attempts" -lt 600 ]; do
        if qmp_exchange "$socket" '{"execute":"query-status"}' \
            "$TMPDIR/status-$label.json" &&
           jq -e -s 'any(.[]; .return.status? == "paused")' \
             "$TMPDIR/status-$label.json" >/dev/null; then
          return 0
        fi
        kill -0 "$qemu_pid" 2>/dev/null || return 1
        sleep 0.1
        attempts=$((attempts + 1))
      done
      return 1
    }

    stop_qemu() {
      if [ -n "''${qemu_pid:-}" ]; then
        kill "$qemu_pid" 2>/dev/null || true
        attempts=0
        while kill -0 "$qemu_pid" 2>/dev/null &&
              [ "$attempts" -lt 50 ]; do
          sleep 0.1
          attempts=$((attempts + 1))
        done
        if kill -0 "$qemu_pid" 2>/dev/null; then
          kill -KILL "$qemu_pid" 2>/dev/null || true
        fi
        wait "$qemu_pid" 2>/dev/null || true
        qemu_pid=
      fi
    }

    cleanup() {
      stop_qemu
    }
    qemu_pid=
    trap cleanup EXIT

    run_rust_test() {
      test_name="$1"
      qmp_socket="$2"
      qtest_socket="$3"
      log="$4"
      qemu_log="$5"
      set +e
      AOS_CHECKPOINT_DELTA_QMP="$qmp_socket" \
      AOS_CHECKPOINT_DELTA_QTEST="$qtest_socket" \
        timeout -k 10 300 cargo test \
          --frozen \
          --offline \
          --target-dir "$TMPDIR/checkpoint-delta-target" \
          --manifest-path crates/Cargo.toml \
          -p crucible-qemu \
          --lib \
          "qmp::checkpoint_delta_flight_tests::$test_name" \
          -- --ignored --exact --nocapture > "$log" 2>&1
      test_status=$?
      set -e
      cat "$log"
      if [ "$test_status" -ne 0 ]; then
        echo "QEMU stderr for failed Rust flight:" >&2
        cat "$qemu_log" >&2
        return "$test_status"
      fi
      test "$(grep -Ec '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in .+$' "$log")" -eq 1 \
        || fail "Rust flight did not report one canonical passing result"
    }

    exact_qmp="$TMPDIR/exact-qmp.sock"
    exact_qtest="$TMPDIR/exact-qtest.sock"
    ${qemuPackage}/bin/qemu-system-x86_64 \
      -machine pc -m 64M \
      -accel sim,thread=single \
      -icount shift=0,sleep=off,align=off,rr_switch_quantum=256 \
      -smp 1 -nodefaults -display none -serial none -monitor none \
      -kernel "$PWD/checkpoint-delta-guest.elf" \
      -qmp "unix:$exact_qmp,server=on,wait=off" \
      -qtest "unix:$exact_qtest,server=on,wait=off" \
      -qtest-log none \
      -plugin "$PWD/checkpoint-delta-plugin.so" \
      > logs/exact-qemu.log 2>&1 &
    qemu_pid="$!"
    wait_for_socket "$exact_qmp" || {
      cat logs/exact-qemu.log >&2
      fail "exact QMP socket did not appear"
    }
    wait_for_socket "$exact_qtest" || fail "exact qtest socket did not appear"
    wait_for_marker CRUCIBLE_CHECKPOINT_DELTA_EXACT_STOP_ADMITTED \
      logs/exact-qemu.log || {
        cat logs/exact-qemu.log >&2
        fail "fixture plugin did not admit an exact stop"
      }
    wait_for_paused "$exact_qmp" exact \
      || fail "exact fixture did not reach RUN_STATE_PAUSED"
    run_rust_test ${exactTest} "$exact_qmp" "$exact_qtest" \
      logs/exact-test.log logs/exact-qemu.log
    direct_restore_to_runnable_us="$(
      sed -n 's/^direct_restore_to_runnable_us=//p' logs/exact-test.log
    )"
    delta_restore_to_runnable_us="$(
      sed -n 's/^delta_restore_to_runnable_us=//p' logs/exact-test.log
    )"
    test "$(printf '%s\n' "$direct_restore_to_runnable_us" | grep -Ec '^[1-9][0-9]*$')" -eq 1 \
      || fail "direct restore latency evidence is missing or duplicated"
    test "$(printf '%s\n' "$delta_restore_to_runnable_us" | grep -Ec '^[1-9][0-9]*$')" -eq 1 \
      || fail "delta restore latency evidence is missing or duplicated"
    grep -Fxq \
      'restore_latency_measurement=descriptor-restore-through-cont-ack' \
      logs/exact-test.log \
      || fail "restore latency measurement label is absent"
    stop_qemu

    ordinary_qmp="$TMPDIR/ordinary-qmp.sock"
    ordinary_qtest="$TMPDIR/ordinary-qtest.sock"
    ${qemuPackage}/bin/qemu-system-x86_64 \
      -machine pc -m 64M \
      -accel tcg \
      -icount shift=0,sleep=off,align=off \
      -smp 1 -nodefaults -display none -serial none -monitor none \
      -kernel "$PWD/checkpoint-delta-guest.elf" \
      -qmp "unix:$ordinary_qmp,server=on,wait=off" \
      -qtest "unix:$ordinary_qtest,server=on,wait=off" \
      -qtest-log none \
      > logs/ordinary-qemu.log 2>&1 &
    qemu_pid="$!"
    wait_for_socket "$ordinary_qmp" || fail "ordinary QMP socket did not appear"
    wait_for_socket "$ordinary_qtest" || fail "ordinary qtest socket did not appear"
    qmp_exchange "$ordinary_qmp" '{"execute":"stop"}' \
      "$TMPDIR/ordinary-stop.json" \
      || fail "ordinary fixture stop command failed"
    wait_for_paused "$ordinary_qmp" ordinary \
      || fail "ordinary fixture did not reach RUN_STATE_PAUSED"
    run_rust_test ${ordinaryTest} "$ordinary_qmp" "$ordinary_qtest" \
      logs/ordinary-test.log logs/ordinary-qemu.log
    stop_qemu

    grep -Fxq PASS ${sourceCheck}/result
    mkdir -p "$out"
    cp -R logs "$out/"
    cp ${sourceCheck}/result "$out/source-result"
    cat > "$out/result" <<'RESULT'
    PASS
    gate=gate:patch-microtests
    patch=crucible-qemu-11.1.1.patch
    patched_fixture_exercised=true
    checkpoint_delta_source_prerequisite_passed=true
    checkpoint_delta_exact_test_passed=1
    ordinary_mode_checkpoint_test_passed=1
    ordinary_mode_checkpoint_rejected=true
    ordinary_mode_inert=true
    direct_delta_reconstruction_equal=true
    checkpoint_restore_equal=true
    restore_latency_measurement=descriptor-restore-through-cont-ack
    RESULT
    {
      printf 'direct_restore_to_runnable_us=%s\n' \
        "$direct_restore_to_runnable_us"
      printf 'delta_restore_to_runnable_us=%s\n' \
        "$delta_restore_to_runnable_us"
      printf 'qemu_package=%s\n' '${qemuPackage}'
      printf 'qemu_package_version=%s\n' '${qemuPackage.version}'
      printf 'attr_path=%s\n' '${attrPath}'
      printf 'task_ids=%s\n' '${taskList}'
    } >> "$out/result"
  '';
  authoritativeGate = pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-checkpoint-delta-flight";
    version = "0";
    src = crucibleSrc;

    buildDeps = runtimeInputs;

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
        script = configureScript;
      }
      {
        name = "build-flight-fixtures";
        script = buildFixturesScript;
      }
      {
        name = "run-native-checkpoint-delta-flight";
        script = runFlightScript;
      }
    ];
  };
  modeRuntimeScript = ''
    cp -R ${crucibleSrc} source
    chmod -R u+w source
    cd source
    ${configureScript}
    ${buildFixturesScript}
    ${runFlightScript}
  '';
in
  if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing runtimeInputs;
      inherit (campaignComposition) mode system;
      gateName = "gate:checkpoint-delta-flight";
      authoritativeAttr = attrPath;
      authoritativeResultIdentity = "restore_latency_measurement=descriptor-restore-through-cont-ack";
      executionFamily = "qemu-runtime";
      name = "checkpoint-delta-flight";
      runtimeClosures = [
        crucibleSrc
        cargoDeps
        checkpointPluginSource
        checkpointGuestSource
        checkpointGuestLinkerScript
      ];
      runtimeScript = modeRuntimeScript;
      runtimeEnvironment = campaignRuntimeEnvironment;
      timeout = 3600;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else authoritativeGate
