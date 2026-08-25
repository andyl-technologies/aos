{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName ? "0056-crucible-node-lifecycle-faults.patch",
  attrPath ? "checks.crucible.phase2.qemuNodeLifecycle",
  taskIds ? ["T-QEMU-0056"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;
  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "deferred native reset completion";
        needle = "qemu_crucible_fault_lifecycle_reset_complete";
      }
      {
        label = "writable volatile RAM treatment";
        needle = "crucible_lifecycle_clear_ram";
      }
      {
        label = "fixed-topology hang eligibility";
        needle = "qemu_crucible_fault_vcpu_hung";
      }
      {
        label = "lifecycle evidence format";
        needle = "CRUCLIF1";
      }
      {
        label = "repeated pflash post-load handler replacement";
        needle = ''
          +        if (pfl->vmstate) {
          +            qemu_del_vm_change_state_handler(pfl->vmstate);
        '';
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${patchName}" patchSource [
      {
        label = "host sleep hang";
        needle = "g_usleep";
      }
      {
        label = "host signal-stop hang";
        needle = "SIGSTOP";
      }
    ];
in
  if failures != []
  then throw "Crucible QEMU node-lifecycle microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-node-lifecycle";
      version = "0";
      src = null;
      buildDeps = [
        pkgs.binutils
        pkgs.coreutils
        pkgs.glib
        pkgs.glib.dev
        pkgs.llvm
        pkgs.pkg-config
        pkgs.qemu
        pkgs.jq
        pkgs.socat
        qemuPackage
      ];
      phases = [
        {
          name = "build-live-fixtures";
          script = ''
            set -eu
            "$CC" -shared -fPIC -Wall -Wextra -Werror \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              -I${./.} \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-node-lifecycle.c} \
              -o crucible-node-lifecycle.so \
              $(pkg-config --libs glib-2.0)
            "$CC" -shared -fPIC -Wall -Wextra -Werror \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              -I${./.} \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-node-hang.c} \
              -o crucible-node-hang.so \
              $(pkg-config --libs glib-2.0)
            as --32 ${./phase2-qemu-fault-guest.S} -o fault-guest-x86.o
            ld -m elf_i386 -T ${./phase2-qemu-fault-guest.ld} \
              fault-guest-x86.o -o fault-guest-x86.elf
            ${pkgs.llvm}/bin/clang --target=aarch64-none-elf \
              -c ${./phase2-qemu-fault-guest-aarch64.S} \
              -o fault-guest-aarch64.o
            ${pkgs.llvm}/bin/ld.lld \
              -T ${./phase2-qemu-fault-guest-aarch64.ld} \
              fault-guest-aarch64.o -o fault-guest-aarch64.elf
          '';
        }
        {
          name = "run-live-lifecycle-matrix";
          script = ''
            set -eu
            mkdir -p logs
            run_reset() {
              architecture="$1"
              architecture_id="$2"
              volatile_policy="$3"
              device_policy="$4"
              boot_policy="''${5:-immediate}"
              case "$architecture" in
                x86_64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine_args='-machine pc -m 64M'
                  guest=fault-guest-x86.elf
                  ;;
                aarch64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine_args='-machine virt -cpu max -m 64M'
                  guest=fault-guest-aarch64.elf
                  ;;
                *)
                  echo "unknown architecture: $architecture" >&2
                  exit 1
                  ;;
              esac
              plugin_args="architecture=$architecture_id,volatile_policy=$volatile_policy,device_policy=$device_policy"
              case "$boot_policy" in
                immediate)
                  expected_status=0
                  pass_marker="CRUCIBLE_NODE_LIFECYCLE_LIVE_PASS architecture=$architecture_id volatile_policy=$volatile_policy device_policy=$device_policy"
                  ;;
                require_ready)
                  expected_status=0
                  plugin_args="$plugin_args,boot_policy=require_ready"
                  pass_marker="CRUCIBLE_NODE_LIFECYCLE_LIVE_PASS architecture=$architecture_id volatile_policy=$volatile_policy device_policy=$device_policy"
                  ;;
                *)
                  echo "unknown boot policy: $boot_policy" >&2
                  exit 1
                  ;;
              esac
              log="logs/$architecture-$volatile_policy-$device_policy-$boot_policy.log"
              set +e
              timeout --kill-after=5 120 "$qemu_binary" \
                  $machine_args \
                  -accel sim \
                  -icount shift=0,rr_switch_quantum=256 \
                  -smp 1 \
                  -nographic \
                  -serial none \
                  -monitor none \
                  -kernel "$guest" \
                  -plugin "$PWD/crucible-node-lifecycle.so,$plugin_args" \
                  > "$log" 2>&1
              status=$?
              set -e
              if test "$status" -ne "$expected_status"; then
                cat "$log" >&2
                return 1
              fi
              cat "$log"
              grep -Fq "$pass_marker" "$log"
              test "$(grep -Fc "$pass_marker" "$log")" -eq 1
            }

            cleanup_ready_exhaustion() {
              if test -n "''${qemu_pid:-}"; then
                kill "$qemu_pid" 2>/dev/null || true
                wait "$qemu_pid" 2>/dev/null || true
              fi
            }
            trap cleanup_ready_exhaustion EXIT

            wait_for_socket() {
              socket="$1"
              attempts=0
              while test "$attempts" -lt 600; do
                test -S "$socket" && return 0
                sleep 0.1
                attempts=$((attempts + 1))
              done
              return 1
            }

            wait_for_marker() {
              marker="$1"
              log="$2"
              attempts=0
              while test "$attempts" -lt 1200; do
                grep -Fq "$marker" "$log" && return 0
                kill -0 "$qemu_pid" 2>/dev/null || return 1
                sleep 0.1
                attempts=$((attempts + 1))
              done
              return 1
            }

            qmp() {
              socket="$1"
              request="$2"
              response="$3"
              {
                sleep 0.1
                printf '%s\r\n' '{"execute":"qmp_capabilities"}'
                sleep 0.1
                printf '%s\r\n' "$request"
                sleep 0.3
              } | socat -T 3 - "UNIX-CONNECT:$socket" \
                > "$response" 2> "$response.err" || true
            }

            run_ready_exhaustion() {
              architecture="$1"
              architecture_id="$2"
              case "$architecture" in
                x86_64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine_args='-machine pc -m 64M'
                  guest=fault-guest-x86.elf
                  ;;
                aarch64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine_args='-machine virt -cpu max -m 64M'
                  guest=fault-guest-aarch64.elf
                  ;;
                *)
                  echo "unknown architecture: $architecture" >&2
                  exit 1
                  ;;
              esac
              socket="$TMPDIR/$architecture-ready-exhaustion.sock"
              log="logs/$architecture-ready-exhaustion.log"
              "$qemu_binary" \
                $machine_args \
                -accel sim \
                -icount shift=0,rr_switch_quantum=256 \
                -smp 1 \
                -nographic \
                -serial none \
                -monitor none \
                -qmp "unix:$socket,server=on,wait=off" \
                -kernel "$guest" \
                -plugin "$PWD/crucible-node-lifecycle.so,architecture=$architecture_id,volatile_policy=1,device_policy=1,boot_policy=exhaust" \
                > "$log" 2>&1 &
              qemu_pid="$!"
              marker_prefix="CRUCIBLE_NODE_READY_EXHAUSTION_LIVE_PASS architecture=$architecture_id attempts=2 effective_transition=6 exit_code=72"
              wait_for_socket "$socket" || {
                cat "$log" >&2
                return 1
              }
              wait_for_marker "$marker_prefix" "$log" || {
                cat "$log" >&2
                return 1
              }

              marker=$(grep -F "$marker_prefix" "$log" | tail -1)
              printf '%s\n' "$marker" | grep -Eq \
                "^$marker_prefix action_sha256=[0-9a-f]{64} evidence_sha256=[0-9a-f]{64} process_generation=1$"
              action=$(printf '%s\n' "$marker" | sed -n 's/.*action_sha256=\([0-9a-f]\{64\}\).*/\1/p')
              evidence=$(printf '%s\n' "$marker" | sed -n 's/.*evidence_sha256=\([0-9a-f]\{64\}\).*/\1/p')
              test "''${#action}" -eq 64
              test "''${#evidence}" -eq 64

              qmp "$socket" '{"execute":"query-status"}' "$TMPDIR/$architecture-status.json"
              jq -e -s '[.[] | select(has("return"))][-1].return.status == "paused"' \
                "$TMPDIR/$architecture-status.json" >/dev/null
              completion=$(printf '{"execute":"crucible-complete-terminal-lifecycle","arguments":{"action-sha256":"%s","evidence-sha256":"%s","process-generation":1}}' "$action" "$evidence")
              qmp "$socket" "$completion" "$TMPDIR/$architecture-completion.json"
              jq -e -s 'all(.[]; has("error") | not) and
                ([.[] | select(has("return"))][-1].return == {})' \
                "$TMPDIR/$architecture-completion.json" >/dev/null

              attempts=0
              while kill -0 "$qemu_pid" 2>/dev/null && test "$attempts" -lt 300; do
                sleep 0.1
                attempts=$((attempts + 1))
              done
              if kill -0 "$qemu_pid" 2>/dev/null; then
                cat "$log" >&2
                return 1
              fi
              set +e
              wait "$qemu_pid"
              status="$?"
              set -e
              qemu_pid=""
              test "$status" -eq 72 || {
                cat "$log" >&2
                return 1
              }
              cat "$log"
              test "$(grep -Fc "$marker_prefix" "$log")" -eq 1
            }

            for volatile_policy in 1 2; do
              for device_policy in 1 2 3; do
                run_reset x86_64 2 "$volatile_policy" "$device_policy"
                run_reset aarch64 3 "$volatile_policy" "$device_policy"
              done
            done
            run_reset x86_64 2 1 1 require_ready
            run_reset aarch64 3 1 1 require_ready
            run_ready_exhaustion x86_64 2
            run_ready_exhaustion aarch64 3
          '';
        }
        {
          name = "run-live-hang-matrix";
          script = ''
            set -eu
            run_hang() {
              architecture="$1"
              architecture_id="$2"
              scope="$3"
              case "$architecture" in
                x86_64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-x86_64
                  machine_args='-machine pc -m 64M'
                  guest=fault-guest-x86.elf
                  ;;
                aarch64)
                  qemu_binary=${qemuPackage}/bin/qemu-system-aarch64
                  machine_args='-machine virt -cpu max -m 64M'
                  guest=fault-guest-aarch64.elf
                  ;;
                *)
                  echo "unknown architecture: $architecture" >&2
                  exit 1
                  ;;
              esac
              case "$scope" in
                node)
                  smp=1
                  plugin_args="architecture=$architecture_id"
                  pass_marker="CRUCIBLE_NODE_HANG_LIVE_PASS architecture=$architecture_id"
                  ;;
                runnable-vcpu)
                  smp=2
                  plugin_args="architecture=$architecture_id,scope=vcpu1,initial_virtual_time=10000"
                  pass_marker="CRUCIBLE_NODE_HANG_LIVE_PASS architecture=$architecture_id"
                  ;;
                simultaneous)
                  smp=2
                  plugin_args="architecture=$architecture_id,scope=simultaneous,initial_virtual_time=10000"
                  pass_marker="CRUCIBLE_NODE_HANG_COMPOSITION_LIVE_PASS architecture=$architecture_id"
                  ;;
                *)
                  echo "unknown hang scope: $scope" >&2
                  exit 1
                  ;;
              esac
              log="logs/$architecture-hang-$scope.log"
              if ! timeout --kill-after=5 120 "$qemu_binary" \
                  $machine_args \
                  -accel sim \
                  -icount shift=0,rr_switch_quantum=256 \
                  -smp "$smp" \
                  -nographic \
                  -serial none \
                  -monitor none \
                  -kernel "$guest" \
                  -plugin "$PWD/crucible-node-hang.so,$plugin_args" \
                  > "$log" 2>&1; then
                cat "$log" >&2
                return 1
              fi
              cat "$log"
              grep -Fq "$pass_marker" "$log"
              test "$(grep -Fc "$pass_marker" "$log")" -eq 1
            }

            run_hang x86_64 2 node
            run_hang aarch64 3 node
            run_hang x86_64 2 runnable-vcpu
            run_hang aarch64 3 runnable-vcpu
            run_hang x86_64 2 simultaneous
            run_hang aarch64 3 simultaneous

            set +e
            timeout --kill-after=5 15 \
              ${pkgs.qemu}/bin/qemu-system-x86_64 \
              -machine none -accel tcg -display none -nodefaults -S \
              -plugin "$PWD/crucible-node-lifecycle.so" \
              > logs/stock-qemu.log 2>&1
            stock_status=$?
            set -e
            test "$stock_status" -ne 0
            test "$stock_status" -ne 124
            ! grep -Fq CRUCIBLE_NODE_LIFECYCLE_LIVE_PASS logs/stock-qemu.log
            ! nm -D --defined-only ${pkgs.qemu}/bin/qemu-system-x86_64 \
              | grep -q qemu_plugin_crucible_fault_submit
          '';
        }
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out"
            cp -R logs "$out/"
            {
              printf 'PASS\n'
              printf 'gate=gate:patch-microtests\n'
              printf 'patch=%s\n' '${patchName}'
              printf 'patched_fixture_exercised=true\n'
              printf 'stock_negative_control=true\n'
              printf 'qemu_package=%s\n' '${qemuPackage}'
              printf 'qemu_package_version=%s\n' '${qemuPackage.version}'
              printf 'check=%s\n' '${attrPath}'
              printf 'tasks=%s\n' '${taskList}'
              printf 'architectures=x86_64,aarch64\n'
              printf 'test_double=false\n'
              printf 'backend=actual-patched-and-stock-qemu\n'
              printf 'volatile_policies=preserve,clear\n'
              printf 'device_policies=preserve,clear,device_reset\n'
              printf 'hang_scopes=node,vcpus\n'
              printf 'watchdog_deadline_axes=stalled,runnable-with-time-bias\n'
              printf 'watchdog_composition=atomic-severity-lattice\n'
              printf 'watchdog=transition_after-reset\n'
              printf 'boot_policy=require_ready-live-guest-callback-and-terminal-exhaustion\n'
              printf 'ready_exhaustion=attempts-2,effective-permanent-failure,exit-72\n'
              printf 'recovery=transactional-remove\n'
              printf 'production_effect_row=node.hang|node-vcpu-watchdog-recovery|gate:live-node-lifecycle-matrix|actual-patched-qemu|CRUCHNG1+CRUCWDC1+CRUCLIF1\n'
              printf 'production_effect_row=node.lifecycle|reset-ready-exhaustion|gate:live-node-lifecycle-matrix|actual-patched-qemu|CRUCLIF1-ready-exhausted-permanent-failure\n'
            } > "$out/result"
          '';
        }
      ];
    }
