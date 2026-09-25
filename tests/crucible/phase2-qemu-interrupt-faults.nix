{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  attrPath ? "checks.crucible.phase2.qemuInterruptFaults",
  taskIds ? ["T-QEMU-0053"],
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  patchSource = builtins.readFile (patchDir + "/${atomicPatch.file}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;

  failures =
    failuresFor "pkgs/emulation/qemu-patches/${atomicPatch.file}" patchSource [
      {
        label = "realized interrupt manifest";
        needle = "qemu_plugin_crucible_fault_interrupt_manifest";
      }
      {
        label = "transactional interrupt interceptor";
        needle = "qemu_crucible_fault_interrupt_intercept";
      }
      {
        label = "controller route validation";
        needle = "qemu_crucible_fault_interrupt_register_route_validator";
      }
      {
        label = "bounded deferred interrupt queue";
        needle = "CRUCIBLE_INTERRUPT_DEFERRED_CAPACITY";
      }
      {
        label = "bounded provenance state";
        needle = "CRUCIBLE_INTERRUPT_PROVENANCE_CAPACITY";
      }
      {
        label = "finite storm execution";
        needle = "crucible_interrupt_storm_cb";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${atomicPatch.file}" patchSource [
      {
        label = "test-double interrupt backend";
        needle = "CRUCIBLE_TEST_DOUBLE";
      }
    ];
in
  if failures != []
  then throw "Crucible QEMU interrupt-fault microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-interrupt-faults";
      version = "0";
      src = null;
      buildDeps = [
        pkgs.binutils
        pkgs.coreutils
        pkgs.glib
        pkgs.glib.dev
        pkgs.grep
        pkgs.llvm
        pkgs.pkg-config
        pkgs.jq
        pkgs.sed
        pkgs.socat
        qemuPackage
      ];
      phases = [
        {
          name = "build-live-probe";
          script = ''
            set -eu
            "$CC" -shared -fPIC -Wall -Wextra -Werror \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              -I${./.} \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-interrupt-manifest.c} \
              -o crucible-interrupt-manifest.so \
              $(pkg-config --libs glib-2.0)
            as --32 ${./phase2-qemu-fault-guest.S} \
              -o interrupt-guest-x86.o
            ld -m elf_i386 -T ${./phase2-qemu-fault-guest.ld} \
              interrupt-guest-x86.o -o interrupt-guest-x86.elf
            ${pkgs.llvm}/bin/clang --target=aarch64-none-elf \
              -c ${./phase2-qemu-fault-guest-aarch64.S} \
              -o interrupt-guest-aarch64.o
            ${pkgs.llvm}/bin/ld.lld \
              -T ${./phase2-qemu-fault-guest-aarch64.ld} \
              interrupt-guest-aarch64.o \
              -o interrupt-guest-aarch64.elf
          '';
        }
        {
          name = "run-live-controller-mutations";
          script = ''
            set -eu
            mkdir -p logs
            run_mutation() {
              architecture="$1"
              architecture_id="$2"
              qemu_binary="$3"
              machine_args="$4"
              guest="$5"
              mutation="$6"
              set +e
              timeout 30 "$qemu_binary" \
                $machine_args \
                -accel sim \
                -icount shift=0,align=off,sleep=off,rr_switch_quantum=256 \
                -smp 1 \
                -nographic \
                -no-reboot \
                -serial none \
                -monitor none \
                -kernel "$guest" \
                -plugin "$PWD/crucible-interrupt-manifest.so,architecture=$architecture_id,mutation=$mutation" \
                > "logs/$architecture-$mutation.log" 2>&1
              status=$?
              set -e
              cat "logs/$architecture-$mutation.log"
              test "$status" -eq 0
              case "$mutation" in
                1) mutation_name=drop ;;
                2) mutation_name=delay ;;
                3) mutation_name=duplicate ;;
                4) mutation_name=replace ;;
              esac
              if test "$architecture_id" -eq 3; then
                mutation_name=storm
              fi
              grep -Fq \
                "CRUCIBLE_INTERRUPT_MUTATION_LIVE_PASS architecture=$architecture_id mutation=$mutation_name" \
                "logs/$architecture-$mutation.log"
              ! grep -Fq CRUCIBLE_INTERRUPT_MUTATION_LIVE_FAIL \
                "logs/$architecture-$mutation.log"
            }
            for mutation in 1 2 3 4; do
              run_mutation x86_64 2 \
                ${qemuPackage}/bin/qemu-system-x86_64 \
                '-machine pc -m 64M' \
                interrupt-guest-x86.elf "$mutation"
            done
            run_mutation aarch64 3 \
              ${qemuPackage}/bin/qemu-system-aarch64 \
              '-machine virt,gic-version=2 -cpu max -m 64M' \
              interrupt-guest-aarch64.elf 1

            qmp_command() {
              request="$2"
              {
                printf '{"execute":"qmp_capabilities"}\r\n'
                printf '%s\r\n' "$request"
              } | socat -T 2 - "UNIX-CONNECT:$1" > "$3"
              jq -e -s '
                ([.[] | select(has("error"))] | length) == 0 and
                ([.[] | select(has("return"))] | length) >= 2
              ' "$3" > /dev/null
            }

            wait_for_snapshot_ready() {
              attempt=0
              while [ "$attempt" -lt 300 ]; do
                if grep -Fq CRUCIBLE_INTERRUPT_SNAPSHOT_READY "$1"; then
                  return 0
                fi
                sleep 0.1
                attempt=$((attempt + 1))
              done
              cat "$1" >&2
              return 1
            }

            # Stop with a storm deadline pending, migrate it, then observe its
            # exact saved tick after the destination resumes.
            source_socket="$PWD/interrupt-source.qmp"
            source_log="$PWD/logs/interrupt-snapshot-source.log"
            migration_file="$PWD/interrupt-pending-storm.vmstate"
            timeout 60 ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc -m 64M \
              -accel sim \
              -icount shift=0,align=off,sleep=off,rr_switch_quantum=256 \
              -smp 1 -nographic -no-reboot -serial none -monitor none \
              -qmp "unix:$source_socket,server=on,wait=off" \
              -kernel interrupt-guest-x86.elf \
              -plugin "$PWD/crucible-interrupt-manifest.so,architecture=2,mutation=1,snapshot=source" \
              > "$source_log" 2>&1 &
            source_pid=$!
            wait_for_snapshot_ready "$source_log"
            attempt=0
            while [ "$attempt" -lt 300 ]; do
              qmp_command "$source_socket" '{"execute":"query-status"}' \
                logs/interrupt-snapshot-status.json
              if jq -e -s \
                '[.[] | select(has("return"))][-1].return.status == "paused"' \
                logs/interrupt-snapshot-status.json > /dev/null; then
                break
              fi
              sleep 0.1
              attempt=$((attempt + 1))
            done
            test "$attempt" -lt 300
            expected_tick=$(sed -n 's/.*expected_storm_tick=\([0-9][0-9]*\).*/\1/p' "$source_log" | tail -n 1)
            test -n "$expected_tick"

            qmp_command "$source_socket" \
              "{\"execute\":\"migrate\",\"arguments\":{\"uri\":\"file:$migration_file\"}}" \
              logs/interrupt-snapshot-migrate.json
            attempt=0
            while [ "$attempt" -lt 300 ]; do
              qmp_command "$source_socket" '{"execute":"query-migrate"}' \
                logs/interrupt-snapshot-query-migrate.json
              migration_status=$(jq -r -s \
                '[.[] | select(has("return"))][-1].return.status // empty' \
                logs/interrupt-snapshot-query-migrate.json)
              test "$migration_status" != failed
              if [ "$migration_status" = completed ]; then
                break
              fi
              sleep 0.1
              attempt=$((attempt + 1))
            done
            test "$migration_status" = completed
            test -s "$migration_file"
            qmp_command "$source_socket" '{"execute":"quit"}' \
              logs/interrupt-snapshot-source-quit.json || true
            wait "$source_pid"

            restore_socket="$PWD/interrupt-restore.qmp"
            restore_log="$PWD/logs/interrupt-snapshot-restore.log"
            timeout 60 ${qemuPackage}/bin/qemu-system-x86_64 \
              -machine pc -m 64M \
              -accel sim \
              -icount shift=0,align=off,sleep=off,rr_switch_quantum=256 \
              -smp 1 -nographic -no-reboot -serial none -monitor none \
              -qmp "unix:$restore_socket,server=on,wait=off" \
              -incoming "file:$migration_file" \
              -kernel interrupt-guest-x86.elf \
              -plugin "$PWD/crucible-interrupt-manifest.so,architecture=2,mutation=1,snapshot=restore,expected_storm_tick=$expected_tick" \
              > "$restore_log" 2>&1 &
            restore_pid=$!
            attempt=0
            while [ ! -S "$restore_socket" ] && [ "$attempt" -lt 300 ]; do
              sleep 0.1
              attempt=$((attempt + 1))
            done
            test -S "$restore_socket"
            qmp_command "$restore_socket" '{"execute":"cont"}' \
              logs/interrupt-snapshot-cont.json
            wait "$restore_pid"
            cat "$restore_log"
            grep -Fq CRUCIBLE_INTERRUPT_SNAPSHOT_RESTORE_LIVE_PASS \
              "$restore_log"

            set +e
            timeout 5 ${referenceQemu}/bin/qemu-system-x86_64 \
              -machine pc -m 64M \
              -accel tcg \
              -icount shift=0 \
              -smp 1 \
              -nographic \
              -no-reboot \
              -serial none \
              -monitor none \
              -kernel interrupt-guest-x86.elf \
              -plugin "$PWD/crucible-interrupt-manifest.so,architecture=2,mutation=1" \
              > logs/stock.log 2>&1
            stock_status=$?
            set -e
            cat logs/stock.log
            test "$stock_status" -ne 0
            test "$stock_status" -ne 124
            ! grep -q CRUCIBLE_INTERRUPT_MUTATION_LIVE_PASS logs/stock.log
            ! nm -D --defined-only \
              ${referenceQemu}/bin/qemu-system-x86_64 \
              | grep -q qemu_plugin_crucible_fault_interrupt_manifest

            mkdir -p "$out"
            cp -R logs "$out/"
            {
              printf 'PASS\n'
              printf 'gate=gate:patch-microtests\n'
              printf 'atomic_patch=%s\n' '${atomicPatch.file}'
              printf 'patched_fixture_exercised=true\n'
              printf 'stock_negative_control=true\n'
              printf 'qemu_package=%s\n' '${qemuPackage}'
              printf 'qemu_package_version=%s\n' '${qemuPackage.version}'
              printf 'attr_path=%s\n' '${attrPath}'
              printf 'task_ids=%s\n' '${taskList}'
              printf 'backend=actual-patched-and-stock-qemu\n'
              printf 'architectures=x86_64,aarch64\n'
              printf 'live_mutations=drop,delay,duplicate,replace,storm\n'
              printf 'deferred_source_tick_phase=7\n'
              printf 'deferred_release_delta_ticks=8\n'
              printf 'pending_storm_snapshot_restore=true\n'
              printf 'production_effect_row=interrupt.disposition|drop-delay-duplicate-replace|gate:patch-microtests|actual-patched-qemu|source+target+vector+delivery-count\n'
              printf 'production_effect_row=interrupt.storm|bounded-storm|gate:patch-microtests|actual-patched-qemu|event-sequence+acknowledgements\n'
            } > "$out/result"
          '';
        }
      ];
    }
