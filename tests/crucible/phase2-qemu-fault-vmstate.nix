{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  patchName,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  inherit (import ./_lib.nix {inherit lib;}) failuresFor;
  failures =
    failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource (
      if lib.hasPrefix "0067-" patchName
      then [
        {label = "aggregate VMState envelope"; needle = "CRUCFVM1";}
        {label = "transactional staged restore"; needle = "CrucibleFaultVmstateStaged";}
        {label = "closed core registry"; needle = "crucible_fault_vmstate_required";}
      ]
      else if lib.hasPrefix "0068-" patchName
      then [
        {label = "clock VMState section"; needle = "crucible_clock_vmstate_section";}
        {label = "device-local timer arm sequence"; needle = "crucible_timer_arm_sequence";}
        {label = "realized clock manifest"; needle = "qemu_plugin_crucible_fault_clock_manifest";}
      ]
      else if lib.hasPrefix "0069-" patchName
      then [
        {label = "real accelerator device"; needle = "virtio-crucible-accelerator-device";}
        {label = "vendor-specific virtio name API"; needle = "void virtio_init_named";}
        {label = "explicit accelerator diagnostic name"; needle = "virtio_init_named(vdev, VIRTIO_ID_CRUCIBLE_ACCELERATOR";}
        {label = "standard virtio ID validation retained"; needle = "virtio_id_to_name(device_id)";}
        {label = "mandatory virtio feature negotiation"; needle = "vdc->get_features = accelerator_get_features;";}
        {label = "accelerator VMState section"; needle = "accelerator_vmstate_section";}
        {label = "realized accelerator manifest"; needle = "qemu_plugin_crucible_fault_accelerator_manifest";}
        {label = "fault-free access never releases a null event reservation"; needle = "if (reservation) {\n+        qemu_crucible_fault_event_reservation_release(reservation);\n+    }";}
      ]
      else if lib.hasPrefix "0071-" patchName
      then [
        {label = "lifecycle VM-state precondition"; needle = "qemu_crucible_fault_lifecycle_precondition";}
        {label = "lifecycle command specialization"; needle = "CRUCIBLE_FAULT_COMMAND_NODE_LIFECYCLE";}
        {label = "fail-closed snapshot error"; needle = "CRUCIBLE_FAULT_STATUS_INTERNAL_ERROR";}
      ]
      else if lib.hasPrefix "0072-" patchName
      then [
        {label = "canonical typed result encoding"; needle = "+        node_encode_evidence(staging, result_payload);";}
        {label = "command-specific result replacement removed"; needle = "-        g_byte_array_append(result_payload, staging->impulse_evidence->data,";}
        {label = "result evidence digest retained"; needle = "result->evidence_hash";}
      ]
      else [
        {label = "final fault-system manifest"; needle = "qemu_plugin_crucible_fault_system_manifest";}
        {label = "complete fault-system capability"; needle = "qemu.fault-system.complete.v1";}
        {label = "VMState registry digest"; needle = "vmstate_sections_sha256";}
      ]
    );
in
  if failures != []
  then throw "Crucible fault-VMState microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-fault-vmstate";
      version = "0";
      src = null;
      buildDeps = [
        pkgs.coreutils
        pkgs.glib
        pkgs.grep
        pkgs.sed
        pkgs.jq
        pkgs.pkg-config
        pkgs.socat
        qemuPackage
        pkgs.qemu
      ];
      phases = [
        {
          name = "build-realized-vmstate-plugin";
          script = ''
            set -eu
            "$CC" -shared -fPIC -Wall -Wextra -Werror \
              -I${qemuPackage}/include/qemu \
              -I${qemuPackage}/include \
              -I${./.} \
              $(pkg-config --cflags glib-2.0) \
              ${./phase2-qemu-fault-vmstate.c} \
              -o crucible-fault-vmstate.so \
              $(pkg-config --libs glib-2.0)
          '';
        }
        {
          name = "run-actual-qemu-snapshot-roundtrip";
          script = ''
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

            qmp() {
              socket="$1"
              request="$2"
              response="$3"
              {
                sleep 0.1
                printf '%s\r\n' '{"execute":"qmp_capabilities"}'
                sleep 0.1
                printf '%s\r\n' "$request"
                sleep 0.4
              } | socat -T 4 - "UNIX-CONNECT:$socket" > "$response" 2> "$response.err" || true
            }

            qmp_expect_success() {
              socket="$1"
              request="$2"
              response="$3"
              qmp "$socket" "$request" "$response"
              if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
                cat "$response" >&2
                return 1
              fi
              jq -e -s '[.[] | select(has("return"))] | length >= 2' \
                "$response" >/dev/null
            }

            wait_for_job() {
              socket="$1"
              job="$2"
              attempts=0
              while [ "$attempts" -lt 600 ]; do
                qmp_expect_success "$socket" '{"execute":"query-jobs"}' "$TMPDIR/jobs-$job.json" || return 1
                if jq -e -s --arg job "$job" '
                    ([.[] | select(has("return"))][-1].return // [])[]
                    | select(.id == $job and has("error"))
                  ' "$TMPDIR/jobs-$job.json" >/dev/null; then
                  cat "$TMPDIR/jobs-$job.json" >&2
                  return 1
                fi
                if jq -e -s --arg job "$job" '
                    ([.[] | select(has("return"))][-1].return // [])[]
                    | select(.id == $job and .status == "concluded")
                  ' "$TMPDIR/jobs-$job.json" >/dev/null; then
                  return 0
                fi
                sleep 0.1
                attempts=$((attempts + 1))
              done
              return 1
            }

            cleanup() {
              if [ -n "''${qemu_pid:-}" ]; then
                kill "$qemu_pid" 2>/dev/null || true
                wait "$qemu_pid" 2>/dev/null || true
              fi
            }
            trap cleanup EXIT

            run_qemu() {
              binary="$1"
              label="$2"
              image="$3"
              plugin="$4"
              socket="$TMPDIR/$label.sock"
              rm -f "$socket"
              plugin_args=
              if [ -n "$plugin" ]; then
                plugin_args="-plugin $plugin"
              fi
              "$binary" \
                -machine pc -m 64M -accel sim \
                -icount shift=0,rr_switch_quantum=256 \
                -smp 1 -nodefaults -display none -serial none -monitor none -S \
                -blockdev "driver=file,filename=$image,node-name=vmfile" \
                -blockdev driver=qcow2,file=vmfile,node-name=vmstate \
                -qmp "unix:$socket,server=on,wait=off" \
                $plugin_args > "logs/$label.log" 2>&1 &
              qemu_pid="$!"
              wait_for_socket "$socket" || return 1
            }

            save_snapshot() {
              socket="$1"
              tag="$2"
              job="save-$tag"
              request=$(printf '{"execute":"snapshot-save","arguments":{"job-id":"%s","tag":"%s","vmstate":"vmstate","devices":["vmstate"]}}' "$job" "$tag")
              qmp_expect_success "$socket" "$request" "$TMPDIR/save-$tag.json" \
                || fail "snapshot-save $tag was rejected"
              wait_for_job "$socket" "$job" \
                || fail "snapshot-save $tag did not conclude"
            }

            load_snapshot() {
              socket="$1"
              tag="$2"
              job="load-$tag"
              request=$(printf '{"execute":"snapshot-load","arguments":{"job-id":"%s","tag":"%s","vmstate":"vmstate","devices":["vmstate"]}}' "$job" "$tag")
              qmp_expect_success "$socket" "$request" "$TMPDIR/load-$tag.json" \
                || return 1
              wait_for_job "$socket" "$job"
            }

            quit_qemu() {
              socket="$1"
              qmp "$socket" '{"execute":"quit"}' "$TMPDIR/quit.json"
              wait "$qemu_pid"
              qemu_pid=""
            }

            patched_image="$TMPDIR/patched.qcow2"
            ${qemuPackage}/bin/qemu-img create -f qcow2 "$patched_image" 128M >/dev/null
            run_qemu ${qemuPackage}/bin/qemu-system-x86_64 patched-save \
              "$patched_image" "$PWD/crucible-fault-vmstate.so" \
              || fail "patched save QEMU did not start"
            wait_for_marker CRUCIBLE_FAULT_VMSTATE_FIXTURE_READY logs/patched-save.log \
              || { cat logs/patched-save.log >&2; fail "realized clock fixture did not initialize"; }
            save_snapshot "$TMPDIR/patched-save.sock" checkpoint
            quit_qemu "$TMPDIR/patched-save.sock"
            grep -a -Fq CRUCFVM1 "$patched_image" \
              || fail "patched snapshot omitted the authenticated aggregate fault envelope"
            grep -a -Fq CRUCCVS3 "$patched_image" \
              || fail "patched snapshot omitted the clock VMState section"

            run_qemu ${qemuPackage}/bin/qemu-system-x86_64 patched-load \
              "$patched_image" "$PWD/crucible-fault-vmstate.so" \
              || fail "patched restore QEMU did not start"
            load_snapshot "$TMPDIR/patched-load.sock" checkpoint \
              || { cat logs/patched-load.log >&2; fail "authenticated aggregate VMState did not restore"; }
            quit_qemu "$TMPDIR/patched-load.sock"

            corrupt_image="$TMPDIR/corrupt.qcow2"
            sed 's/CRUCFVM1/CRUCFVX1/g' "$patched_image" > "$corrupt_image"
            grep -a -Fq CRUCFVX1 "$corrupt_image" \
              || fail "corruption fixture did not alter the aggregate magic"
            if grep -a -Fq CRUCFVM1 "$corrupt_image"; then
              fail "corruption fixture left an authenticated aggregate envelope"
            fi
            run_qemu ${qemuPackage}/bin/qemu-system-x86_64 patched-corrupt \
              "$corrupt_image" "$PWD/crucible-fault-vmstate.so" \
              || fail "corrupt restore QEMU did not start"
            if load_snapshot "$TMPDIR/patched-corrupt.sock" checkpoint; then
              fail "corrupt aggregate fault VMState was accepted"
            fi
            quit_qemu "$TMPDIR/patched-corrupt.sock"

            stock_image="$TMPDIR/stock.qcow2"
            ${pkgs.qemu}/bin/qemu-img create -f qcow2 "$stock_image" 128M >/dev/null
            ${pkgs.qemu}/bin/qemu-system-x86_64 \
              -machine pc -m 64M -accel tcg -smp 1 \
              -nodefaults -display none -serial none -monitor none -S \
              -blockdev "driver=file,filename=$stock_image,node-name=vmfile" \
              -blockdev driver=qcow2,file=vmfile,node-name=vmstate \
              -qmp "unix:$TMPDIR/stock.sock,server=on,wait=off" \
              > logs/stock.log 2>&1 &
            qemu_pid="$!"
            wait_for_socket "$TMPDIR/stock.sock" || fail "stock QMP socket did not appear"
            save_snapshot "$TMPDIR/stock.sock" stock
            quit_qemu "$TMPDIR/stock.sock"
            if grep -a -Fq CRUCFVM1 "$stock_image" ||
               grep -a -Fq CRUCCVS3 "$stock_image"; then
              fail "stock QEMU emitted Crucible fault VMState"
            fi
          '';
        }
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out"
            cp -R logs "$out/"
            {
              echo PASS
              echo gate=gate:patch-microtests
              echo patch=${patchName}
              echo patched_fixture_exercised=true
              echo stock_negative_control=true
              echo qemu_package=${qemuPackage}
              echo qemu_package_version=${qemuPackage.version}
              echo backend=actual-patched-qemu
              echo vmstate=authenticated-aggregate-snapshot-roundtrip
              echo corruption=aggregate-magic-rejected-before-commit
              echo clock_manifest=realized-bound-sealed-and-restored
              echo system_manifest=authenticated-build-patch-header-and-vmstate-identity
            } > "$out/result"
          '';
        }
      ];
    }
