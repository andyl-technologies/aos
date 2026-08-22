# Canonical exact-horizon runtime discriminator for patches whose effects alter
# execution scheduling or terminal observation rather than simple guest output.
{
  pkgs,
  lib,
  index,
  buildDrv,
  qemuPackage ? pkgs.qemu-crucible,
  attrPath ? "drop-one-canonical-trace",
}: let
  execBoundaryPluginSource =
    builtins.toFile
    "drop-one-exec-boundary-plugin.c"
    (builtins.readFile ./drop-one-exec-boundary-plugin.c);
  execBoundaryPlugin = pkgs.mkDerivation {
    pname = "crucible-drop-one-exec-boundary-plugin";
    version = "0";
    src = null;
    buildDeps = [pkgs.glib pkgs.glib.dev pkgs.pkg-config qemuPackage];
    PLUGIN_SOURCE = "${execBoundaryPluginSource}";
    phases = [
      {
        name = "build-exec-boundary-plugin";
        script = ''
          set -eu
          cc -fPIC -shared -O2 -Wall -Wextra \
            $(pkg-config --cflags glib-2.0) \
            -I${qemuPackage}/include \
            "$PLUGIN_SOURCE" \
            -o drop-one-exec-boundary-plugin.so
          mkdir -p "$out/lib/qemu/plugins"
          cp drop-one-exec-boundary-plugin.so \
            "$out/lib/qemu/plugins/drop-one-exec-boundary-plugin.so"
        '';
      }
    ];
  };
  warpBoundaryPluginSource =
    builtins.toFile
    "drop-one-warp-boundary-plugin.c"
    (builtins.readFile ./drop-one-warp-boundary-plugin.c);
  warpBoundaryPlugin = pkgs.mkDerivation {
    pname = "crucible-drop-one-warp-boundary-plugin";
    version = "0";
    src = null;
    buildDeps = [pkgs.glib pkgs.glib.dev pkgs.pkg-config qemuPackage];
    PLUGIN_SOURCE = "${warpBoundaryPluginSource}";
    phases = [
      {
        name = "build-warp-boundary-plugin";
        script = ''
          set -eu
          cc -fPIC -shared -O2 -Wall -Wextra \
            $(pkg-config --cflags glib-2.0) \
            -I${qemuPackage}/include \
            "$PLUGIN_SOURCE" \
            -o drop-one-warp-boundary-plugin.so
          mkdir -p "$out/lib/qemu/plugins"
          cp drop-one-warp-boundary-plugin.so \
            "$out/lib/qemu/plugins/drop-one-warp-boundary-plugin.so"
        '';
      }
    ];
  };
  variantPackage = pkgs.mkDerivation {
    pname = "crucible-drop-one-qemu-wrapper-${toString index}";
    version = "0";
    src = null;
    BUILD_DRV = "${buildDrv}";
    phases = [
      {
        name = "install-variant-wrapper";
        script = ''
          set -eu
          mkdir -p "$out/bin" "$out/share"
          if [ "$(cat "$BUILD_DRV/outcome")" != built ]; then
            exit 0
          fi
          ln -s "$BUILD_DRV/variant-qemu-system-x86_64" \
            "$out/bin/qemu-system-x86_64"
          ln -s ${qemuPackage}/share/qemu "$out/share/qemu"
          if [ -d ${qemuPackage}/libexec ]; then
            ln -s ${qemuPackage}/libexec "$out/libexec"
          fi
        '';
      }
    ];
  };
  minimalWorkload = import ./_sim-workload.nix {inherit pkgs lib;};
  idleWorkload = import ./phase2-qemu-live-plugin-quantum-guest.nix {inherit pkgs;};
  rrKickProbe =
    if index == 38
    then
      pkgs.mkDerivation {
        pname = "crucible-drop-one-rr-kick-probe";
        version = "0";
        src = null;
        buildDeps = [pkgs.coreutils execBoundaryPlugin qemuPackage];
        BUILD_DRV = "${buildDrv}";
        FULL_QEMU = "${qemuPackage}/bin/qemu-system-x86_64";
        FIRMWARE = "${qemuPackage}/share/qemu";
        EXEC_PLUGIN = "${execBoundaryPlugin}/lib/qemu/plugins/drop-one-exec-boundary-plugin.so";
        KERNEL = "${pkgs.linux}";
        INITRAMFS = "${minimalWorkload.initramfs}/initrd.img";
        phases = [
          {
            name = "probe-rr-kick-deadline";
            script = ''
              set -eu
              mkdir -p "$out"
              if [ "$(cat "$BUILD_DRV/outcome")" != built ]; then
                cat > "$out/result" <<RESULT
              PASS
              check=${attrPath}
              gate=gate:patch-microtests
              drop_index=38
              sim_discriminator_classification=not-applicable
              reason=variant-not-built
              RESULT
                exit 0
              fi
              variant="$BUILD_DRV/variant-qemu-system-x86_64"
              vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
              test -n "$vmlinuz"

              run_probe() {
                qemu="$1"
                label="$2"
                timeout 30 "$qemu" \
                  -L "$FIRMWARE" \
                  -nodefaults \
                  -no-user-config \
                  -display none \
                  -monitor none \
                  -machine q35,hpet=off,pit=off,pic=off \
                  -accel sim,thread=single \
                  -icount shift=0,sleep=off,align=off,rr_switch_quantum=1000000000 \
                  -cpu qemu64 \
                  -smp 2 \
                  -seed 0x0010c026 \
                  -kernel "$vmlinuz" \
                  -initrd "$INITRAMFS" \
                  -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet" \
                  -serial none \
                  -plugin "$EXEC_PLUGIN,out=$out/$label.tsv,stop_after=1" \
                  -no-reboot
                test "$(wc -l < "$out/$label.tsv" | tr -d ' ')" -ge 1
              }

              run_probe "$FULL_QEMU" full-a
              run_probe "$FULL_QEMU" full-b
              run_probe "$variant" variant-a
              run_probe "$variant" variant-b

              # request_shutdown() is asynchronous: callbacks already queued
              # after the requested first-event horizon may still reach the
              # plugin. Compare the first event that defines this probe, not
              # the incidental shutdown tail.
              head -1 "$out/full-a.tsv" > "$out/full-a.boundary"
              head -1 "$out/full-b.tsv" > "$out/full-b.boundary"
              head -1 "$out/variant-a.tsv" > "$out/variant-a.boundary"
              head -1 "$out/variant-b.tsv" > "$out/variant-b.boundary"
              cmp "$out/full-a.boundary" "$out/full-b.boundary"
              cmp "$out/variant-a.boundary" "$out/variant-b.boundary"
              cut -f1-3 "$out/full-a.boundary" > "$out/full-prefix"
              cut -f1-3 "$out/variant-a.boundary" > "$out/variant-prefix"
              cmp "$out/full-prefix" "$out/variant-prefix"
              if cmp -s "$out/full-a.boundary" "$out/variant-a.boundary"; then
                echo "RR kick deadline is identical with patch 0038 dropped" >&2
                exit 1
              fi
              full_deadline=$(cut -f4 "$out/full-a.boundary")
              variant_deadline=$(cut -f4 "$out/variant-a.boundary")
              test "$full_deadline" -ge 0
              test "$variant_deadline" -ge 0
              test "$variant_deadline" -lt "$full_deadline"

              cat > "$out/result" <<RESULT
              PASS
              check=${attrPath}
              gate=gate:patch-microtests
              drop_index=38
              sim_discriminator_classification=differs
              semantic_form=stock-rr-kick-virtual-deadline-present-only-in-variant
              full_rr_kick_deadline=$full_deadline
              variant_rr_kick_deadline=$variant_deadline
              full_boundary_run_twice_identical=true
              variant_runs=2
              variant_diverges=false
              runs_to_diverge=0
              RESULT
            '';
          }
        ];
      }
    else null;
  warpFreezeProbe =
    if index == 37
    then
      pkgs.mkDerivation {
        pname = "crucible-drop-one-warp-freeze-probe";
        version = "0";
        src = null;
        buildDeps = [
          pkgs.coreutils
          pkgs.jq
          pkgs.socat
          qemuPackage
          warpBoundaryPlugin
        ];
        BUILD_DRV = "${buildDrv}";
        FULL_QEMU = "${qemuPackage}/bin/qemu-system-x86_64";
        FIRMWARE = "${qemuPackage}/share/qemu";
        WARP_PLUGIN = "${warpBoundaryPlugin}/lib/qemu/plugins/drop-one-warp-boundary-plugin.so";
        KERNEL = "${pkgs.linux}";
        INITRAMFS = "${idleWorkload}/initrd.img";
        phases = [
          {
            name = "probe-terminal-warp-freeze";
            script = ''
              set -eu
              mkdir -p "$out"
              if [ "$(cat "$BUILD_DRV/outcome")" != built ]; then
                cat > "$out/result" <<RESULT
              PASS
              check=${attrPath}
              gate=gate:patch-microtests
              drop_index=37
              sim_discriminator_classification=not-applicable
              reason=variant-not-built
              RESULT
                exit 0
              fi
              variant="$BUILD_DRV/variant-qemu-system-x86_64"
              vmlinuz=$(ls "$KERNEL"/boot/vmlinuz-* | head -1)
              test -n "$vmlinuz"
              active_qemu_pid=""

              cleanup() {
                if [ -n "$active_qemu_pid" ]; then
                  kill "$active_qemu_pid" 2>/dev/null || true
                  wait "$active_qemu_pid" 2>/dev/null || true
                  active_qemu_pid=""
                fi
              }
              trap cleanup EXIT

              qmp_cmd() {
                socket="$1"
                request="$2"
                response="$3"
                {
                  # Socket creation precedes QMP's ability to service commands.
                  # Leave bounded host-scheduling slack so aggregate parallel
                  # builds cannot turn control-plane startup into a false
                  # semantic failure.
                  sleep 1
                  printf '{"execute":"qmp_capabilities"}\r\n'
                  sleep 1
                  printf '%s\r\n' "$request"
                  sleep 2
                } | socat -T 15 - "UNIX-CONNECT:$socket" \
                    > "$response" 2> "$response.err" || true
                test -s "$response"
                ! jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null
                jq -e -s \
                  '[.[] | select(has("return"))] | length >= 2' \
                  "$response" >/dev/null
              }

              wait_for_socket() {
                socket="$1"
                attempts=0
                while [ "$attempts" -lt 600 ]; do
                  [ -S "$socket" ] && return 0
                  attempts=$((attempts + 1))
                  sleep 0.1
                done
                return 1
              }

              wait_for_marker() {
                marker="$1"
                attempts=0
                while [ "$attempts" -lt 1200 ]; do
                  if grep -Eq \
                    '^reached=[0-9]+	minimum=5000000$' \
                    "$marker" 2>/dev/null; then
                    return 0
                  fi
                  attempts=$((attempts + 1))
                  sleep 0.1
                done
                return 1
              }

              wait_for_migration() {
                socket="$1"
                label="$2"
                attempts=0
                while [ "$attempts" -lt 1200 ]; do
                  if qmp_cmd \
                    "$socket" \
                    '{"execute":"query-migrate"}' \
                    "$TMPDIR/query-migrate-$label.json"; then
                    status=$(
                      jq -r -s \
                        '[.[] | select(has("return"))][-1].return.status // empty' \
                        "$TMPDIR/query-migrate-$label.json"
                    )
                    case "$status" in
                      completed)
                        return 0
                        ;;
                      failed | cancelled)
                        cat "$TMPDIR/query-migrate-$label.json" >&2
                        return 1
                        ;;
                    esac
                  fi
                  attempts=$((attempts + 1))
                  sleep 0.1
                done
                return 1
              }

              run_probe() {
                qemu="$1"
                label="$2"
                socket="$TMPDIR/qmp-$label.sock"
                marker="$out/$label.marker"
                state="$TMPDIR/$label.migration"
                rm -f "$socket" "$marker" "$state"

                timeout 180 "$qemu" \
                  -L "$FIRMWARE" \
                  -nodefaults \
                  -no-user-config \
                  -display none \
                  -monitor none \
                  -machine q35 \
                  -accel sim,thread=single \
                  -icount shift=0,sleep=off,align=off,rr_switch_quantum=4096 \
                  -cpu qemu64 \
                  -m 128 \
                  -smp 2 \
                  -rtc base=2026-01-01T00:00:00,clock=vm \
                  -uuid 0010c037-0000-4000-8000-000000000037 \
                  -seed 0x0010c037 \
                  -kernel "$vmlinuz" \
                  -initrd "$INITRAMFS" \
                  -append "console=ttyS0 reboot=k panic=1 rdinit=/init quiet nokaslr norandmaps random.trust_cpu=off net.ifnames=0 nohz=off" \
                  -serial none \
                  -plugin "$WARP_PLUGIN,out=$marker,target=5000000" \
                  -S \
                  -qmp "unix:$socket,server=on,wait=off" \
                  -no-shutdown &
                active_qemu_pid="$!"
                wait_for_socket "$socket"
                qmp_cmd \
                  "$socket" \
                  '{"execute":"cont"}' \
                  "$TMPDIR/qmp-cont-$label.json"
                wait_for_marker "$marker"

                # Leave the observer-clamped VM runnable for a fixed host
                # interval. Patch 0037 freezes virtual-time warp throughout
                # this interval; the drop-one variant advances its icount bias.
                sleep 2
                qmp_cmd \
                  "$socket" \
                  '{"execute":"stop"}' \
                  "$TMPDIR/qmp-stop-$label.json"
                qmp_cmd \
                  "$socket" \
                  "{\"execute\":\"migrate\",\"arguments\":{\"uri\":\"file:$state\"}}" \
                  "$TMPDIR/qmp-migrate-$label.json"
                wait_for_migration "$socket" "$label"
                sha256sum "$state" | cut -d ' ' -f1 > "$out/$label.sha256"
                wc -c < "$state" | tr -d ' ' > "$out/$label.bytes"
                rm -f "$state"
                qmp_cmd \
                  "$socket" \
                  '{"execute":"quit"}' \
                  "$TMPDIR/qmp-quit-$label.json" || true
                wait "$active_qemu_pid"
                active_qemu_pid=""
              }

              run_probe "$FULL_QEMU" full-a
              run_probe "$FULL_QEMU" full-b
              run_probe "$variant" variant-a
              run_probe "$variant" variant-b

              cmp "$out/full-a.marker" "$out/full-b.marker"
              cmp "$out/variant-a.marker" "$out/variant-b.marker"
              full_a=$(cat "$out/full-a.sha256")
              full_b=$(cat "$out/full-b.sha256")
              variant_a=$(cat "$out/variant-a.sha256")
              variant_b=$(cat "$out/variant-b.sha256")
              test "$full_a" = "$full_b"
              if [ "$variant_a" != "$variant_b" ]; then
                classification=diverges
                semantic_form=variant-terminal-vmstate-diverges-after-warp-window
                runs_to_diverge=2
              elif [ "$full_a" != "$variant_a" ]; then
                classification=differs
                semantic_form=variant-terminal-vmstate-differs-after-warp-window
                runs_to_diverge=0
              else
                echo "drop-0037 terminal VM state matched the frozen full state" >&2
                exit 1
              fi

              cat > "$out/result" <<RESULT
              PASS
              check=${attrPath}
              gate=gate:patch-microtests
              drop_index=37
              sim_discriminator_classification=$classification
              semantic_form=$semantic_form
              observer_target_icount=5000000
              post_boundary_host_delay_seconds=2
              terminal_state_transport=qemu-migration-stream
              full_terminal_state_sha256=$full_a
              variant_first_terminal_state_sha256=$variant_a
              full_run_twice_identical=true
              variant_runs=2
              variant_diverges=$(test "$classification" = diverges && echo true || echo false)
              runs_to_diverge=$runs_to_diverge
              RESULT
            '';
          }
        ];
      }
    else null;
  liveIoProbe =
    if builtins.elem index [17 19]
    then
      import ./_drop-one-live-io.nix {
        inherit pkgs lib index qemuPackage buildDrv;
        attrPath = "${attrPath}.liveIo";
      }
    else null;
  ninepSyncKickProbe =
    if index == 40
    then
      import ./_drop-one-9p-sync-kick.nix {
        inherit pkgs lib qemuPackage buildDrv;
        attrPath = "${attrPath}.ninepSyncKick";
      }
    else null;
  usesFocusedProbe = builtins.elem index [17 19 37 38 40];
  traceStopAt =
    if index == 3
    then 500000000
    else 150000000;
  traceCadence =
    if index == 3
    then 100000000
    else 25000000;
  traceQuantum =
    if index == 3
    then 400000000
    else 4096;
  traceArgs = {
    inherit pkgs lib;
    cadence = traceCadence;
    stopAt = traceStopAt;
    memoryMib = 128;
    vcpuCount = 2;
    requireGuestPass = false;
    # The drop-one fanout deliberately runs many independent QEMU probes under
    # the same Nix build. Keep a finite wall-clock bound while allowing the
    # canonical 500M-instruction migration probe to make progress under that
    # aggregate CPU contention.
    runTimeoutSeconds = 1200;
    execBoundaryPluginPackage = execBoundaryPlugin;
    realtimeDeadlineProbe = index == 3;
    rrSwitchQuantum = traceQuantum;
  };
  fullTrace =
    if usesFocusedProbe
    then null
    else import ./phase0-s11.nix traceArgs;
  variantTrace =
    if usesFocusedProbe
    then null
    else
      import ./phase0-s11.nix (traceArgs
        // {
          qemuPackage = variantPackage;
          qemuDataDir = "${qemuPackage}/share/qemu";
          qemuRuntimeDeps = [qemuPackage];
          permitTraceMismatch = true;
          skipUnlessBuilt = buildDrv;
        });
in
  pkgs.mkDerivation {
    pname = "crucible-drop-one-canonical-trace-${toString index}";
    version = "0";
    src = null;
    buildDeps = [pkgs.coreutils pkgs.diffutils pkgs.gawk pkgs.jq];
    BUILD_DRV = "${buildDrv}";
    FULL_TRACE =
      if usesFocusedProbe
      then ""
      else "${fullTrace}";
    VARIANT_TRACE =
      if usesFocusedProbe
      then ""
      else "${variantTrace}";
    FOCUSED_PROBE =
      if index == 38
      then "${rrKickProbe}"
      else if index == 37
      then "${warpFreezeProbe}"
      else if builtins.elem index [17 19]
      then "${liveIoProbe}"
      else if index == 40
      then "${ninepSyncKickProbe}"
      else "";
    DROP_INDEX = toString index;
    phases = [
      {
        name = "classify-canonical-trace";
        script = ''
          set -eu
          export LC_ALL=C
          mkdir -p "$out"

          if [ "$(cat "$BUILD_DRV/outcome")" != built ]; then
            cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          drop_index=$DROP_INDEX
          sim_discriminator_classification=not-applicable
          reason=variant-not-built
          RESULT
            exit 0
          fi

          if [ -n "$FOCUSED_PROBE" ]; then
            for artifact in "$FOCUSED_PROBE"/*; do
              if [ -f "$artifact" ]; then
                cp "$artifact" "$out/"
              fi
            done
            exit 0
          fi

          normalize_trace() {
            jq -S -c '
              del(
                .launch_definition_digest,
                .qemu_build_digest,
                .trace_plugin_build_digest,
                .process_argv_attestation_version,
                .process_argv_encoding,
                .process_argv_argc,
                .process_argv_raw_bytes,
                .process_argv_digest,
                .process_argv_status,
                .stream_hash,
                .diagnostic_extended_fnv
              )
            ' "$1"
          }

          normalize_trace "$FULL_TRACE/trace-authoritative-a.jsonl" \
            > "$out/full-normalized.jsonl"
          normalize_trace "$VARIANT_TRACE/trace-authoritative-a.jsonl" \
            > "$out/variant-a-normalized.jsonl"
          normalize_trace "$VARIANT_TRACE/trace-authoritative-b.jsonl" \
            > "$out/variant-b-normalized.jsonl"

          if ! diff -u \
            "$FULL_TRACE/exec-boundaries-a.tsv" \
            "$FULL_TRACE/exec-boundaries-b.tsv" \
            > "$out/full-exec-boundaries.diff"; then
            echo "full execution-boundary traces differ" >&2
            exit 1
          elif ! diff -u \
            "$VARIANT_TRACE/exec-boundaries-a.tsv" \
            "$VARIANT_TRACE/exec-boundaries-b.tsv" \
            > "$out/variant-exec-boundaries.diff"; then
            classification=diverges
            semantic_form=variant-execution-boundary-trace-diverges
            runs_to_diverge=2
          elif ! diff -u \
            "$FULL_TRACE/exec-boundaries-a.tsv" \
            "$VARIANT_TRACE/exec-boundaries-a.tsv" \
            > "$out/full-vs-variant-exec-boundaries.diff"; then
            classification=differs
            semantic_form=variant-execution-boundary-trace-differs-from-full
            runs_to_diverge=0
          else
            variant_match=$(
              gawk -F= '/^extended_fingerprint_match=/ { print $2 }' \
                "$VARIANT_TRACE/result"
            )
            if [ "$variant_match" = false ]; then
              classification=diverges
              semantic_form=variant-canonical-trace-diverges
              runs_to_diverge=2
            elif ! diff -u \
            "$out/full-normalized.jsonl" \
            "$out/variant-a-normalized.jsonl" \
            > "$out/full-vs-variant.diff"; then
              classification=differs
              semantic_form=variant-canonical-trace-differs-from-full
              runs_to_diverge=0
            else
              classification=none
              semantic_form=canonical-traces-and-execution-boundaries-identical
              runs_to_diverge=0
            fi
          fi

          cp "$FULL_TRACE/result" "$out/full-trace.result"
          cp "$VARIANT_TRACE/result" "$out/variant-trace.result"
          cat > "$out/result" <<RESULT
          PASS
          check=${attrPath}
          gate=gate:patch-microtests
          drop_index=$DROP_INDEX
          sim_discriminator_classification=$classification
          semantic_form=$semantic_form
          canonical_exact_horizon_trace=true
          canonical_trace_stop_at=${toString traceStopAt}
          canonical_trace_vcpus=2
          execution_boundary_trace=true
          identity_only_fields_normalized=true
          full_run_twice_identical=true
          variant_runs=2
          variant_diverges=$(test "$classification" = diverges && echo true || echo false)
          runs_to_diverge=$runs_to_diverge
          RESULT
        '';
      }
    ];
  }
