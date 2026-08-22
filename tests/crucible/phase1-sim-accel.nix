{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0001-crucible-sim-accel.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");
  pluginSource = builtins.readFile ./phase1-sim-accel-plugin.c;
  qemuPackageResultLines =
    if qemuPackage == null
    then ''
      qemu_package=standalone-fixture
      qemu_package_version=standalone-fixture
    ''
    else ''
      qemu_package=${qemuPackage}
      qemu_package_version=${qemuPackage.version}
    '';
  qemuRuntimeResultLines =
    if qemuPackage == null
    then ''
      sim_accel_runtime_exercised=false
    ''
    else ''
      sim_accel_runtime_exercised=true
      sim_accel_selectable=true
      sim_accel_requires_icount=true
      sim_accel_fixed_icount_tb_trace_identical=true
    '';

  qemuRuntimeScript =
    if qemuPackage == null
    then ''
      echo "qemuPackage=null; runtime sim accelerator exercise skipped" > "$out/runtime-skipped.txt"
    ''
    else ''
      qemu="${qemuPackage}/bin/qemu-system-x86_64"
      qemu_pid=""

      fail() {
        echo "FAIL: $*" >&2
        exit 1
      }

      cleanup_qemu() {
        if [ -n "''${qemu_pid:-}" ]; then
          kill "$qemu_pid" 2>/dev/null || true
          wait "$qemu_pid" 2>/dev/null || true
          qemu_pid=""
        fi
      }

      trap cleanup_qemu EXIT

      cp "$pluginSourcePath" phase1-sim-accel-plugin.c
      cc -fPIC -shared -O2 -Wall -Wextra \
        $(pkg-config --cflags glib-2.0) \
        -I${qemuPackage}/include \
        phase1-sim-accel-plugin.c \
        -o phase1-sim-accel-plugin.so
      plugin="$PWD/phase1-sim-accel-plugin.so"

      "$qemu" -accel help > "$out/accel-help.txt"
      grep -F -x -q 'sim' "$out/accel-help.txt"

      if timeout 10 "$qemu" \
        -nodefaults \
        -no-user-config \
        -display none \
        -monitor none \
        -machine q35 \
        -accel sim,thread=single \
        -S \
        -serial none \
        -no-reboot \
        > "$out/no-icount.stdout" 2> "$out/no-icount.stderr"; then
        fail "-accel sim without icount unexpectedly succeeded"
      fi
      grep -F -q -- '-accel sim requires -icount shift=N' "$out/no-icount.stderr"

      qmp_cmd() {
        socket="$1"
        request="$2"
        response="$3"
        response_err="$response.err"

        {
          printf '{"execute":"qmp_capabilities"}\r\n'
          printf '%s\r\n' "$request"
        } | socat -T 2 - "UNIX-CONNECT:$socket" > "$response" 2> "$response_err" || true

        if [ ! -s "$response" ]; then
          cat "$response_err" >&2
          return 1
        fi

        if jq -e -s 'any(.[]; has("error"))' "$response" >/dev/null; then
          cat "$response" >&2
          return 1
        fi
        jq -e -s '[.[] | select(has("return"))] | length >= 2' "$response" >/dev/null
      }

      wait_for_socket() {
        socket="$1"
        waited=0
        while [ "$waited" -lt 300 ]; do
          if [ -S "$socket" ]; then
            return 0
          fi
          sleep 0.1
          waited=$((waited + 1))
        done
        return 1
      }

      wait_for_trace() {
        trace="$1"
        waited=0
        while [ "$waited" -lt 600 ]; do
          if [ -f "$trace" ]; then
            count=$(grep -c '^tb_exec ' "$trace" || true)
            if [ "$count" -ge 256 ]; then
              return 0
            fi
          fi
          if ! kill -0 "$qemu_pid" 2>/dev/null; then
            return 2
          fi
          sleep 0.1
          waited=$((waited + 1))
        done
        return 1
      }

      run_sim_trace() {
        label="$1"
        socket="$TMPDIR/sim-$label.qmp"
        trace="$TMPDIR/sim-$label.tb-trace"
        normalized="$out/sim-$label.tb-trace"
        stderr="$out/sim-$label.stderr"
        stdout="$out/sim-$label.stdout"
        rm -f "$socket" "$trace" "$normalized" "$stderr" "$stdout"

        vmlinuz=$(ls ${pkgs.linux}/boot/vmlinuz-* | head -1)
        if [ -z "$vmlinuz" ]; then
          fail "no vmlinuz under ${pkgs.linux}/boot"
        fi

        timeout 120 "$qemu" \
          -nodefaults \
          -no-user-config \
          -display none \
          -monitor none \
          -machine q35 \
          -accel sim,thread=single \
          -icount shift=0,sleep=off,align=off \
          -cpu qemu64,-rdrand,-rdseed \
          -m 128 \
          -smp 1 \
          -rtc base=2026-01-01T00:00:00,clock=vm \
          -seed 0x0010c004 \
          -kernel "$vmlinuz" \
          -append "console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off net.ifnames=0" \
          -plugin "$plugin",out="$trace",max=256 \
          -serial none \
          -qmp "unix:$socket,server=on,wait=off" \
          -no-reboot \
          > "$stdout" 2> "$stderr" &
        qemu_pid="$!"

        wait_for_socket "$socket" || {
          cat "$stderr" >&2 || true
          fail "$label QMP socket did not appear"
        }
        wait_for_trace "$trace" || {
          wait_status="$?"
          cat "$trace" >&2 || true
          cat "$stderr" >&2 || true
          case "$wait_status" in
            2)
              fail "$label QEMU exited before writing 256 TB trace events"
              ;;
            *)
              fail "$label did not write 256 TB trace events"
              ;;
          esac
        }

        qmp_cmd "$socket" '{"execute":"query-status"}' "$out/sim-$label.status.json" \
          || fail "$label QMP query-status failed while sim vCPU was executing"
        qmp_cmd "$socket" '{"execute":"quit"}' "$out/sim-$label.quit.json" >/dev/null 2>&1 || true
        wait "$qemu_pid" || true
        qemu_pid=""

        grep -F -q 'cursor=' "$trace"
        awk '/^tb_exec / { print }' "$trace" > "$normalized"
        line_count=$(wc -l < "$normalized" | tr -d ' ')
        if [ "$line_count" -ne 256 ]; then
          fail "$label normalized trace has $line_count events, expected 256"
        fi
      }

      run_sim_trace a
      run_sim_trace b
      diff -u "$out/sim-a.tb-trace" "$out/sim-b.tb-trace"
    '';

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  failuresFor = label: content: requirements:
    lib.concatMap (
      requirement:
        lib.optionals (!(hasInfix requirement.needle content)) [
          "${label}: missing ${requirement.label}: `${requirement.needle}`"
        ]
    )
    requirements;

  qemuNixRequirements = [
    {
      label = "sim accel patch wiring";
      needle = "builtins.concatStringsSep \"\" (map patchCommand series.patchFiles)";
    }
  ];

  patchRequirements = [
    {
      label = "sim accel class";
      needle = "TYPE_SIM_ACCEL";
    }
    {
      label = "sim accel ops type";
      needle = ''ACCEL_OPS_NAME("sim")'';
    }
    {
      label = "sim requires icount";
      needle = "-accel sim requires -icount shift=N";
    }
    {
      label = "sim disables MTTCG";
      needle = "s->mttcg_enabled = false";
    }
    {
      label = "sim initializes TCG state";
      needle = ".instance_init = tcg_accel_instance_init";
    }
    {
      label = "sim stores TCG state";
      needle = ".instance_size = sizeof(TCGState)";
    }
    {
      label = "sim reuses TCG target CPU hooks";
      needle = ''g_str_equal(ac->name, "sim")'';
    }
    {
      label = "sim target CPU fallback";
      needle = ''ACCEL_CLASS_NAME("tcg")'';
    }
    {
      label = "sim ops new file";
      needle = "tcg-accel-ops-sim.c";
    }
    {
      label = "split event-loop rationale";
      needle = "vCPU thread owns";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements;
in
  if failures != []
  then throw "crucible phase1 sim-accel check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-sim-accel";
      version = "0";
      src = null;

      inherit patchSource pluginSource;
      passAsFile = ["patchSource" "pluginSource"];

      buildDeps =
        [
          pkgs.coreutils
          pkgs.diffutils
          pkgs.gawk
          pkgs.glib
          pkgs.glib.dev
          pkgs.grep
          pkgs.jq
          pkgs.patch
          pkgs.pkg-config
          pkgs.socat
          pkgs.tar
          pkgs.xz
        ]
        ++ lib.optionals (qemuPackage != null) [qemuPackage];

      phases = [
        {
          name = "run-sim-accel-microtest";
          script = ''
            set -eu

            mkdir -p "$out"

            apply_dir="$TMPDIR/qemu-sim-accel-apply"
            mkdir -p "$apply_dir"
            tar -xf ${pkgs.qemu-crucible.src} -C "$apply_dir"
            source_dir="$apply_dir/qemu-${pkgs.qemu-crucible.version}"

            if grep -R -q 'ACCEL_CLASS_NAME("sim")' "$source_dir"/accel "$source_dir"/include 2>/dev/null; then
              echo "stock source unexpectedly contains sim accelerator" >&2
              exit 1
            fi

            (
              cd "$source_dir"
              patch --batch --fuzz=0 -p1 < "$patchSourcePath"
              test -f accel/tcg/tcg-accel-ops-sim.c
              grep -F -q 'TYPE_SIM_ACCEL' accel/tcg/tcg-all.c
              grep -F -q 'ACCEL_OPS_NAME("sim")' accel/tcg/tcg-accel-ops-sim.c
              grep -F -q 'g_str_equal(ac->name, "sim")' accel/accel-target.c
              grep -F -q 'ACCEL_CLASS_NAME("tcg")' accel/accel-target.c
              grep -F -q 's->mttcg_enabled = false' accel/tcg/tcg-all.c
              grep -F -q '.instance_init = tcg_accel_instance_init' accel/tcg/tcg-all.c
              grep -F -q '.instance_size = sizeof(TCGState)' accel/tcg/tcg-all.c
              grep -F -q -- '-accel sim requires -icount shift=N' accel/tcg/tcg-all.c
            )

            ${qemuRuntimeScript}

            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.simAccel
            gate=gate:layer0-determinism
            gate=gate:patch-microtests
            tasks=T-PATCH-4
            patch=0001-crucible-sim-accel.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            ${qemuPackageResultLines}
            ${qemuRuntimeResultLines}
            RESULT
          '';
        }
      ];
    }
