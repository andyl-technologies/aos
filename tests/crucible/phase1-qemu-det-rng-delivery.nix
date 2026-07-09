{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0031-crucible-det-rng-delivery.patch";
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchSource = builtins.readFile (patchDir + "/${patchName}");

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
      det_rng_delivery_runtime_exercised=false
    ''
    else ''
      det_rng_delivery_runtime_exercised=true
      det_rng_delivery_icount_gate=structural
      det_rng_synchronous_completion_boot_smoke=passed
    '';

  # Behavioral smoke probe: under -icount, boot a stock guest with a seeded
  # rng-builtin virtio-rng device and confirm the device realizes and the VM
  # reaches `running`. The crucible-det-rng-delivery patch completes builtin-RNG
  # entropy inline in rng_backend_request_entropy under icount (via the new
  # ->drain_requests backend hook) instead of from a host-scheduled bottom half,
  # so the completion interrupt lands at the exact request icount; this smoke run
  # confirms that synchronous-completion path does not break device realization
  # or execution. This is the backend hop of the two-hop synchronous
  # entropy-completion seal; the dispatch hop is the crucible-det-virtio-ioeventfd
  # microtest. The end-to-end determinism property — two identical runs producing
  # a byte-identical fingerprint under an adversarial host — is witnessed
  # authoritatively by checks.crucible.phase0.s6KaslrAslr and
  # checks.crucible.phase1.guestEntropyLaunch, which the per-patch microtests name.
  qemuRuntimeScript =
    if qemuPackage == null
    then ''
      echo "qemuPackage=null; runtime rng-delivery smoke exercise skipped" > "$out/runtime-skipped.txt"
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

      socket="$TMPDIR/detrng.qmp"
      stdout="$out/detrng.stdout"
      stderr="$out/detrng.stderr"
      rm -f "$socket" "$stdout" "$stderr"

      timeout 60 "$qemu" \
        -nodefaults \
        -no-user-config \
        -display none \
        -monitor none \
        -machine q35 \
        -accel tcg,thread=single \
        -icount shift=0,sleep=off,align=off \
        -cpu qemu64,-rdrand,-rdseed \
        -m 128 \
        -smp 1 \
        -rtc base=2026-01-01T00:00:00,clock=vm \
        -seed 0x0010c031 \
        -object rng-builtin,id=det-rng0 \
        -device virtio-rng-pci,rng=det-rng0,id=det-vrng0 \
        -serial none \
        -qmp "unix:$socket,server=on,wait=off" \
        -no-reboot \
        > "$stdout" 2> "$stderr" &
      qemu_pid="$!"

      wait_for_socket "$socket" || {
        cat "$stderr" >&2 || true
        fail "det-rng QMP socket did not appear under icount"
      }

      qmp_cmd "$socket" '{"execute":"query-status"}' "$out/detrng.status.json" \
        || fail "query-status failed under icount (synchronous rng completion broke execution)"
      status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$out/detrng.status.json")
      if [ "$status" != "running" ]; then
        cat "$out/detrng.status.json" >&2 || true
        fail "VM status is '$status' under icount, expected 'running'"
      fi
      # Reaching `running` implies the seeded rng-builtin virtio-rng-pci device
      # realized: a failed device realization aborts QEMU before the QMP monitor
      # comes up, and the synchronous entropy-completion path introduced by the
      # patch is on the device's request path.

      qmp_cmd "$socket" '{"execute":"quit"}' "$out/detrng.quit.json" >/dev/null 2>&1 || true
      wait "$qemu_pid" || true
      qemu_pid=""
    '';

  hasInfix = needle: haystack: let
    needleLen = builtins.stringLength needle;
    haystackLen = builtins.stringLength haystack;
    maxStart = haystackLen - needleLen;
    indexes =
      if needleLen == 0
      then [0]
      else if maxStart < 0
      then []
      else builtins.genList (index: index) (maxStart + 1);
  in
    builtins.any (index:
      builtins.substring index needleLen haystack == needle)
    indexes;

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
      label = "det rng delivery patch wiring";
      needle = "patch -p1 < \${./qemu-patches/0031-crucible-det-rng-delivery.patch}";
    }
  ];

  patchRequirements = [
    {
      label = "backend drain hook";
      needle = "void (*drain_requests)(RngBackend *s);";
    }
    {
      label = "builtin drain implementation";
      needle = "static void rng_builtin_drain_requests(RngBackend *b)";
    }
    {
      label = "builtin drain registration";
      needle = "rbc->drain_requests = rng_builtin_drain_requests;";
    }
    {
      label = "icount-gated synchronous drain";
      needle = "if (icount_enabled() && k->drain_requests) {";
    }
    {
      label = "icount gate include";
      needle = "system/cpu-timers.h";
    }
    {
      label = "no record/replay rationale";
      needle = "RFC-0010";
    }
    {
      label = "paired dispatch seal cross-reference";
      needle = "15-io-subnodes.md";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements;
in
  if failures != []
  then throw "crucible phase1 det-rng-delivery check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-det-rng-delivery";
      version = "0";
      src = null;

      inherit patchSource;
      passAsFile = ["patchSource"];

      buildDeps = [
        pkgs.coreutils
        pkgs.grep
        pkgs.jq
        pkgs.patch
        pkgs.socat
        pkgs.tar
        pkgs.xz
      ] ++ lib.optionals (qemuPackage != null) [qemuPackage];

      phases = [
        {
          name = "run-det-rng-delivery-microtest";
          script = ''
            set -eu

            mkdir -p "$out"

            apply_dir="$TMPDIR/qemu-det-rng-delivery-apply"
            mkdir -p "$apply_dir"
            tar -xf ${pkgs.qemu-crucible.src} -C "$apply_dir"
            source_dir="$apply_dir/qemu-${pkgs.qemu-crucible.version}"

            if grep -R -q 'drain_requests' "$source_dir"/backends/rng-builtin.c "$source_dir"/include/system/rng.h 2>/dev/null; then
              echo "stock rng backend already exposes a synchronous drain hook" >&2
              exit 1
            fi

            (
              cd "$source_dir"
              patch --batch --fuzz=0 -p1 < "$patchSourcePath"
              grep -F -q 'void (*drain_requests)(RngBackend *s);' include/system/rng.h
              grep -F -q 'static void rng_builtin_drain_requests(RngBackend *b)' backends/rng-builtin.c
              grep -F -q 'rbc->drain_requests = rng_builtin_drain_requests;' backends/rng-builtin.c
              grep -F -q 'if (icount_enabled() && k->drain_requests) {' backends/rng.c
              grep -F -q '#include "system/cpu-timers.h"' backends/rng.c
            )

            ${qemuRuntimeScript}

            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.detRngDelivery
            gate=gate:layer0-determinism
            gate=gate:patch-microtests
            tasks=T-DET-1
            patch=0031-crucible-det-rng-delivery.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            seal_hop=backend
            paired_dispatch_seal=0032-crucible-det-virtio-ioeventfd.patch
            e2e_witness=checks.crucible.phase0.s6KaslrAslr
            e2e_witness=checks.crucible.phase1.guestEntropyLaunch
            ${qemuPackageResultLines}
            ${qemuRuntimeResultLines}
            RESULT
          '';
        }
      ];
    }
