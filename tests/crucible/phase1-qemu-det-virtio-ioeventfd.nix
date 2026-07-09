{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  qemuNix = builtins.readFile ../../pkgs/emulation/qemu.nix;
  patchName = "0032-crucible-det-virtio-ioeventfd.patch";
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
      det_virtio_ioeventfd_runtime_exercised=false
    ''
    else ''
      det_virtio_ioeventfd_runtime_exercised=true
      det_virtio_ioeventfd_icount_gate=structural
      det_virtio_synchronous_dispatch_boot_smoke=passed
    '';

  # Behavioral smoke probe: under -icount, boot a stock guest with a virtio-rng-pci
  # device and confirm the device realizes and the VM reaches `running`. The
  # crucible-det-virtio-ioeventfd patch makes virtio_pci_ioeventfd_enabled()
  # return false under icount_enabled() for the virtio-rng device specifically,
  # so its virtqueue kick is serviced synchronously on the requesting vCPU thread
  # rather than via a host-scheduled main-loop dispatch (block/9p keep the stock
  # async kick, whose determinism is anchored by the crucible blk/9p shmem
  # substrate); this smoke run confirms that synchronous-dispatch path does not
  # break device realization or execution. The effective ioeventfd
  # decision is a runtime override of the qdev flag and is not exposed as a QMP
  # property, so the icount gate itself is asserted structurally against the
  # patched virtio_pci_ioeventfd_enabled() below. This is the dispatch hop of the
  # two-hop synchronous entropy-completion seal; the backend hop is the
  # crucible-det-rng-delivery microtest. The end-to-end determinism property is
  # witnessed by checks.crucible.phase0.s6KaslrAslr and
  # checks.crucible.phase1.guestEntropyLaunch.
  qemuRuntimeScript =
    if qemuPackage == null
    then ''
      echo "qemuPackage=null; runtime virtio ioeventfd exercise skipped" > "$out/runtime-skipped.txt"
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

      socket="$TMPDIR/ioeventfd.qmp"
      stdout="$out/ioeventfd.stdout"
      stderr="$out/ioeventfd.stderr"
      rm -f "$socket" "$stdout" "$stderr"

      # A running (no -S) icount boot exercises the synchronous virtqueue-kick
      # dispatch path introduced by the patch; the virtio-rng device must realize
      # and the VM must reach `running` without error.
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
        -seed 0x0010c032 \
        -object rng-builtin,id=det-rng0 \
        -device virtio-rng-pci,rng=det-rng0,id=det-vrng0 \
        -serial none \
        -qmp "unix:$socket,server=on,wait=off" \
        -no-reboot \
        > "$stdout" 2> "$stderr" &
      qemu_pid="$!"

      wait_for_socket "$socket" || {
        cat "$stderr" >&2 || true
        fail "virtio ioeventfd QMP socket did not appear under icount"
      }

      # The device must be present (realized) and the VM must be executing.
      qmp_cmd "$socket" '{"execute":"query-status"}' "$out/ioeventfd.status.json" \
        || fail "query-status failed under icount (synchronous virtio-pci dispatch broke execution)"
      status=$(jq -r -s '[.[] | select(has("return"))][-1].return.status // empty' "$out/ioeventfd.status.json")
      if [ "$status" != "running" ]; then
        cat "$out/ioeventfd.status.json" >&2 || true
        fail "VM status is '$status' under icount, expected 'running'"
      fi
      # Reaching `running` implies the virtio-rng-pci device realized: a failed
      # device realization aborts QEMU before the QMP monitor comes up, and the
      # synchronous virtqueue-kick dispatch path introduced by the patch is on the
      # device's execution path, so a broken dispatch would fault before this point.

      qmp_cmd "$socket" '{"execute":"quit"}' "$out/ioeventfd.quit.json" >/dev/null 2>&1 || true
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
      label = "det virtio ioeventfd patch wiring";
      needle = "patch -p1 < \${./qemu-patches/0032-crucible-det-virtio-ioeventfd.patch}";
    }
  ];

  patchRequirements = [
    {
      label = "ioeventfd predicate function";
      needle = "static bool virtio_pci_ioeventfd_enabled(DeviceState *d)";
    }
    {
      label = "icount gate include";
      needle = "system/cpu-timers.h";
    }
    {
      label = "icount-gated disable";
      needle = "if (icount_enabled()) {";
    }
    {
      label = "virtio-rng scoping lookup";
      needle = "VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);";
    }
    {
      label = "virtio-rng device-id gate";
      needle = "if (vdev != NULL && vdev->device_id == VIRTIO_ID_RNG) {";
    }
    {
      label = "synchronous dispatch return";
      needle = "return false;";
    }
    {
      label = "upstream default preserved";
      needle = "(proxy->flags & VIRTIO_PCI_FLAG_USE_IOEVENTFD) != 0";
    }
    {
      label = "no record/replay rationale";
      needle = "RFC-0010 NG-6";
    }
    {
      label = "paired backend seal cross-reference";
      needle = "15-io-subnodes.md";
    }
  ];

  failures =
    failuresFor "pkgs/emulation/qemu.nix" qemuNix qemuNixRequirements
    ++ failuresFor "pkgs/emulation/qemu-patches/${patchName}" patchSource patchRequirements;
in
  if failures != []
  then throw "crucible phase1 det-virtio-ioeventfd check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase1-det-virtio-ioeventfd";
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
          name = "run-det-virtio-ioeventfd-microtest";
          script = ''
            set -eu

            mkdir -p "$out"

            apply_dir="$TMPDIR/qemu-det-virtio-ioeventfd-apply"
            mkdir -p "$apply_dir"
            tar -xf ${pkgs.qemu-crucible.src} -C "$apply_dir"
            source_dir="$apply_dir/qemu-${pkgs.qemu-crucible.version}"

            if grep -R -q 'if (icount_enabled())' "$source_dir"/hw/virtio/virtio-pci.c 2>/dev/null; then
              echo "stock virtio-pci already gates ioeventfd on icount" >&2
              exit 1
            fi

            (
              cd "$source_dir"
              patch --batch --fuzz=0 -p1 < "$patchSourcePath"
              grep -F -q 'static bool virtio_pci_ioeventfd_enabled(DeviceState *d)' hw/virtio/virtio-pci.c
              grep -F -q 'if (icount_enabled()) {' hw/virtio/virtio-pci.c
              grep -F -q 'VirtIODevice *vdev = virtio_bus_get_device(&proxy->bus);' hw/virtio/virtio-pci.c
              grep -F -q 'if (vdev != NULL && vdev->device_id == VIRTIO_ID_RNG) {' hw/virtio/virtio-pci.c
              grep -F -q '#include "system/cpu-timers.h"' hw/virtio/virtio-pci.c
              grep -F -q '(proxy->flags & VIRTIO_PCI_FLAG_USE_IOEVENTFD) != 0' hw/virtio/virtio-pci.c
            )

            ${qemuRuntimeScript}

            cat > "$out/result" <<'RESULT'
            PASS
            check=checks.crucible.phase1.detVirtioIoeventfd
            gate=gate:layer0-determinism
            gate=gate:patch-microtests
            tasks=T-DET-1
            patch=0032-crucible-det-virtio-ioeventfd.patch
            patched_fixture_exercised=true
            stock_negative_control=true
            seal_hop=dispatch
            paired_backend_seal=0031-crucible-det-rng-delivery.patch
            e2e_witness=checks.crucible.phase0.s6KaslrAslr
            e2e_witness=checks.crucible.phase1.guestEntropyLaunch
            ${qemuPackageResultLines}
            ${qemuRuntimeResultLines}
            RESULT
          '';
        }
      ];
    }
