{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  patchName = "0042-crucible-aarch64-det-ipi-adapter.patch";
  series = import (patchDir + "/_series.nix");
  prefixPatchFiles =
    builtins.genList
    (index: builtins.elemAt series.patchFiles index)
    41;
  patchSource = builtins.readFile (patchDir + "/${patchName}");

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
    builtins.any
    (index: builtins.substring index needleLen haystack == needle)
    indexes;

  failures =
    lib.optionals (!(hasInfix "crucible_sim_det_ipi_drain_pending" patchSource)) [
      "${patchName}: AArch64 deterministic IPI drain adapter is absent"
    ]
    ++ lib.optionals (!(hasInfix "crucible_sim_det_ipi_deliver_commanded" patchSource)) [
      "${patchName}: AArch64 commanded IPI adapter is absent"
    ]
    ++ lib.optionals (!(hasInfix "cpu_interrupt(dst_cpu, CPU_INTERRUPT_HARD)" patchSource)) [
      "${patchName}: AArch64 hard-interrupt delivery is absent"
    ]
    ++ lib.optionals (
      builtins.length series.patchFiles
      <= 41
      || builtins.elemAt series.patchFiles 41 != patchName
    ) [
      "${patchName}: AArch64 adapter patch is not patch-series entry 42"
    ];
in
  if failures != []
  then throw "crucible phase2 QEMU AArch64 deterministic IPI adapter check failed:\n${builtins.concatStringsSep "\n" failures}"
  else
    pkgs.mkDerivation {
      pname = "crucible-phase2-qemu-aarch64-det-ipi-adapter";
      version = "0";
      src = null;

      buildDeps = [pkgs.coreutils pkgs.grep pkgs.patch pkgs.tar pkgs.xz];

      phases = [
        {
          name = "run-qemu-aarch64-det-ipi-adapter-microtest";
          script = ''
            set -eu

            fail() {
              echo "FAIL: $*" >&2
              exit 1
            }

            mkdir -p qemu-source "$out"
            tar -xf ${qemuPackage.src} -C qemu-source
            cd qemu-source/qemu-${qemuPackage.version}

            for patch in ${builtins.concatStringsSep " " prefixPatchFiles}; do
              patch --batch --fuzz=0 -p1 < "${patchDir}/$patch" > /dev/null
            done

            if grep -q 'crucible_sim_det_ipi_deliver_commanded' target/arm/cpu.c; then
              fail "prefix unexpectedly exposes the AArch64 IPI adapter"
            fi

            patch --batch --fuzz=0 -p1 < "${patchDir}/${patchName}" > /dev/null
            grep -q 'crucible_sim_det_ipi_drain_pending' target/arm/cpu.c
            grep -q 'crucible_sim_det_ipi_deliver_commanded' target/arm/cpu.c
            grep -q 'cpu_interrupt(dst_cpu, CPU_INTERRUPT_HARD)' target/arm/cpu.c
            grep -q 'qemu_plugin_crucible_maybe_fire_ipi_delivery_cb' target/arm/cpu.c

            cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:patch-microtests
            patch=0042-crucible-aarch64-det-ipi-adapter.patch
            prefix_negative_control=true
            aarch64_rr_drain_adapter=true
            aarch64_commanded_ipi_adapter=true
            aarch64_delivery_callback=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
