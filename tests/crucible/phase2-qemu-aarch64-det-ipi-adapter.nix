{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import (patchDir + "/_atomic-patch.nix");
  patchSource = builtins.readFile (patchDir + "/${atomicPatch.file}");

  inherit (import ./_lib.nix {inherit lib;}) hasInfix;

  failures =
    lib.optionals (!(hasInfix "crucible_sim_det_ipi_drain_pending" patchSource)) [
      "${atomicPatch.file}: AArch64 deterministic IPI drain adapter is absent"
    ]
    ++ lib.optionals (!(hasInfix "crucible_sim_det_ipi_deliver_commanded" patchSource)) [
      "${atomicPatch.file}: AArch64 commanded IPI adapter is absent"
    ]
    ++ lib.optionals (!(hasInfix "cpu_interrupt(dst_cpu, CPU_INTERRUPT_HARD)" patchSource)) [
      "${atomicPatch.file}: AArch64 hard-interrupt delivery is absent"
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

            if grep -q 'crucible_sim_det_ipi_deliver_commanded' target/arm/cpu.c; then
              fail "stock QEMU unexpectedly exposes the AArch64 IPI adapter"
            fi

            patch --batch --fuzz=0 -p1 < "${patchDir}/${atomicPatch.file}" > /dev/null
            grep -q 'crucible_sim_det_ipi_drain_pending' target/arm/cpu.c
            grep -q 'crucible_sim_det_ipi_deliver_commanded' target/arm/cpu.c
            grep -q 'cpu_interrupt(dst_cpu, CPU_INTERRUPT_HARD)' target/arm/cpu.c

            cat > "$out/result" <<'RESULT'
            PASS
            gate=gate:patch-microtests
            atomic_patch=${atomicPatch.file}
            patched_fixture_exercised=true
            stock_negative_control=true
            stock_tree_negative_control=true
            aarch64_rr_drain_adapter=true
            aarch64_commanded_ipi_adapter=true
            qemu_package=${qemuPackage}
            qemu_package_version=${qemuPackage.version}
            RESULT
          '';
        }
      ];
    }
