{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
  referenceQemu ? pkgs.qemu-crucible-reference,
  attrPath ? "checks.crucible.phase2.qemuHardwareErrorFaults",
  taskIds ? ["T-QEMU-0054"],
  campaignComposition ? null,
  testing ? import ../../lib/testing {inherit pkgs lib;},
}: let
  patchDir = ../../pkgs/emulation/qemu-patches;
  atomicPatch = import ../../pkgs/emulation/qemu-patches/_atomic-patch.nix;
  patchSource = builtins.readFile (patchDir + "/${atomicPatch.file}");
  taskList = builtins.concatStringsSep "," taskIds;
  inherit (import ./_lib.nix {inherit lib;}) failuresFor forbiddenFor;

  failures =
    failuresFor "pkgs/emulation/qemu-patches/${atomicPatch.file}" patchSource [
      {
        label = "realized hardware-error manifest";
        needle = "qemu_plugin_crucible_fault_hardware_error_manifest";
      }
      {
        label = "x86 MCA bank mutation";
        needle = "x86_cpu_write_fault_bank";
      }
      {
        label = "AArch64 RAS pending state";
        needle = "crucible_hardware_error.synchronous_pending";
      }
      {
        label = "ACPI GHES CPER memory record";
        needle = "acpi_ghes_memory_error_record";
      }
      {
        label = "architecture error VMState building block";
        needle = "vmstate_crucible_hardware_error";
      }
      {
        label = "exact prior and resulting state evidence";
        needle = "cpu_read_fault_hardware_error_state";
      }
    ]
    ++ forbiddenFor "pkgs/emulation/qemu-patches/${atomicPatch.file}" patchSource [
      {
        label = "test-double hardware backend";
        needle = "CRUCIBLE_TEST_DOUBLE";
      }
    ];
  runtimeInputs = [
    pkgs.binutils
    pkgs.coreutils
    pkgs.glib
    pkgs.glib.dev
    pkgs.grep
    pkgs.llvm
    pkgs.pkg-config
    qemuPackage
    referenceQemu
  ];
  campaignRuntimeInputs = runtimeInputs ++ [pkgs.gcc];
  campaignRuntimeEnvironment = {
    CC = "${pkgs.gcc}/bin/cc";
    PKG_CONFIG_PATH = "${pkgs.glib.dev}/lib/pkgconfig";
  };
  campaignRuntimeClosures =
    map (
      source: builtins.toFile (builtins.baseNameOf source) (builtins.readFile source)
    ) [
      ./phase2-qemu-hardware-error-manifest.c
      ./phase2-qemu-fault-guest.S
      ./phase2-qemu-fault-guest-aarch64.S
      ./phase2-qemu-fault-guest.ld
      ./phase2-qemu-fault-guest-aarch64.ld
    ];
  executorPhases = [
    {
      name = "build-live-probe";
      script = ''
        set -eu
        "$CC" -shared -fPIC -Wall -Wextra -Werror \
          -I${qemuPackage}/include/qemu \
          -I${qemuPackage}/include \
          -I${./.} \
          $(pkg-config --cflags glib-2.0) \
          ${./phase2-qemu-hardware-error-manifest.c} \
          -o crucible-hardware-error-manifest.so \
          $(pkg-config --libs glib-2.0)
        as --32 --defsym CRUCIBLE_ENABLE_MCA=1 \
          ${./phase2-qemu-fault-guest.S} \
          -o hardware-error-guest-x86.o
        ld -m elf_i386 -T ${./phase2-qemu-fault-guest.ld} \
          hardware-error-guest-x86.o -o hardware-error-guest-x86.elf
        ${pkgs.llvm}/bin/clang --target=aarch64-none-elf \
          -c ${./phase2-qemu-fault-guest-aarch64.S} \
          -o hardware-error-guest-aarch64.o
        ${pkgs.llvm}/bin/ld.lld \
          -T ${./phase2-qemu-fault-guest-aarch64.ld} \
          hardware-error-guest-aarch64.o \
          -o hardware-error-guest-aarch64.elf
      '';
    }
    {
      name = "run-live-hardware-error-mutations";
      script = ''
        set -eu
        mkdir -p logs
        run_mutation() {
          architecture="$1"
          architecture_id="$2"
          qemu_binary="$3"
          machine_args="$4"
          guest="$5"
          mode="$6"
          set +e
          timeout 30 "$qemu_binary" \
            $machine_args \
            -accel sim \
            -icount shift=0,rr_switch_quantum=256 \
            -smp 1 \
            -nographic \
            -no-reboot \
            -serial none \
            -monitor none \
            -kernel "$guest" \
            -plugin "$PWD/crucible-hardware-error-manifest.so,architecture=$architecture_id,mode=$mode" \
            > "logs/$architecture-$mode.log" 2>&1
          status=$?
          set -e
          cat "logs/$architecture-$mode.log"
          test "$status" -eq 0
          case "$mode:$architecture_id" in
            ecc:*) mode_name=corrected-ecc ;;
            architecture:2) mode_name=x86-mca ;;
            architecture:3) mode_name=aarch64-ras ;;
          esac
          grep -Fq \
            "CRUCIBLE_HARDWARE_ERROR_MUTATION_LIVE_PASS architecture=$architecture_id mode=$mode_name" \
            "logs/$architecture-$mode.log"
          ! grep -Fq CRUCIBLE_HARDWARE_ERROR_MUTATION_LIVE_FAIL \
            "logs/$architecture-$mode.log"
        }
        run_mutation x86_64 2 \
          ${qemuPackage}/bin/qemu-system-x86_64 \
          '-machine pc -cpu max -m 64M' \
          hardware-error-guest-x86.elf ecc
        for mode in architecture; do
          run_mutation x86_64 2 \
            ${qemuPackage}/bin/qemu-system-x86_64 \
            '-machine pc -cpu max -m 64M' \
            hardware-error-guest-x86.elf "$mode"
          run_mutation aarch64 3 \
            ${qemuPackage}/bin/qemu-system-aarch64 \
            '-machine virt,gic-version=3 -cpu max -m 64M' \
            hardware-error-guest-aarch64.elf "$mode"
        done

        set +e
        timeout 5 ${referenceQemu}/bin/qemu-system-x86_64 \
          -machine pc -cpu max -m 64M \
          -accel tcg \
          -icount shift=0 \
          -smp 1 \
          -nographic \
          -no-reboot \
          -serial none \
          -monitor none \
          -kernel hardware-error-guest-x86.elf \
          -plugin "$PWD/crucible-hardware-error-manifest.so,architecture=2,mode=ecc" \
          > logs/stock.log 2>&1
        stock_status=$?
        set -e
        cat logs/stock.log
        test "$stock_status" -ne 0
        test "$stock_status" -ne 124
        ! grep -q CRUCIBLE_HARDWARE_ERROR_MUTATION_LIVE_PASS logs/stock.log
        ! nm -D --defined-only \
          ${referenceQemu}/bin/qemu-system-x86_64 \
          | grep -q qemu_plugin_crucible_fault_hardware_error_manifest

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
          printf 'live_mutations=corrected-ecc,x86-mca,aarch64-ras\n'
          printf 'production_effect_row=cpu.exception|x86-mca-aarch64-ras|gate:patch-microtests|actual-patched-qemu|architecture-error-acknowledgement\n'
          printf 'production_effect_row=memory.ecc_event|corrected-ecc|gate:patch-microtests|actual-patched-qemu|platform-record+corrected-data\n'
        } > "$out/result"
      '';
    }
  ];
  runtimeScript = ''
    cd "$TMPDIR"
    ${builtins.concatStringsSep "\n" (map (phase: phase.script) executorPhases)}
  '';
  authoritativeGate = pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-hardware-error-faults";
    version = "0";
    src = null;
    buildDeps = runtimeInputs;
    phases = executorPhases;
  };
in
  if failures != []
  then throw "Crucible QEMU hardware-error microtest failed:\n${builtins.concatStringsSep "\n" failures}"
  else if campaignComposition != null
  then
    import ./phase9-campaign-mode-system-gate.nix {
      inherit pkgs lib testing runtimeScript;
      inherit (campaignComposition) mode system;
      gateName = "gate:patch-microtests";
      authoritativeAttr = attrPath;
      executionFamily = "qemu-runtime";
      name = "qemu-hardware-error-faults";
      runtimeInputs = campaignRuntimeInputs;
      runtimeEnvironment = campaignRuntimeEnvironment;
      runtimeClosures = campaignRuntimeClosures;
      timeout = 3600;
      memoryMiB = 4096;
      varSizeMiB = 8192;
    }
  else authoritativeGate
