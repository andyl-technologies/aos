# Exercises main-loop fault installation against a previously cached CPU1 TB.
{
  pkgs,
  lib,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  series = import ../../pkgs/emulation/qemu-patches/_series.nix;
  repository = import ./_qemu-patch-stack-repository.nix {
    inherit pkgs lib qemuPackage;
  };
  directFlushQemu = pkgs.callPackage ../../pkgs/emulation/qemu.nix {
    pname = "qemu-crucible-direct-instruction-flush-negative";
    enablePlugins = true;
    applyCruciblePatches = true;
    enableLinuxUser = false;
    testOnlyNonDistributable = true;
    testOnlyPostPatch = ./fixtures/qemu-direct-instruction-flush.patch;
  };
in
  pkgs.mkDerivation {
    pname = "crucible-phase2-qemu-queued-invalidation";
    version = "0";
    src = null;
    buildDeps = [
      pkgs.coreutils
      pkgs.git
      pkgs.glib.dev
      pkgs.grep
      pkgs.llvm
      pkgs.pkg-config
      pkgs.python3
      qemuPackage
      directFlushQemu
    ];
    phases = [
      {
        name = "verify-exclusive-tb-invalidation";
        script = ''
          set -eu
          mkdir -p "$out"
          ulimit -c 0

          for source_file in \
            tests/tcg/plugins/crucible-instruction.c \
            tests/tcg/plugins/run-crucible-smp-invalidation.py \
            tests/tcg/aarch64/system/crucible-smp-invalidation.S \
            tests/tcg/aarch64/system/kernel.ld; do
            git --git-dir=${repository}/repo.git \
              show ${series.patchBranchHeadCommit}:"$source_file" \
              > "$(basename "$source_file")"
          done

          "$CC" -shared -fPIC \
            -I${qemuPackage}/include -I${qemuPackage}/include/qemu \
            $(pkg-config --cflags glib-2.0) crucible-instruction.c \
            -o instruction.so $(pkg-config --libs glib-2.0) \
            -Wl,-rpath,${pkgs.glib}/lib
          ${pkgs.llvm}/bin/clang --target=aarch64-none-elf \
            -c crucible-smp-invalidation.S -o guest.o
          ${pkgs.llvm}/bin/ld.lld -T kernel.ld guest.o -o guest.elf

          ${pkgs.python3}/bin/python3 run-crucible-smp-invalidation.py \
            --qemu ${qemuPackage}/bin/qemu-system-aarch64 \
            --guest guest.elf --plugin "$PWD/instruction.so" \
            > "$out/queued-flush.log" 2>&1
          cat "$out/queued-flush.log"
          grep -Fxq 'CRUCIBLE_INSTRUCTION_SMP_FLUSH_LIVE_PASS flushes=1' \
            "$out/queued-flush.log"

          if ${pkgs.python3}/bin/python3 run-crucible-smp-invalidation.py \
            --qemu ${directFlushQemu}/bin/qemu-system-aarch64 \
            --guest guest.elf --plugin "$PWD/instruction.so" \
            > "$out/direct-flush.log" 2>&1; then
            echo 'direct-flush negative control unexpectedly passed' >&2
            exit 1
          fi
          cat "$out/direct-flush.log"
          grep -Fq 'tb_flush__exclusive_or_serial: Assertion' \
            "$out/direct-flush.log"

          cat > "$out/result" <<'RESULT'
          PASS
          main_loop_instruction_installation=true
          cpu1_cached_instruction_retranslated=true
          global_flushes=1
          direct_flush_negative_asserts=true
          RESULT
        '';
      }
    ];
  }
