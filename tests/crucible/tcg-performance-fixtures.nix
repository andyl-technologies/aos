{
  pkgs,
  qemuPackage ? pkgs.qemu-crucible,
}: let
  native = qemuPackage.passthru.atomicPatch;
  nativePatch = ../../pkgs/emulation/qemu-patches + "/${native.file}";
in
  assert builtins.hashFile "sha256" nativePatch == native.sha256;
    pkgs.mkDerivation {
      pname = "crucible-tcg-performance-fixtures";
      version = "0";
      src = null;

      buildDeps = [pkgs.binutils pkgs.coreutils pkgs.git pkgs.glib.dev];

      phases = [
        {
          name = "build-deterministic-performance-witness";
          script = ''
            set -eu
            mkdir -p "$out"

            cat > bios.ld <<'LINKER'
            OUTPUT_FORMAT(elf32-i386)
            ENTRY(_start)
            SECTIONS {
              . = 0;
              .text : { *(.text*) }
              . = 0xfff0;
              .reset : { *(.reset*) }
              . = 0xffff;
              .last : { BYTE(0) }
              /DISCARD/ : { *(.note*) *(.comment*) }
            }
            LINKER
            build_bios() {
              bios_name="$1"
              shift
              as --32 "$@" ${./tcg-performance-bios.S} -o bios.o
              ld -m elf_i386 -nostdlib -T bios.ld -o bios.elf bios.o
              objcopy -O binary bios.elf "$out/$bios_name"
              test "$(wc -c < "$out/$bios_name")" -eq 65536
            }

            build_bios bios.bin
            build_bios io-bios.bin --defsym IO_POST=1

            # The component owner comes from the exact corresponding native patch;
            # the fixture does not maintain another copy of its admission policy.
            mkdir native-source
            (
              cd native-source
              git apply --include=tests/tcg/plugins/crucible-resident-ram.h ${nativePatch}
            )
            cp native-source/tests/tcg/plugins/crucible-resident-ram.h .

            cc -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-parameter \
              -shared -fPIC -I. -I${qemuPackage}/include -I${qemuPackage}/include/qemu \
              -I${pkgs.glib.dev}/include/glib-2.0 \
              -I${pkgs.glib.dev}/lib/glib-2.0/include \
              ${./tcg-performance-plugin.c} -o "$out/plugin.so"
          '';
        }
      ];
    }
