{
  pkgs,
  iterations ? 50000000,
}:
assert iterations > 0 && iterations <= 4294967295;
  pkgs.mkDerivation {
    pname = "crucible-tcg-finite-rom";
    version = "0";
    src = null;

    buildDeps = [pkgs.binutils pkgs.coreutils pkgs.python3];

    phases = [
      {
        name = "assemble-and-qualify-fixed-work";
        script = ''
          set -eu
          mkdir -p "$out"
          cat > rom.ld <<'LINKER'
          OUTPUT_FORMAT(elf32-i386)
          ENTRY(_start)
          SECTIONS {
            . = 0xf0000;
            .text : { *(.text*) }
            . = 0xffff0;
            .reset : { *(.reset*) }
            . = 0xfffff;
            .last : { BYTE(0) }
            /DISCARD/ : { *(.note*) *(.comment*) }
          }
          LINKER
          as --32 --defsym ITERATIONS=${toString iterations} \
            ${./tcg-finite-rom.S} -o rom.o
          ld -m elf_i386 -nostdlib -T rom.ld rom.o -o "$out/rom.elf"
          objcopy -O binary "$out/rom.elf" "$out/rom.bin"
          objdump -D -Mintel,i8086 "$out/rom.elf" > "$out/disassembly-16.txt"
          objdump -D -Mintel,i386 "$out/rom.elf" > "$out/disassembly-32.txt"
          python3 ${./tcg-finite-rom-test.py}
          python3 ${./tcg-finite-rom-test.py} --elf "$out/rom.elf" \
            --rom "$out/rom.bin" --nm "$(command -v nm)" \
            --iterations ${toString iterations} --manifest "$out/manifest.json"
        '';
      }
    ];
  }
