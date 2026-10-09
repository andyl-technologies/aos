# A real PC reset ROM plus generic-loader RAM seed; no VM activation here.
{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-ram-reset-rom-writer";
  version = "0";
  src = ./ram-reset-rom-writer.S;

  buildDeps = [pkgs.binutils pkgs.coreutils pkgs.python3];
  phases = [
    {
      name = "assemble-reset-rom-writer";
      script = ''
        set -eu
        cc -m32 -c "$src" -o reset.o
        ld -m elf_i386 -T ${./x86-direct-reset.ld} reset.o -o reset.elf
        objcopy -O binary reset.elf reset.bin
        # Execute the ROM decoder bytes without linking 16-bit boot relocations.
        objcopy --only-section=.text.reply reset.o reply-decoder.o
        cc -m32 -Os -ffreestanding -fno-builtin -fno-pic -fno-pie \
          -fno-stack-protector -Wall -Wextra -Werror \
          -c ${./ram-reset-rom-reply-control.c} -o reply-control.o
        ld -m elf_i386 -e _start reply-control.o reply-decoder.o -o reply-control
        ./reply-control
        mkdir boot-include
        cp ${./ram-writer-boot-init.c} boot-include/ram-writer-boot-init.c
        cc -static -O2 -Wall -Wextra -Werror -I "$PWD/boot-include" \
          ${./ram-writer-boot-control.c} -o boot-wire-control
        ./boot-wire-control --wire wire-reference.bin
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${./ram-reset-rom-asset.py} \
          --rom reset.bin --elf reset.elf --objdump ${pkgs.binutils}/bin/objdump \
          --objcopy ${pkgs.binutils}/bin/objcopy \
          --nm ${pkgs.binutils}/bin/nm --wire-reference wire-reference.bin \
          --output "$out"
        ${pkgs.python3}/bin/python3 ${./ram-reset-rom-test.py} \
          --elf reset.elf --checker ${./ram-reset-rom-asset.py} \
          --objdump ${pkgs.binutils}/bin/objdump \
          --objcopy ${pkgs.binutils}/bin/objcopy --nm ${pkgs.binutils}/bin/nm \
          --ld ${pkgs.binutils}/bin/ld --reply-decoder-object reply-decoder.o \
          --reply-control-object reply-control.o \
          --wire-reference wire-reference.bin \
          > "$out/negative-controls.json"
        install -m 444 reset.elf reset.bin reply-control "$out/"
      '';
    }
  ];
}
