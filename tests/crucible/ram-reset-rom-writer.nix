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
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${./ram-reset-rom-asset.py} \
          --rom reset.bin --elf reset.elf --objdump ${pkgs.binutils}/bin/objdump \
          --objcopy ${pkgs.binutils}/bin/objcopy \
          --output "$out"
        ${pkgs.python3}/bin/python3 ${./ram-reset-rom-test.py} \
          --elf reset.elf --checker ${./ram-reset-rom-asset.py} \
          --objdump ${pkgs.binutils}/bin/objdump \
          --objcopy ${pkgs.binutils}/bin/objcopy --nm ${pkgs.binutils}/bin/nm \
          > "$out/negative-controls.json"
        install -m 444 reset.elf reset.bin "$out/"
      '';
    }
  ];
}
