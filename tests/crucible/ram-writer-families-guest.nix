# Real CPU writer bytes, built and tested independently of the managed VM gate.
{pkgs}:
pkgs.mkDerivation {
  pname = "crucible-ram-writer-families-guest";
  version = "0";
  src = ./ram-writer-families-guest.c;

  buildDeps = [pkgs.binutils pkgs.coreutils pkgs.python3];
  phases = [
    {
      name = "build-and-check-writer-instructions";
      script = ''
        set -eu
        cc -std=c11 -O2 -g -Wall -Wextra -Werror -static "$src" -o writer-guest
        mkdir -p "$out"
        ${pkgs.python3}/bin/python3 ${./ram-writer-families-test.py} \
          --binary "$PWD/writer-guest" --objdump ${pkgs.binutils}/bin/objdump \
          --evidence-directory "$out"
        cc -std=c11 -O2 -g -Wall -Wextra -Werror -static \
          ${./ram-dma-writer-guest.c} -o dma-writer-guest
        ${pkgs.python3}/bin/python3 ${./ram-dma-writer-test.py} \
          --binary "$PWD/dma-writer-guest" > "$out/local-dma-control.json"
        install -m 555 writer-guest "$out/writer-guest"
        install -m 555 dma-writer-guest "$out/dma-writer-guest"
      '';
    }
  ];
}
