##! Checks Linux process emulation and the binfmt_misc preserved-argv contract.
{
  pkgs,
  qemu,
}: let
  cpu = pkgs.stdenv.hostPlatform.constraints.cpu;
  architecture =
    if cpu == "i686"
    then "i386"
    else cpu;
in
  pkgs.mkDerivation {
    pname = "aos-qemu-linux-user";
    version = "1";
    src = null;
    buildDeps = [qemu];
    phases = [
      {
        name = "check";
        script = ''
          cat > probe.c <<'SOURCE'
          #include <string.h>

          int main(int argc, char **argv)
          {
              return argc != 2 ||
                  strcmp(argv[0], "preserved argv zero") != 0 ||
                  strcmp(argv[1], "argument with spaces") != 0;
          }
          SOURCE
          cc -O2 probe.c -o probe

          ${qemu}/bin/qemu-${architecture} -0 'preserved argv zero' \
            "$PWD/probe" 'argument with spaces'
          ${qemu}/bin/qemu-${architecture}-binfmt-P \
            "$PWD/probe" 'preserved argv zero' 'argument with spaces'
          if ${qemu}/bin/qemu-${architecture}-binfmt-P "$PWD/probe"; then
            echo 'binfmt interpreter accepted a missing original argv[0]' >&2
            exit 1
          fi

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
