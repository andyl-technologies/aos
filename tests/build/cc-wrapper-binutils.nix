##! Proves compiler wrappers use their declared assembler and linker.
{pkgs}: let
  tracedBinutils = pkgs.mkDerivation {
    pname = "aos-traced-binutils";
    version = "1";
    src = null;
    runtimeDeps = [pkgs.bash pkgs.binutils];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          for tool in as ld; do
            cat > "$out/bin/$tool" <<EOF
          #!${pkgs.bash}/bin/bash
          set -eu
          printf '%s\n' '$tool' >> "\$AOS_WRAPPER_TRACE"
          exec ${pkgs.binutils}/bin/$tool "\$@"
          EOF
            chmod 755 "$out/bin/$tool"
          done
        '';
      }
    ];
  };
  wrapper = import ../../stdenv/cc-wrapper.nix {
    shell = "${pkgs.bash}/bin/bash";
    inherit (pkgs) coreutils;
    inherit (pkgs.stdenv) hostPlatform;
    cc = pkgs.stdenv.gcc;
    libc = pkgs.stdenv.glibc;
    binutils_ = tracedBinutils;
    staticDefault = true;
  };
in
  pkgs.mkDerivation {
    pname = "aos-cc-wrapper-binutils";
    version = "1";
    src = null;
    phases = [
      {
        name = "check";
        script = ''
          cat > probe.c <<'SOURCE'
          #include <stdio.h>

          int main(void)
          {
              return puts("declared binutils executed") < 0;
          }
          SOURCE

          for driver in gcc g++ cc c++; do
            export AOS_WRAPPER_TRACE="$PWD/$driver.trace"
            for tool in as ld; do
              selected=$(${wrapper}/bin/$driver -print-prog-name=$tool)
              if [ "$selected" != "${tracedBinutils}/bin/$tool" ]; then
                echo "$driver selected $selected; expected ${tracedBinutils}/bin/$tool" >&2
                exit 1
              fi
            done

            ${wrapper}/bin/$driver probe.c -o "$driver-probe"
            "./$driver-probe"
            grep -Fxq as "$AOS_WRAPPER_TRACE"
            grep -Fxq ld "$AOS_WRAPPER_TRACE"
          done

          mkdir -p "$out"
          echo PASS > "$out/result"
        '';
      }
    ];
  }
