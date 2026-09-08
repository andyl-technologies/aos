# Build-only smoke coverage for the Linux-hosted AArch64 GNU cross toolchain.
{pkgs}: let
  buildSystem = pkgs.stdenv.buildPlatform.system;
  targetSystem = "aarch64-linux";
  cross = import ../.. {
    system = buildSystem;
    crossSystem = targetSystem;
  };
  sharedPhases = import ../../stdenv/phases.nix;
  compilerRuntimeDirectory = "${cross.stdenv.gccRuntime}/lib";
  targetBash = cross.pkgs.bash;
  targetCoreutils = cross.pkgs.coreutils;
  customFixup = cross.pkgs.mkDerivation {
    pname = "linux-cross-custom-fixup-smoke";
    version = "0";
    src = null;
    phases = [
      {
        name = "fixup";
        script = ''
          printf 'package fixup preserved\n' > "$out/custom-fixup"
        '';
      }
    ];
  };
  sharedFixup = cross.pkgs.mkDerivation {
    pname = "linux-cross-shared-fixup-smoke";
    version = "0";
    src = null;
    phases = [
      {
        name = "build";
        script = ''
          mkdir -p "$out/bin"
          printf '%s\n' \
            '#include <stdio.h>' \
            'int main(void) { return puts("shared fixup") < 0; }' \
            > shared-fixup.c
          "$CC" -g shared-fixup.c -o "$out/bin/shared-fixup"
        '';
      }
      sharedPhases.fixupPhase
    ];
  };
in
  assert cross.stdenv.isCross;
  assert cross.stdenv.system == targetSystem;
  assert cross.stdenv.cc.system == buildSystem;
  assert cross.stdenv.gcc.system == buildSystem;
  assert cross.stdenv.hostPlatform.system == targetSystem;
  assert cross.buildPackages.rust.system == buildSystem;
    cross.stdenv.mkDerivation {
      pname = "linux-cross-smoke-aarch64";
      version = "0";
      src = null;

      phases = [
        {
          name = "build-and-verify";
          script = ''
            mkdir -p "$out/bin"

            printf '%s\n' \
              '#include <stdio.h>' \
              'int main(void) { return puts("aos Linux C cross smoke") < 0; }' \
              > smoke.c
            "$CC" smoke.c -o "$out/bin/aos-linux-c-smoke"

            printf '%s\n' \
              '#include <iostream>' \
              'int main() { std::cout << "aos Linux C++ cross smoke\\n"; return 0; }' \
              > smoke.cc
            "$CXX" smoke.cc -o "$out/bin/aos-linux-cxx-smoke"

            for executable in "$out/bin/aos-linux-c-smoke" "$out/bin/aos-linux-cxx-smoke"; do
              ${cross.stdenv.binutils}/bin/readelf -h "$executable" | grep -Fq 'Machine:                           AArch64'
              ${cross.stdenv.binutils}/bin/readelf -l "$executable" | grep -Fq '${cross.stdenv.glibc}/lib/${cross.stdenv.hostPlatform.dynamicLinker}'
            done

            ${cross.stdenv.binutils}/bin/readelf -d "$out/bin/aos-linux-cxx-smoke" | grep -Fq 'Shared library: [libstdc++.so.6]'
            ${cross.stdenv.binutils}/bin/readelf -d "$out/bin/aos-linux-cxx-smoke" | grep -Fq '${compilerRuntimeDirectory}'

            for package in ${targetBash} ${targetCoreutils}; do
              grep -Fx '${targetSystem}' "$package/nix-support/aos-target-platform"
            done
            for executable in ${targetBash}/bin/bash ${targetCoreutils}/bin/coreutils; do
              ${cross.stdenv.binutils}/bin/readelf -h "$executable" | grep -Fq 'Machine:                           AArch64'
            done

            grep -Fx 'package fixup preserved' ${customFixup}/custom-fixup
            shared_sections=$(${cross.stdenv.binutils}/bin/readelf -S ${sharedFixup}/bin/shared-fixup)
            case "$shared_sections" in
              *.debug_info*)
                echo 'shared cross fixup retained debug sections' >&2
                exit 1
                ;;
            esac
          '';
        }
      ];
    }
