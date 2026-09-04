# Build-only smoke coverage for the Linux-hosted AArch64 GNU cross toolchain.
{pkgs}: let
  buildSystem = pkgs.stdenv.buildPlatform.system;
  targetSystem = "aarch64-linux";
  cross = import ../.. {
    system = buildSystem;
    crossSystem = targetSystem;
  };
  compilerRuntimeDirectory = "${cross.stdenv.gcc}/${cross.stdenv.hostPlatform.config}/lib64";
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
          '';
        }
      ];
    }
