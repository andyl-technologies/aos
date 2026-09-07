# Build-only smoke coverage for the Linux-hosted AArch64 GNU cross toolchain.
{pkgs}: let
  buildSystem = pkgs.stdenv.buildPlatform.system;
  targetSystem = "aarch64-linux";
  cross = import ../.. {
    system = buildSystem;
    crossSystem = targetSystem;
  };
  crucible = cross.pkgs.crucible;
  systemImageFixture = cross.pkgs.aos-system-image-e2e-fixture;
  compilerRuntimeDirectory = "${cross.stdenv.gcc}/${cross.stdenv.hostPlatform.config}/lib64";
in
  assert cross.stdenv.isCross;
  assert cross.stdenv.system == targetSystem;
  assert cross.stdenv.cc.system == buildSystem;
  assert cross.stdenv.gcc.system == buildSystem;
  assert cross.stdenv.hostPlatform.system == targetSystem;
  assert cross.buildPackages.rust.system == buildSystem;
  # Crucible's Rust, pkg-config, and protobuf executables are build tools even
  # when the suite's runtime artifacts target AArch64.
  assert crucible.platforms.host.system == targetSystem;
  assert crucible.system == buildSystem;
  # Evaluating the x86-specific image fixture under a target package set must
  # keep its data artifacts targeted while every derivation runs on the build
  # platform. This catches target data accidentally classified as buildDeps.
  assert systemImageFixture.platforms.host.system == targetSystem;
  assert systemImageFixture.system == buildSystem;
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
