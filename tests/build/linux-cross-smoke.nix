# Build-only smoke coverage for the Linux-hosted AArch64 GNU cross toolchain.
{pkgs}: let
  buildSystem = pkgs.stdenv.buildPlatform.system;
  targetSystem = "aarch64-linux";
  cross = import ../.. {
    system = buildSystem;
    crossSystem = targetSystem;
  };
  crucible = cross.pkgs.crucible;
  glibcLocales = cross.pkgs.glibc-locales;
  passt = cross.pkgs.passt;
  systemImageFixture = cross.pkgs.aos-system-image-e2e-fixture;
  compilerRuntimeDirectory = "${cross.stdenv.gcc}/${cross.stdenv.hostPlatform.config}/lib64";
in
  assert cross.stdenv.isCross;
  assert cross.stdenv.system == targetSystem;
  assert cross.stdenv.cc.system == buildSystem;
  assert cross.stdenv.gcc.system == buildSystem;
  assert cross.stdenv.hostPlatform.system == targetSystem;
  assert cross.stdenv.hostPlatform.pageSize == 4096;
  assert cross.buildPackages.rust.system == buildSystem;
  # Crucible's Rust, pkg-config, and protobuf executables are build tools even
  # when the suite's runtime artifacts target AArch64.
  assert crucible.platforms.host.system == targetSystem;
  assert crucible.system == buildSystem;
  # Locale data targets AArch64, but localedef must remain executable on the
  # build machine while consuming the target libc's matching i18n sources.
  assert glibcLocales.platforms.host.system == targetSystem;
  assert glibcLocales.system == buildSystem;
  assert builtins.elem (toString cross.buildPackages.glibc.bin) glibcLocales.nativeBuildInputs;
  assert !(builtins.elem (toString cross.pkgs.glibc.bin) glibcLocales.nativeBuildInputs);
  assert passt.platforms.host.system == targetSystem;
  assert passt.system == buildSystem;
  assert !(builtins.elem (toString cross.pkgs.glibc.bin) passt.nativeBuildInputs);
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

            test -f '${cross.pkgs.glibc.bin}/share/i18n/charmaps/UTF-8.gz'
            test -f '${cross.pkgs.glibc.bin}/share/i18n/locales/C'

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
