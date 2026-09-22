##! highway — Portable SIMD primitives for image processing.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "1.4.0";
  needsAssembler = !stdenv.isCross && stdenv.hostPlatform.isLinux && stdenv.hostPlatform.isx86_64;
  assembler = import ./_highway-assembler.nix {inherit buildPackages fetchurl;};
  src = fetchurl {
    urls = ["https://github.com/google/highway/archive/${version}.tar.gz"];
    hash = "0g2599v8z8w107qh78r6hx1x8ic0a25pdv9cwlx6bfr4jnn428p7";
  };
in
  mkDerivation {
    pname = "highway";
    inherit version src;

    buildDeps = [buildPackages.cmake buildPackages.gnumake];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd highway-${version}
            # GCC 16.2 still exhibits the ARM poly-constant cloning bug from
            # upstream issue #2813. Extend the existing test-only workaround.
            sed -i 's/HWY_COMPILER_GCC_ACTUAL < 1600/HWY_COMPILER_GCC_ACTUAL < 1700/' hwy/tests/test_util.h
          '';
        }
        {
          name = "configure";
          script = ''
            ${
              if needsAssembler
              then ''
                # GCC's Highway dispatch targets include AVX10.2, which the
                # bootstrap assembler predates. Preserve the wrapper's libc,
                # linker, and hardening flags while preferring the newer as.
                mkdir compiler
                for language in CC CXX; do
                  eval "compiler=\$$language"
                  sed 's| -B| -B${assembler}/bin/ -B|' "$compiler" > "compiler/$language"
                  chmod +x "compiler/$language"
                done
                export CC="$PWD/compiler/CC" CXX="$PWD/compiler/CXX"
              ''
              else ""
            }
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DBUILD_SHARED_LIBS=ON \
              -DHWY_TEST_STANDALONE=ON
          '';
        }
        {
          name = "build";
          script = ''
            cmake --build build --parallel "$NIX_BUILD_CORES"
          '';
        }
      ]
      ++ (
        if stdenv.isCross
        then []
        else [
          {
            name = "check";
            script = ''
              ctest --test-dir build --output-on-failure --parallel "$NIX_BUILD_CORES"
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            cmake --install build
            mkdir -p "$out/share/licenses/highway"
            cp LICENSE "$out/share/licenses/highway/"
          '';
        }
      ];

    meta = {
      description = "Portable SIMD library with image-processing contributions and examples";
      homepage = "https://github.com/google/highway";
      license = "Apache-2.0";
    };
  }
