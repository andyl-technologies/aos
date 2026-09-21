##! mozjpeg — JPEG encoder and decoder used by source-built Sharp/libvips.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  libpng,
  zlib,
}: let
  revision = "08265790774cd0714832c9e675522acbe5581437";
  version = "5.0.0-unstable-0826579";
  src = fetchurl {
    urls = ["https://github.com/mozilla/mozjpeg/archive/${revision}.tar.gz"];
    hash = "sha256-toAWe9XZr+vdV2oS+MSdLJBmo7ku+WorLF94KbhgD+U=";
  };
  fdctFix = fetchurl {
    urls = ["https://github.com/mozilla/mozjpeg/commit/f90668e0e4fb79c81e1f24a0ccc0e2090af761bf.patch"];
    hash = "sha256-pl+Hyt86YFLkTWMUyQb24okTUvgmRrim8Lj88sGJHnw=";
  };
in
  mkDerivation {
    pname = "mozjpeg";
    inherit version src;

    buildDeps = [buildPackages.cmake buildPackages.gnumake buildPackages.nasm buildPackages.patch];
    runtimeDeps = [libpng zlib];
    propagatedDeps = [libpng zlib];
    passthru.evidenceSources = [src fdctFix ./_mozjpeg/standard-profile-tests.patch];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd mozjpeg-${revision}
            # Match Sharp's upstream correction for SIMD transform overflow.
            patch -p1 < ${fdctFix}
            # These fixtures use the standard profile, as do the neighboring
            # compatibility tests. Keep their original checksum assertions.
            patch -p1 < ${./_mozjpeg/standard-profile-tests.patch}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" \
              -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DWITH_JPEG8=ON \
              -DREQUIRE_SIMD=ON \
              -DCMAKE_PREFIX_PATH="${libpng};${zlib}"
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
            mkdir -p "$out/share/licenses/mozjpeg"
            cp LICENSE.md README.ijg "$out/share/licenses/mozjpeg/"
          '';
        }
      ];

    meta = {
      description = "JPEG compression library with PNG input, SIMD, and TurboJPEG support";
      homepage = "https://github.com/mozilla/mozjpeg";
      license = "BSD-3-Clause AND IJG AND Zlib";
    };
  }
