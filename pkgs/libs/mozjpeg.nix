##! mozjpeg — JPEG encoder and decoder used by source-built Sharp/libvips.
{
  lib,
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
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "mozjpeg";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A two-by-two red PPM bitmap.";
        operation = "Encode it as JPEG and decode it back to PPM.";
        expected = "All decoded pixels remain predominantly red.";
        files."probe.ppm" = "P3\n2 2\n255\n255 0 0 255 0 0\n255 0 0 255 0 0\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/cjpeg" "-quality" "95" "-outfile" "probe.jpg" "probe.ppm"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/djpeg" "-outfile" "decoded.ppm" "probe.jpg"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                header, dimensions, max_value, pixels = Path("decoded.ppm").read_bytes().split(b"\n", 3)
                assert (header, dimensions, max_value) == (b"P6", b"2 2", b"255")
                assert len(pixels) == 12
                for offset in range(0, len(pixels), 3):
                    red, green, blue = pixels[offset:offset + 3]
                    assert red >= 240 and green <= 16 and blue <= 16
                print("mozjpeg image round trip passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "mozjpeg image round trip passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Bytes that do not contain a JPEG image.";
        operation = "Attempt to decode them with djpeg.";
        expected = "The decoder rejects the invalid image.";
        files."broken.jpg" = "not JPEG\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/djpeg" "-outfile" "broken.ppm" "broken.jpg"];
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
    inherit version src;

    buildDeps =
      [buildPackages.cmake buildPackages.gnumake buildPackages.nasm buildPackages.patch]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [buildPackages.llvm]
        else []
      );
    runtimeDeps = [libpng zlib];
    propagatedDeps = [libpng zlib];
    passthru.evidenceSources = [src fdctFix ./_mozjpeg/standard-profile-tests.patch];
    # Enabling NASM makes CMake redetect Darwin binutils during configuration.
    cmakeFlags =
      if stdenv.hostPlatform.isDarwin
      then "-DCMAKE_INSTALL_NAME_TOOL=${buildPackages.llvm}/bin/llvm-install-name-tool"
      else "";

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
