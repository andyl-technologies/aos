##! TIFF image codecs and image-processing tools.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  zlib,
  libdeflate,
  mozjpeg,
  jbigkit,
  xz,
  zstd,
  lerc,
  libwebp,
}: let
  version = "4.7.2";
  codecDependencies = [zlib libdeflate mozjpeg jbigkit xz zstd lerc libwebp];
  dependencyPrefixes = builtins.concatStringsSep ";" (map toString codecDependencies);
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
    pname = "libtiff";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A two-by-two RGB bitmap.";
        operation = "Encode it as TIFF, copy it with a different compression, and compare decoded pixels.";
        expected = "Both TIFF files decode to the same two-by-two RGB image.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                pixels = bytes([255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255])
                Path("pixels.ppm").write_bytes(b"P6\n2 2\n255\n" + pixels)
              ''
            ];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/ppm2tiff" "pixels.ppm" "packed.tif"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/tiffcp" "-c" "none" "packed.tif" "unpacked.tif"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@out@/bin/tiffcmp" "packed.tif" "unpacked.tif"];
            exit_code = 0;
            stdout.exact = "Compression: 32773 1\n";
            stderr.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                import subprocess

                result = subprocess.run(
                    ["@out@/bin/tiffinfo", "unpacked.tif"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                assert "Image Width: 2 Image Length: 2" in result.stdout
                assert "Samples/Pixel: 3" in result.stdout
                assert "Compression Scheme: None" in result.stdout
                print("libtiff image conversion passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "libtiff image conversion passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "Bytes that do not contain a TIFF image.";
        operation = "Inspect them with tiffinfo.";
        expected = "The parser rejects the invalid image.";
        files."broken.tif" = "not a TIFF\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/tiffinfo" "broken.tif"];
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://download.osgeo.org/libtiff/tiff-${version}.tar.xz"];
      hash = "126v5mkgn5k490z56ix2m0xpg27542djgim53jdp351hz72g15j9";
    };

    buildDeps = [buildPackages.cmake buildPackages.gnumake buildPackages.pkg-config];
    runtimeDeps = codecDependencies;
    # pkg-config resolves private requirements even for downstream cflags.
    propagatedDeps = codecDependencies;

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd tiff-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release -DCMath_LIBRARY:STRING=m \
              -DCMAKE_PREFIX_PATH="${dependencyPrefixes}" \
              -DBUILD_SHARED_LIBS=ON -Dtiff-static=OFF \
              -Dzlib=ON -Dlibdeflate=ON -Djpeg=ON -Djbig=ON \
              -Dlzma=ON -Dzstd=ON -Dlerc=ON -Dwebp=ON
          '';
        }
        {
          name = "build";
          script = ''
            cmake --build build --parallel "$NIX_BUILD_CORES"

            # TIFF selects one linkage form per build directory.
            cmake -S . -B build-static $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release -DCMath_LIBRARY:STRING=m \
              -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
              -DCMAKE_PREFIX_PATH="${dependencyPrefixes}" \
              -Dtiff-static=ON -Dzlib=ON -Dlibdeflate=ON -Djpeg=ON \
              -Djbig=ON -Dlzma=ON -Dzstd=ON -Dlerc=ON -Dwebp=ON
            cmake --build build-static --target tiff tiffxx --parallel "$NIX_BUILD_CORES"
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
            cp build-static/libtiff/libtiff.a build-static/libtiff/libtiffxx.a "$out/lib/"
            mkdir -p "$out/share/licenses/libtiff"
            cp LICENSE.md "$out/share/licenses/libtiff/"
          '';
        }
      ];

    meta = {
      description = "TIFF image library with external compression codecs and conversion tools";
      homepage = "https://libtiff.gitlab.io/libtiff/";
      license = "libtiff";
    };
  }
