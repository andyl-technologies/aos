##! TIFF image codecs and image-processing tools.
{
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
