##! lerc — Limited-error raster compression.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "4.2.0";
  src = fetchurl {
    urls = ["https://github.com/Esri/lerc/archive/refs/tags/v${version}.tar.gz"];
    hash = "1j8pgr282gg58pbh07cn5qh4a9w79x2w9wya024b7dgws4z5kyx1";
  };
in
  mkDerivation {
    pname = "lerc";
    inherit version src;

    buildDeps = [buildPackages.cmake buildPackages.gnumake];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd lerc-${version}
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
              -DBUILD_SHARED_LIBS=ON
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
              # Upstream ships its codec test driver outside the CMake targets.
              $CXX -std=c++17 src/LercTest/main.cpp -Lbuild \
                -Wl,-rpath,"$PWD/build" -lLerc -o build/lerc-test
              build/lerc-test
            '';
          }
        ]
      )
      ++ [
        {
          name = "install";
          script = ''
            cmake --install build
            mkdir -p "$out/share/licenses/lerc"
            cp LICENSE "$out/share/licenses/lerc/"
          '';
        }
      ];

    meta = {
      description = "Limited-error raster compression library";
      homepage = "https://github.com/Esri/lerc";
      license = "Apache-2.0";
    };
  }
