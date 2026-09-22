##! Imath — vector, matrix, and half-precision arithmetic for imaging.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "3.2.3";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "imath";
    inherit version;
    src = fetchurl {
      urls = ["https://github.com/AcademySoftwareFoundation/Imath/archive/refs/tags/v${version}.tar.gz"];
      hash = "1y7r5pnyyvqbvr0disxy8zbnh4v9qzciahlxw04byi8zyari4371";
    };

    buildDeps = [buildPackages.cmake buildPackages.gnumake];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd Imath-${version}
          '';
        }
        {
          name = "configure";
          script = ''
            cmake -S . -B build $cmakeFlags \
              -DCMAKE_INSTALL_PREFIX="$out" -DCMAKE_INSTALL_LIBDIR=lib \
              -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
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
            mkdir -p "$out/share/licenses/imath"
            cp LICENSE.md "$out/share/licenses/imath/"
          '';
        }
      ];

    meta = {
      description = "Vector, matrix, and half-precision arithmetic library";
      homepage = "https://imath.readthedocs.io/";
      license = "BSD-3-Clause";
    };
  }
