##! libdeflate — Optimized DEFLATE, zlib, and gzip compression.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  zlib,
}: let
  version = "1.26";
  src = fetchurl {
    urls = ["https://github.com/ebiggers/libdeflate/archive/refs/tags/v${version}.tar.gz"];
    hash = "11fg2fgmzl52pvzdbr42gpkf4v7zzil6kkkm6qhpd1akqpzkz85v";
  };
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "libdeflate";
    inherit version src;

    buildDeps = [buildPackages.cmake buildPackages.gnumake];
    runtimeDeps = [];

    phases =
      [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd libdeflate-${version}
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
              -DCMAKE_PREFIX_PATH="${zlib}" \
              -DCMAKE_BUILD_RPATH="${zlib}/lib" \
              -DLIBDEFLATE_BUILD_TESTS=ON
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
            mkdir -p "$out/share/licenses/libdeflate"
            cp COPYING "$out/share/licenses/libdeflate/"
          '';
        }
      ];

    meta = {
      description = "DEFLATE, zlib, and gzip compression library and command-line tools";
      homepage = "https://github.com/ebiggers/libdeflate";
      license = "MIT";
    };
  }
