##! fmt — Modern C++ formatting library
{
  mkDerivation,
  fetchurl,
  cmake,
  gnumake,
}: let
  version = "12.1.0";
in
  mkDerivation {
    pname = "fmt";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/fmtlib/fmt/archive/refs/tags/${version}.tar.gz"
      ];
      hash = "sha256-6n3kKZaJ4Stt3dOS+YlvCPsHd6xxaIl6JEptYIUEP+o=";
    };

    buildDeps = [
      cmake
      gnumake
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd fmt-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          mkdir build
          cd build
          cmake .. \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DBUILD_SHARED_LIBS=ON \
            -DFMT_DOC=OFF \
            -DFMT_TEST=ON
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build . -j$NIX_BUILD_CORES
          ctest --output-on-failure
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install .
        '';
      }
    ];

    meta = {
      description = "Modern C++ formatting library";
      homepage = "https://fmt.dev";
      license = "MIT";
    };
  }
