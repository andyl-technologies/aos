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

    buildDeps = [cmake gnumake];
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
          cmake -S . -B build \
            $cmakeFlags \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_SHARED_LIBS=ON \
            -DFMT_DOC=OFF \
            -DFMT_TEST=OFF
        '';
      }
      {
        name = "build";
        script = ''
          cmake --build build --parallel $NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          cmake --install build
        '';
      }
    ];

    meta = {
      description = "Modern formatting library for C++";
      homepage = "https://fmt.dev/";
      license = "MIT";
    };
  }
