##! fmt — Modern C++ formatting library
{
  mkDerivation,
  mkGithubUpstream,
  cmake,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "fmt-12";
    family = "fmt";
    stream = "12";
    owner = "pkgs/libs/fmt.nix";
    version = "12.1.0";
    upstreamId = "12.1.0";
    repository = "fmtlib/fmt";
    provider = "github-releases";
    major = 12;
    source = {
      authority = "github.com";
      path = [
        "fmtlib"
        "fmt"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-6n3kKZaJ4Stt3dOS+YlvCPsHd6xxaIl6JEptYIUEP+o=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "fmt";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

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
