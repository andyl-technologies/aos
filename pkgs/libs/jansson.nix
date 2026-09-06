##! jansson — C library for encoding, decoding and manipulating JSON data
{
  mkDerivation,
  mkGithubUpstream,
  stdenv,
  gnumake,
  cmake,
  ninja,
}: let
  upstream = mkGithubUpstream {
    unitId = "jansson-2";
    family = "jansson";
    stream = "2";
    owner = "pkgs/libs/jansson.nix";
    version = "2.15.1";
    upstreamId = "v2.15.1";
    repository = "akheron/jansson";
    provider = "github-releases";
    tagPrefix = "v";
    major = 2;
    source = {
      authority = "github.com";
      path = [
        "akheron"
        "jansson"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "v";}
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
      hash = "sha256-2/lcsK+QP0+4thUH2WtFtn230UeWiO3jUuHVcTlNBvc=";
    };
  };
  inherit (upstream) version;
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "jansson";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [
      gnumake
      cmake
      ninja
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if isDarwinCross
          then ''
            tar xf $src
            cd jansson-${version}

            # Cross CMake uses static-library try-compiles, which falsely
            # report ELF symbol-version linker switches as supported. Mach-O
            # shared libraries do not use GNU symbol-version scripts.
            sed -i \
              -e 's/if (SYMVER_WORKS)/if (SYMVER_WORKS AND NOT APPLE)/' \
              -e 's/if (VSCRIPT_WORKS)/if (VSCRIPT_WORKS AND NOT APPLE)/' \
              CMakeLists.txt
          ''
          else ''
            tar xf $src
            cd jansson-${version}
          '';
      }
      {
        name = "configure";
        script = ''
          cmake -S . -B build -G Ninja \
            $cmakeFlags \
            -DCMAKE_BUILD_TYPE=Release \
            -DCMAKE_INSTALL_PREFIX=$out \
            -DCMAKE_INSTALL_LIBDIR=lib \
            -DJANSSON_BUILD_SHARED_LIBS=ON \
            -DJANSSON_BUILD_DOCS=OFF
        '';
      }
      {
        name = "build";
        script = ''
          ninja -C build -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          ninja -C build install
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-jansson";
        library = self;
        libs = ["-ljansson"];
        testSource = ''
          #include <jansson.h>
          #include <stdio.h>
          int main() {
            json_t *obj = json_object();
            if (!obj) return 1;
            json_decref(obj);
            printf("jansson version: %s\n", JANSSON_VERSION);
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "jansson — C library for encoding, decoding and manipulating JSON data";
      homepage = "https://github.com/akheron/jansson";
      license = "MIT";
    };
  }
