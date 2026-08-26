##! jansson — C library for encoding, decoding and manipulating JSON data
{
  mkDerivation,
  fetchurl,
  gnumake,
  cmake,
  ninja,
}: let
  version = "2.15.0";
in
  mkDerivation {
    pname = "jansson";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/akheron/jansson/archive/refs/tags/v${version}.tar.gz"
      ];
      hash = "sha256-c6wSu8Yv9TbkDHo+Fe0AeZPFyk0jiX3iPxkG+JG1pLs=";
    };

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
        script = ''
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
