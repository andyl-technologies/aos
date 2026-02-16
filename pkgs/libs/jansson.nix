##! jansson — C library for encoding, decoding and manipulating JSON data
{
  mkDerivation,
  fetchurl,
  make,
  cmake,
  ninja,
}:

let
  version = "2.14.1";
in
mkDerivation {
  pname = "jansson";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/akheron/jansson/archive/refs/tags/v${version}.tar.gz"
    ];
    hash = "sha256-l5IQ6v/f+89Uz8NNBH/M3hPyG1KaOB3ybbhx2Ib3KaQ=";
  };

  buildDeps = [
    make
    cmake
    ninja
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

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

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      link = testing.mkLinkCheck {
        pname = "lib-jansson";
        library = self;
        libs = [ "-ljansson" ];
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
