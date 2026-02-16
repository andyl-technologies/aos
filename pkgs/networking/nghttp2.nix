##! nghttp2 — HTTP/2 C library
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
}:

let
  version = "1.67.1";
in
mkDerivation {
  pname = "nghttp2";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/nghttp2/nghttp2/releases/download/v${version}/nghttp2-${version}.tar.bz2"
    ];
    hash = "sha256-37cg1CQ6eVBYn6JjI3i+te6a1ELpS3lLO44soowdfio=";
  };

  buildDeps = [
    make
    pkg-config
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd nghttp2-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --enable-lib-only \
          --enable-shared \
          --disable-static \
          --disable-examples
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "nghttp2 — HTTP/2 C library";
    homepage = "https://nghttp2.org/";
    license = "MIT";
  };

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      link = testing.mkLinkCheck {
        pname = "lib-nghttp2";
        library = self;
        libs = [ "-lnghttp2" ];
        testSource = ''
          #include <nghttp2/nghttp2.h>
          #include <stdio.h>
          int main() {
            nghttp2_info *info = nghttp2_version(0);
            if (!info) return 1;
            printf("nghttp2 version: %s\n", info->version_str);
            return 0;
          }
        '';
      };
    };
}
