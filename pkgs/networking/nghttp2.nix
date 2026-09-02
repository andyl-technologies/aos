##! nghttp2 — HTTP/2 C library
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  stdenv,
}: let
  version = "1.68.0";
in
  mkDerivation {
    pname = "nghttp2";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/nghttp2/nghttp2/releases/download/v${version}/nghttp2-${version}.tar.bz2"
      ];
      hash = "sha256-jYDLTkWtylRqIAW4YlG6Wntj9eoyIiiuKOmWl0P5lwc=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [];
    propagatedDeps = [];

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
            $configureFlags \
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
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            make install

              # Keep upstream's generic build-tree examples from resembling
              # an unsanitized Nix sandbox path in published outputs.
              sed -i 's|/build/|/build-tree/|g' \
                "$out/share/doc/nghttp2/README.rst"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "nghttp2 — HTTP/2 C library";
      homepage = "https://nghttp2.org/";
      license = "MIT";
    };

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-nghttp2";
        library = self;
        libs = ["-lnghttp2"];
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
