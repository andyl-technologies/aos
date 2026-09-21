##! nghttp2 — HTTP/2 C library
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  pkg-config,
  stdenv,
}: let
  upstream = mkGithubUpstream {
    unitId = "nghttp2-1";
    family = "nghttp2";
    stream = "1";
    owner = "pkgs/networking/nghttp2.nix";
    version = "1.70.0";
    upstreamId = "v1.70.0";
    repository = "nghttp2/nghttp2";
    provider = "github-releases";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "nghttp2"
        "nghttp2"
        "releases"
        "download"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
          ];
        }
        {
          parts = [
            {literal = "nghttp2-";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.bz2";}
          ];
        }
      ];
      hash = "sha256-j6yh94qpmsO8F2ina34PazbY5qYsE4GHUbHSBfAvlAU=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "nghttp2";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

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
