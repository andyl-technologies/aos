##! Oniguruma — regular expression library
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "oniguruma-6";
    family = "oniguruma";
    stream = "6";
    owner = "pkgs/libs/oniguruma.nix";
    version = "6.9.10";
    upstreamId = "v6.9.10";
    repository = "kkos/oniguruma";
    provider = "github-releases";
    tagPrefix = "v";
    major = 6;
    source = {
      authority = "github.com";
      path = [
        "kkos"
        "oniguruma"
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
            {literal = "onig-";}
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
      hash = "sha256-Klz8WuJZ5Ol/hraN//wVLNr/6U4gYLdwy4JyONdp/AU=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "oniguruma";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd onig-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static \
            --enable-posix-api=yes
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

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-oniguruma";
        library = self;
        libs = ["-lonig"];
        testSource = ''
          #include <oniguruma.h>
          #include <stdio.h>
          int main() {
            printf("oniguruma version: %s\n", onig_version());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "Oniguruma — regular expression library";
      homepage = "https://github.com/kkos/oniguruma";
      license = "BSD-2-Clause";
    };
  }
