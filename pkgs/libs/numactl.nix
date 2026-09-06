##! numactl — NUMA policy tools and libnuma
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
}: let
  upstream = mkGithubUpstream {
    unitId = "numactl-2";
    family = "numactl";
    stream = "2";
    owner = "pkgs/libs/numactl.nix";
    version = "2.0.19";
    upstreamId = "v2.0.19";
    repository = "numactl/numactl";
    provider = "github-releases";
    tagPrefix = "v";
    major = 2;
    source = {
      authority = "github.com";
      path = [
        "numactl"
        "numactl"
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
            {literal = "numactl-";}
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
      hash = "sha256-8mcqA4HLWRlunCRr+LzEPVVovEV3AKaX8aHfdiua+IQ=";
    };
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "numactl";
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
          cd numactl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            --prefix=$out \
            --enable-shared \
            --enable-static
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
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-numactl";
        tool = self;
        command = "numactl --show";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libnuma.so"];
      };
    };

    meta = {
      description = "NUMA policy control tools and library";
      homepage = "https://github.com/numactl/numactl";
      license = "LGPL-2.1-only";
    };
  }
