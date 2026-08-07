##! numactl — NUMA policy tools and libnuma
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "2.0.19";
in
  mkDerivation {
    pname = "numactl";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/numactl/numactl/releases/download/v${version}/numactl-${version}.tar.gz"
      ];
      hash = "sha256-8mcqA4HLWRlunCRr+LzEPVVovEV3AKaX8aHfdiua+IQ=";
    };

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
