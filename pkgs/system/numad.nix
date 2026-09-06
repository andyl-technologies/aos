##! numad — Automatic NUMA placement daemon
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "0.5+20150602";
in
  mkDerivation {
    pname = "numad";
    inherit version;

    src = fetchurl {
      urls = ["https://deb.debian.org/debian/pool/main/n/numad/numad_0.5+20150602.orig.tar.gz"];
      hash = "sha256-Nb/5CIjfn3kXUjz+KXhev5jCKq2Ug34tfu5w6Yfb88I=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd numad-${version}
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install prefix="$out"
          "$out/bin/numad" -V | grep -q '${version}'
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-numad";
        tool = self;
        command = "numad -V";
      };
    };

    meta = {
      description = "Monitors NUMA topology and places workloads for local memory access";
      homepage = "https://pagure.io/numad";
      license = "LGPL-2.1-only";
      mainProgram = "numad";
    };
  }
