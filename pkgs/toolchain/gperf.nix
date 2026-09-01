##! gperf — GNU perfect hash function generator
{
  mkDerivation,
  fetchurl,
  gnumake,
}: let
  version = "3.3";
in
  mkDerivation {
    pname = "gperf";
    inherit version;

    src = fetchurl {
      urls = [
        "https://mirrors.kernel.org/gnu/gperf/gperf-${version}.tar.gz"
      ];
      hash = "sha256-/Yfgq6fkOuBUg3r9bNTbA6PyaT3rNhkIXm7Z2NlgStg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gperf-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out
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
      description = "gperf — GNU perfect hash function generator";
      homepage = "https://www.gnu.org/software/gperf/";
      license = "GPL-3.0-or-later";
    };
  }
