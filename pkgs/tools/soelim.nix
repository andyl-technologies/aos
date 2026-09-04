##! GNU soelim — roff source include preprocessor
{
  mkDerivation,
  fetchurl,
  bison,
  gnumake,
  m4,
  perl,
}: let
  version = "1.23.0";
in
  mkDerivation {
    pname = "soelim";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/groff/groff-${version}.tar.gz"
        "https://ftpmirror.gnu.org/groff/groff-${version}.tar.gz"
      ];
      hash = "sha256-a5dX9ZK3UYtJAutq9+VFcL3Mujeocf3bLTCuOGNRHBM=";
    };

    buildDeps = [bison gnumake m4 perl];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd groff-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure --prefix=$out
        '';
      }
      {
        name = "build";
        script = ''
          # The focused target omits this generated gnulib header from its
          # dependency edge even though libgnu consumes it.
          make lib/unitypes.h lib/uniwidth.h
          make -j$NIX_BUILD_CORES soelim
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 soelim $out/bin/soelim
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-soelim";
        tool = self;
        command = "soelim --version";
      };
    };

    meta = {
      description = "GNU roff source include preprocessor";
      homepage = "https://www.gnu.org/software/groff/";
      license = "GPL-3.0-or-later";
    };
  }
