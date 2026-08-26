##! editline — Small line editing library (troglobit editline)
{
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
}: let
  version = "1.17.1";
in
  mkDerivation {
    pname = "editline";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/troglobit/editline/releases/download/${version}/editline-${version}.tar.xz"
      ];
      hash = "sha256-3yI7MzOlRf3bxntJ3tPSQsZvrfegS+s62iCVf80f/A4=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [ncurses];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd editline-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --disable-static
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
      description = "editline — small line editing library";
      homepage = "https://github.com/troglobit/editline";
      license = "ISC";
    };
  }
