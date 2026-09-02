##! less — terminal pager
{
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
}: let
  version = "668";
in
  mkDerivation {
    pname = "less";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.greenwoodsoftware.com/less/less-${version}.tar.gz"
        "https://mirrors.kernel.org/gentoo/distfiles/less-${version}.tar.gz"
      ];
      hash = "sha256-KBn1VWTYbVQqu+yv2C/2HoGaPuyWf6o2zT5o8VlqRLg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [ncurses];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd less-${version}
        '';
      }
      {
        name = "build";
        script = ''
          $CONFIG_SHELL ./configure $configureFlags --prefix=$out --sysconfdir=/etc
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
      description = "less — terminal pager";
      homepage = "https://www.greenwoodsoftware.com/less/";
      license = "GPL-3.0-or-later";
    };
  }
