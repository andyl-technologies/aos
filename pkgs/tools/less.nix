##! less — terminal pager
{
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
}: let
  version = "704";
in
  mkDerivation {
    pname = "less";
    inherit version;

    src = fetchurl {
      urls = [
        "https://www.greenwoodsoftware.com/less/less-${version}.tar.gz"
        "https://mirrors.kernel.org/gentoo/distfiles/less-${version}.tar.gz"
      ];
      hash = "sha256-IKCworslJfpTx+7pvrhUtMnPFy6rsgmvcCB0NUe/6fs=";
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
