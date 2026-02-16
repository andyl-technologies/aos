##! GNU Autoconf — generates configure scripts from templates
{
  mkDerivation,
  fetchurl,
  make,
  m4,
  perl,
}:

let
  version = "2.72";
in
mkDerivation {
  pname = "autoconf";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.gnu.org/gnu/autoconf/autoconf-${version}.tar.xz"
    ];
    hash = "sha256-uohcExlXjWyU1G6bDc60AUyq/iSQ5Deg28o/JwoiP1o=";
  };

  buildDeps = [ make ];
  runtimeDeps = [
    m4
    perl
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd autoconf-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
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
    description = "GNU Autoconf — generates configure scripts from templates";
    homepage = "https://www.gnu.org/software/autoconf/";
    license = "GPL-3.0-or-later";
  };
}
