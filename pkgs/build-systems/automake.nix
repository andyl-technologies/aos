##! GNU Automake — generates Makefile.in from Makefile.am templates
{
  mkDerivation,
  fetchurl,
  make,
  autoconf,
  perl,
}:

let
  version = "1.17";
in
mkDerivation {
  pname = "automake";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.gnu.org/gnu/automake/automake-${version}.tar.xz"
    ];
    hash = "sha256-iSDB/EEeE7kL9wTvnbbynVQOdtIyyzssn03EzFmb2ZA=";
  };

  buildDeps = [ make ];
  runtimeDeps = [
    autoconf
    perl
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd automake-${version}
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
    description = "GNU Automake — generates Makefile.in from Makefile.am templates";
    homepage = "https://www.gnu.org/software/automake/";
    license = "GPL-2.0-or-later";
  };
}
