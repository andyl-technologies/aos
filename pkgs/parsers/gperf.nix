# gperf — GNU perfect hash function generator
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "3.1";
in
mkDerivation {
  pname = "gperf";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.gnu.org/gnu/gperf/gperf-${version}.tar.gz"
    ];
    hash = "sha256-WIVGuUW7pLcLajphboC0q0ZuPzMCSjUvwhmBEs27OuI=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

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
