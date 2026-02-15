##! GNU m4 — Macro processor
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.4.19";
in
mkDerivation {
  pname = "m4";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.gnu.org/gnu/m4/m4-${version}.tar.xz"
    ];
    hash = "sha256-Y67eXG0zttmxNRHNC+LKwEby5w/QoHqpVzoEqCeDr5Y=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd m4-${version}
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
    description = "GNU m4 — macro processor";
    homepage = "https://www.gnu.org/software/m4/";
    license = "GPL-3.0-or-later";
  };
}
