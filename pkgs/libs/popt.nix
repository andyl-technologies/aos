##! popt — command-line option parsing library
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.19";
in
mkDerivation {
  pname = "popt";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.osuosl.org/pub/rpm/popt/releases/popt-1.x/popt-${version}.tar.gz"
    ];
    hash = "sha256-wlpIOPyOTByKrLi9Yg7bMISj1jv4mH/a08onWMYyQPk=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd popt-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
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
    description = "popt — command-line option parsing library";
    homepage = "https://github.com/rpm-software-management/popt";
    license = "MIT";
  };
}
