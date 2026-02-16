##! Oniguruma — regular expression library
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "6.9.10";
in
mkDerivation {
  pname = "oniguruma";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/kkos/oniguruma/releases/download/v${version}/onig-${version}.tar.gz"
    ];
    hash = "sha256-Klz8WuJZ5Ol/hraN//wVLNr/6U4gYLdwy4JyONdp/AU=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd onig-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --enable-shared \
          --disable-static \
          --enable-posix-api=yes
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
    description = "Oniguruma — regular expression library";
    homepage = "https://github.com/kkos/oniguruma";
    license = "BSD-2-Clause";
  };
}
