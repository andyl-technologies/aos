##! ALSA library — Advanced Linux Sound Architecture user-space library
{
  mkDerivation,
  fetchurl,
  gnumake,
}:
let
  version = "1.2.13";
in
mkDerivation {
  pname = "alsa-lib";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.alsa-project.org/files/pub/lib/alsa-lib-${version}.tar.bz2"
    ];
    hash = "sha256-jE/zdVPL6JYY4Yfkx3n3GpuyqLJ7kfh+1AmHzJIz2PY=";
  };

  buildDeps = [ gnumake ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd alsa-lib-${version}
      '';
    }
    {
      name = "build";
      script = ''
        $CONFIG_SHELL ./configure \
          --prefix=$out \
          --without-debug \
          --disable-python
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
    description = "ALSA library — Advanced Linux Sound Architecture user-space library";
    homepage = "https://www.alsa-project.org";
    license = "LGPL-2.1-or-later";
  };
}
