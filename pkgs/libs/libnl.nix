##! libnl — Linux Netlink protocol library suite
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  flex,
  bison,
}:

let
  version = "3.12.0";
in
mkDerivation {
  pname = "libnl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/thom311/libnl/releases/download/libnl${
        builtins.replaceStrings [ "." ] [ "_" ] version
      }/libnl-${version}.tar.gz"
    ];
    hash = "sha256-/FHKcZbxo/X99v/ThktQ9PnAIzO+KL5O7KBX4QPA3Rg=";
  };

  buildDeps = [
    make
    pkg-config
    flex
    bison
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd libnl-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=$out/etc \
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
    description = "libnl — Linux Netlink protocol library suite";
    homepage = "https://github.com/thom311/libnl";
    license = "LGPL-2.1-only";
  };
}
