##! libsodium — Modern cryptography library
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.0.20";
in
mkDerivation {
  pname = "libsodium";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/jedisct1/libsodium/archive/refs/tags/${version}-RELEASE.tar.gz"
      "https://download.libsodium.org/libsodium/releases/old/libsodium-${version}-RELEASE.tar.gz"
    ];
    hash = "sha256-jlrsoHpyOie77MO+7xSwBo035/wOl/UbPxyC0qWABcE=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd libsodium-${version}-RELEASE
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
    description = "libsodium — modern, easy-to-use cryptography library";
    homepage = "https://libsodium.org";
    license = "ISC";
  };
}
