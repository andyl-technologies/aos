##! libtirpc — Transport Independent RPC library
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
}:

let
  version = "1.3.6";
in
mkDerivation {
  pname = "libtirpc";
  inherit version;

  src = fetchurl {
    urls = [
      "https://sourceforge.net/projects/libtirpc/files/libtirpc/${version}/libtirpc-${version}.tar.bz2"
    ];
    hash = "sha256-u9Jqjw31aQpipH9qow95fz740CVg0bxEmoMGa1odNQg=";
  };

  buildDeps = [
    make
    pkg-config
  ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd libtirpc-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --disable-gssapi
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
    description = "libtirpc — Transport Independent RPC library";
    homepage = "https://sourceforge.net/projects/libtirpc/";
    license = "BSD-3-Clause";
  };
}
