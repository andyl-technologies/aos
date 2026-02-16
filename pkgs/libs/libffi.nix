##! libffi — Foreign Function Interface library
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "3.4.6";
in
mkDerivation {
  pname = "libffi";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/libffi/libffi/releases/download/v${version}/libffi-${version}.tar.gz"
      "https://gcc.gnu.org/pub/libffi/libffi-${version}.tar.gz"
    ];
    hash = "sha256-mFBrEs4KLbMfQOFOcPMzwJRKIGTysPR3CaiI4GRzFZA=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd libffi-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --enable-shared \
          --disable-static \
          --disable-docs
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
        # Some packages look for libffi headers in include/ not lib/libffi-*/include/
        if [ -d "$out/lib/libffi-${version}/include" ]; then
          cp -n "$out/lib/libffi-${version}/include/"*.h "$out/include/" 2>/dev/null || true
        fi
      '';
    }
  ];

  meta = {
    description = "libffi — a portable foreign function interface library";
    homepage = "https://sourceware.org/libffi/";
    license = "MIT";
  };
}
