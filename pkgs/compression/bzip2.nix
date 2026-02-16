##! bzip2 — Block-sorting file compressor
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.0.8";
in
mkDerivation {
  pname = "bzip2";
  inherit version;

  src = fetchurl {
    urls = [
      "https://sourceware.org/pub/bzip2/bzip2-${version}.tar.gz"
    ];
    hash = "sha256-q1oDF27hBtPw+pDjgdpHjdrkBZGBU8yiSOaCzQxKImk=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd bzip2-${version}
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES \
          CC=$CC \
          CFLAGS="$CFLAGS -fPIC -O2 -D_FILE_OFFSET_BITS=64" \
          LDFLAGS="$LDFLAGS"
        make -f Makefile-libbz2_so \
          CC=$CC \
          CFLAGS="$CFLAGS -fPIC -O2 -D_FILE_OFFSET_BITS=64" \
          LDFLAGS="$LDFLAGS"
      '';
    }
    {
      name = "install";
      script = ''
        make install PREFIX=$out
        # Install shared library
        cp -a libbz2.so* $out/lib/
        ln -sf libbz2.so.${version} $out/lib/libbz2.so
        ln -sf libbz2.so.${version} $out/lib/libbz2.so.1
        ln -sf libbz2.so.${version} $out/lib/libbz2.so.1.0
      '';
    }
  ];

  meta = {
    description = "bzip2 — block-sorting file compressor";
    homepage = "https://sourceware.org/bzip2/";
    license = "bzip2-1.0.6";
  };
}
