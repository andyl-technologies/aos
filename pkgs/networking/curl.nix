##! curl — Command-line URL transfer tool
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  perl,
  openssl,
  zlib,
  nghttp2,
  ca-certificates,
}:

let
  version = "8.10.1";
in
mkDerivation {
  pname = "curl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://curl.se/download/curl-${version}.tar.xz"
    ];
    hash = "sha256-c6Sw6ZWWoJ+lkkpPt+S5lahf2g0YosAquc8TS+vOBO4=";
  };

  buildDeps = [
    make
    pkg-config
    perl
  ];
  runtimeDeps = [
    openssl
    zlib
    nghttp2
    ca-certificates
  ];
  propagatedDeps = [
    openssl
    zlib
    nghttp2
  ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd curl-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --with-openssl=${openssl} \
          --with-zlib=${zlib} \
          --with-nghttp2=${nghttp2} \
          --with-ca-bundle=${ca-certificates}/etc/ssl/certs/ca-certificates.crt \
          --enable-shared \
          --disable-static \
          --disable-ldap \
          --disable-ldaps \
          --without-librtmp \
          --without-libpsl \
          --without-libidn2 \
          --enable-threaded-resolver \
          --enable-ipv6 \
          --disable-docs \
          --disable-manual
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
        # Create curl.pc symlink (some consumers look for "curl" not "libcurl")
        ln -sf libcurl.pc $out/lib/pkgconfig/curl.pc
      '';
    }
  ];

  meta = {
    description = "curl — command-line tool for transferring data via URLs";
    homepage = "https://curl.se";
    license = "curl";
  };
}
