# curl — Command-line URL transfer tool
{ mkDerivation, fetchurl, sources, versions, make, pkg-config,
  openssl, zlib, ca-certificates }:

mkDerivation {
  name = "curl-${versions.networking.curl}";
  version = versions.networking.curl;

  src = fetchurl {
    inherit (sources.curl) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ openssl zlib ca-certificates ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd curl-${versions.networking.curl}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --with-openssl=${openssl} \
          --with-zlib=${zlib} \
          --with-ca-bundle=${ca-certificates}/etc/ssl/certs/ca-certificates.crt \
          --enable-shared \
          --disable-static \
          --disable-ldap \
          --disable-ldaps \
          --without-librtmp \
          --without-libpsl \
          --without-libidn2 \
          --enable-threaded-resolver \
          --enable-ipv6
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install
      '';
    }
  ];

  meta = {
    description = "curl — command-line tool for transferring data via URLs";
    homepage = "https://curl.se";
    license = "curl";
  };
}
