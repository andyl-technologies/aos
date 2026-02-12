# OpenSSL — TLS and cryptography library
{ mkDerivation, fetchurl, sources, versions, make, zlib, perl }:

mkDerivation {
  name = "openssl-${versions.tls.openssl}";
  version = versions.tls.openssl;

  src = fetchurl {
    inherit (sources.openssl) url hash;
  };

  buildDeps = [ make perl ];
  runtimeDeps = [ zlib ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd openssl-${versions.tls.openssl}
      '';
    }
    { name = "configure";
      script = ''
        ./Configure \
          --prefix=$out \
          --openssldir=$out/etc/ssl \
          linux-x86_64 \
          no-ssl2 \
          no-ssl3 \
          no-dtls \
          no-legacy \
          shared \
          zlib \
          --with-zlib-include=${zlib}/include \
          --with-zlib-lib=${zlib}/lib \
          -Wl,-rpath,$out/lib
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
        make install_sw install_ssldirs
      '';
    }
  ];

  meta = {
    description = "OpenSSL — TLS/SSL and cryptography toolkit";
    homepage = "https://www.openssl.org";
    license = "Apache-2.0";
  };
}
