# OpenSSL — TLS and cryptography library
{ mkDerivation, fetchurl, make, zlib, perl }:

let version = "3.3.2"; in
mkDerivation {
  pname = "openssl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://www.openssl.org/source/openssl-${version}.tar.gz"
    ];
    hash = "sha256-LopAsBl5r+i+C7+z3l3BxnCf7bRtbInBDaEUq1/D0oE=";
  };

  buildDeps = [ make perl ];
  runtimeDeps = [ zlib ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd openssl-${version}
      '';
    }
    { name = "configure";
      script = ''
        perl ./Configure \
          --prefix=$out \
          --libdir=lib \
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
