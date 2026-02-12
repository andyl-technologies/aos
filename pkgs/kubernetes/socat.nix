# socat — Multipurpose relay for bidirectional data transfer
{ mkDerivation, fetchurl, sources, versions, make, openssl }:

mkDerivation {
  name = "socat-${versions.kubernetes.socat}";
  version = versions.kubernetes.socat;

  src = fetchurl {
    inherit (sources.socat) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [ openssl ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd socat-${versions.kubernetes.socat}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --enable-openssl \
          --with-openssl=${openssl}
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
    description = "socat — multipurpose relay for bidirectional data transfer";
    homepage = "http://www.dest-unreach.org/socat/";
    license = "GPL-2.0-only";
  };
}
