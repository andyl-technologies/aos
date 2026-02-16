##! socat — Multipurpose relay for bidirectional data transfer
{
  mkDerivation,
  fetchurl,
  make,
  openssl,
}:

let
  version = "1.8.0.1";
in
mkDerivation {
  pname = "socat";
  inherit version;

  src = fetchurl {
    urls = [
      "http://www.dest-unreach.org/socat/download/socat-${version}.tar.bz2"
    ];
    hash = "sha256-aig1Zdt8+GKSxvcFBMWKuwPimIit7tWmxfNFfoA8G4E=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ openssl ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd socat-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --enable-openssl \
          --with-openssl=${openssl}
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
    description = "socat — multipurpose relay for bidirectional data transfer";
    homepage = "http://www.dest-unreach.org/socat/";
    license = "GPL-2.0-only";
  };

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkToolCheck {
        pname = "tool-socat";
        tool = self;
        command = "socat -V";
      };
    };
}
