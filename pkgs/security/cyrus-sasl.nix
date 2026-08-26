##! Cyrus SASL — Pluggable authentication framework
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  krb5,
  openssl,
  sqlite,
}: let
  version = "2.1.28";
in
  mkDerivation {
    pname = "cyrus-sasl";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/cyrusimap/cyrus-sasl/releases/download/cyrus-sasl-${version}/cyrus-sasl-${version}.tar.gz"
      ];
      hash = "sha256-fM/Gq9Ae1nwaCSSzU+Um8bdmsh9C1FYu5jWo6/xbs4w=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [krb5 openssl sqlite];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd cyrus-sasl-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
            $configureFlags \
            --prefix=$out \
            --enable-shared \
            --enable-static \
            --enable-gssapi \
            --enable-scram \
            --with-openssl=${openssl} \
            --with-sqlite3=${sqlite}
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

    checks = {
      testing,
      self,
      ...
    }: {
      cli = testing.mkToolCheck {
        pname = "tool-sasl2";
        tool = self;
        command = "sasl2pluginviewer";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libsasl2.so"];
      };
    };

    meta = {
      description = "Cyrus Simple Authentication and Security Layer";
      homepage = "https://www.cyrusimap.org/sasl/";
      license = "BSD-3-Clause";
    };
  }
