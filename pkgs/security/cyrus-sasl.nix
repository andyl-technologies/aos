##! Cyrus SASL — Pluggable authentication framework
{
  mkDerivation,
  fetchurl,
  file,
  gnumake,
  pkg-config,
  krb5,
  libxcrypt,
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

    buildDeps = [file gnumake pkg-config];
    runtimeDeps = [krb5 libxcrypt openssl sqlite];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd cyrus-sasl-${version}

          # Cyrus SASL 2.1.28 predates C23's removal of implicit function
          # declarations. Include the standard declaration used by time() and
          # clock() instead of weakening the AOS compiler diagnostics.
          sed -i '/#ifdef HAVE_TIME_H/,/#endif/c\#include <time.h>' lib/saslutil.c
          for source in plugins/cram.c plugins/digestmd5.c plugins/otp.c; do
            sed -i '/#include <stdio.h>/a#include <time.h>' "$source"
          done

          # The release embeds an old libtool probe with an FHS-only path.
          # Point it at AOS file so ABI detection remains hermetic.
          sed -i 's|/usr/bin/file|${file}/bin/file|g' configure
        '';
      }
      {
        name = "configure";
        script = ''
          ./configure \
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
