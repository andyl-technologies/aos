##! PostgreSQL — Object-relational database server
{
  mkDerivation,
  fetchurl,
  cc,
  gnumake,
  pkg-config,
  bison,
  flex,
  perl,
  python3,
  llvm,
  curl,
  docbook-xml,
  docbook-xsl,
  gettext,
  icu,
  krb5,
  libselinux,
  liburing,
  libxml2,
  libxslt,
  linux-pam,
  lz4,
  numactl,
  openldap,
  openssl,
  readline,
  systemd,
  tcl,
  tzdata,
  util-linux,
  zlib,
  zstd,
}: let
  version = "18.4";
in
  mkDerivation {
    pname = "postgresql";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.postgresql.org/pub/source/v${version}/postgresql-${version}.tar.bz2"
      ];
      hash = "sha256-gagexpX7DHkBQH3vqh0veXNhcVTPJ7p046erjmRDYJQ=";
    };

    buildDeps = [
      gnumake
      pkg-config
      bison
      flex
      perl
      python3
      llvm
      docbook-xml
      docbook-xsl
      gettext
      libxml2
      libxslt
      util-linux
    ];
    runtimeDeps = [
      curl
      icu
      krb5
      libselinux
      liburing
      libxml2
      libxslt
      linux-pam
      llvm
      lz4
      numactl
      openldap
      openssl
      perl
      python3
      readline
      systemd
      tcl
      tzdata
      util-linux
      zlib
      zstd
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd postgresql-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export LLVM_CONFIG=${llvm}/bin/llvm-config
          export CLANG="${llvm}/bin/clang $(cat ${cc}/nix-support/cc-cflags)"
          export TCLSH=${tcl}/bin/tclsh9.0
          export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
          ./configure \
            --prefix=$out \
            --enable-nls \
            --with-llvm \
            --with-icu \
            --with-tcl \
            --with-tclconfig=${tcl}/lib \
            --with-gssapi \
            --with-ldap \
            --with-liburing \
            --with-libnuma \
            --with-system-tzdata=${tzdata}/share/zoneinfo \
            --with-perl \
            --with-python \
            --with-pam \
            --with-selinux \
            --with-systemd \
            --with-uuid=e2fs \
            --with-libcurl \
            --with-libxml \
            --with-libxslt \
            --with-lz4 \
            --with-zstd \
            --with-ssl=openssl

          for macro in \
            ENABLE_GSS ENABLE_NLS HAVE_LIBNUMA USE_ICU USE_LDAP USE_LIBURING USE_LLVM \
            USE_LIBCURL USE_LIBXML USE_LIBXSLT USE_LZ4 USE_OPENSSL USE_PAM \
            USE_SYSTEMD USE_ZSTD HAVE_LIBSELINUX HAVE_UUID_E2FS; do
            grep "^#define $macro 1$" src/include/pg_config.h
          done
        '';
      }
      {
        name = "build";
        script = ''
          export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
          make -j$NIX_BUILD_CORES world
        '';
      }
      {
        name = "install";
        script = ''
          export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
          make install-world
          test -f "$out/share/doc/html/index.html"
          test -f "$out/share/man/man1/postgres.1"
          test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"
        '';
      }
    ];

    meta = {
      description = "PostgreSQL object-relational database server";
      homepage = "https://www.postgresql.org/";
      license = "PostgreSQL";
    };

    checks = {
      testing,
      self,
      ...
    }: {
      version = testing.mkToolCheck {
        pname = "storage-postgresql";
        tool = self;
        command = "postgres --version";
      };

      features = testing.mkVMTest {
        name = "storage-postgresql-features";
        rootfsDeps = [self];
        testScript = ''
          pg_config --configure > /tmp/postgresql-configure
          for flag in \
            --enable-nls --with-llvm --with-icu --with-tcl --with-tclconfig=${tcl}/lib \
            --with-gssapi --with-ldap --with-liburing --with-libnuma \
            --with-system-tzdata=${tzdata}/share/zoneinfo \
            --with-perl --with-python --with-pam \
            --with-selinux --with-systemd --with-uuid=e2fs --with-libcurl \
            --with-libxml --with-libxslt --with-lz4 --with-zstd \
            --with-ssl=openssl; do
            grep -- "$flag" /tmp/postgresql-configure
          done
          test -f ${self}/share/doc/html/index.html
          test -f ${self}/share/man/man1/postgres.1
          test -n "$(find ${self}/share/locale -name '*.mo' -print -quit)"
        '';
      };
    };
  }
