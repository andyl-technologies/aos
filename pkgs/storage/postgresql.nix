##! PostgreSQL — Object-relational database server
{
  mkDerivation,
  fetchurl,
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
  openpam,
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
  stdenv,
  buildPackages,
}: let
  version = "18.4";
  isDarwin = stdenv.hostPlatform.isDarwin;
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

    buildDeps =
      if isDarwin
      then [
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
      ]
      else [
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
    runtimeDeps =
      if isDarwin
      then [
        curl
        icu
        krb5
        libxml2
        libxslt
        openpam
        llvm
        lz4
        openldap
        openssl
        perl
        python3
        readline
        tcl
        tzdata
        zlib
        zstd
      ]
      else [
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
        script =
          if isDarwin
          then ''
            # PostgreSQL needs native LLVM utilities to generate bitcode, but
            # must compile and link against the Darwin LLVM headers and dylib.
            mkdir -p .aos-native-tools
            cat > .aos-native-tools/llvm-config <<'LLVM_CONFIG_WRAPPER'
            #!$CONFIG_SHELL
            case "$1" in
              --bindir)
                printf '%s\n' '${buildPackages.llvm}/bin'
                ;;
              *)
                '${buildPackages.llvm}/bin/llvm-config' "$@" |
                  sed 's|${buildPackages.llvm}|${llvm}|g'
                ;;
            esac
            LLVM_CONFIG_WRAPPER
            chmod +x .aos-native-tools/llvm-config
            export LLVM_CONFIG=$PWD/.aos-native-tools/llvm-config
            export CLANG="${buildPackages.llvm}/bin/clang --target=${stdenv.hostPlatform.config} --sysroot=${stdenv.sdk}"

            # Query the Darwin Perl configuration using the native interpreter.
            # Config.pm is pure Perl and the versions are identical across the
            # build and host package sets, so no target executable is run.
            target_perl_config=$(find ${perl.dev}/lib -name Config.pm -print -quit)
            test -n "$target_perl_config"
            target_perl_archlib=$(dirname "$target_perl_config")
            target_perl_privlib=$(dirname "$target_perl_archlib")
            export PERL=${buildPackages.perl}/bin/perl
            export PERL5LIB="$target_perl_archlib:$target_perl_privlib"

            # Only PostgreSQL's small sysconfig queries need target Python
            # answers. The wrapper delegates every other operation to the
            # native interpreter used for source generation.
            cat > .aos-native-tools/python3 <<'PYTHON_CONFIG_WRAPPER'
            #!$CONFIG_SHELL
            if [ "$1" = -c ]; then
              case "$2" in
                *"get_config_vars('LIBPL')"*)
                  printf '%s\n' '${python3}/lib'
                  exit 0
                  ;;
                *"get_config_var('INCLUDEPY')"*)
                  printf '%s\n' '-I${python3}/include/python3.14'
                  exit 0
                  ;;
                *"get_config_vars('LIBDIR')"*)
                  printf '%s\n' '${python3}/lib'
                  exit 0
                  ;;
                *"get_config_vars('LDLIBRARY')"*)
                  printf '%s\n' 'libpython3.14.dylib'
                  exit 0
                  ;;
                *"get_config_vars('LIBS','LIBC','LIBM','BASEMODLIBS')"*)
                  printf '\n'
                  exit 0
                  ;;
              esac
            fi
            exec '${buildPackages.python3}/bin/python3' "$@"
            PYTHON_CONFIG_WRAPPER
            chmod +x .aos-native-tools/python3
            export PYTHON=$PWD/.aos-native-tools/python3

            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-nls \
              --with-llvm \
              --with-icu \
              --with-tcl \
              --with-tclconfig=${tcl}/lib \
              --with-gssapi \
              --with-ldap \
              --with-system-tzdata=${tzdata}/share/zoneinfo \
              --with-perl \
              --with-python \
              --with-pam \
              --with-uuid=e2fs \
              --with-libcurl \
              --with-libxml \
              --with-libxslt \
              --with-lz4 \
              --with-zstd \
              --with-ssl=openssl

            for macro in \
              ENABLE_GSS ENABLE_NLS USE_ICU USE_LDAP USE_LLVM USE_LIBCURL \
              USE_LIBXML USE_LIBXSLT USE_LZ4 USE_OPENSSL USE_PAM USE_ZSTD \
              HAVE_UUID_E2FS; do
              grep "^#define $macro 1$" src/include/pg_config.h
            done

            # pg_config and installed PGXS makefiles must name a compiler that
            # runs on Darwin, not the Linux-hosted cross wrapper used here.
            sed -i '/#include "common\/config_info.h"/a\
            #undef VAL_CC\
            #define VAL_CC "${llvm}/bin/clang"' \
              src/common/config_info.c
          ''
          else ''
            export LLVM_CONFIG=${llvm}/bin/llvm-config
            export CLANG=${llvm}/bin/clang
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
        script =
          if isDarwin
          then ''
            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            make install-world
            test -f "$out/share/doc/postgresql/html/index.html"
            test -f "$out/share/man/man1/postgres.1"
            test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"

            # PGXS is target-side tooling. Retarget interpreter and LLVM
            # paths recorded while Linux-native generators built the tree.
            find "$out/lib/pgxs" -type f -exec sed -i \
              -e 's|${buildPackages.perl}|${perl}|g' \
              -e 's|${buildPackages.python3}|${python3}|g' \
              -e 's|${buildPackages.llvm}|${llvm}|g' \
              -e "s|$CC|${llvm}/bin/clang|g" \
              {} +
          ''
          else ''
            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            make install-world
            test -f "$out/share/doc/postgresql/html/index.html"
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
          test -f ${self}/share/doc/postgresql/html/index.html
          test -f ${self}/share/man/man1/postgres.1
          test -n "$(find ${self}/share/locale -name '*.mo' -print -quit)"
        '';
      };
    };
  }
