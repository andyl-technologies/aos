##! PostgreSQL — Object-relational database server
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  bison,
  flex,
  coreutils,
  tar,
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
        docbook-xml
        docbook-xsl
      ]
      else [
        gnumake
        pkg-config
        bison
        flex
        perl
        python3
        llvm
        tcl
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
        bison
        flex
        coreutils
        pkg-config
        tar
        curl
        gettext
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
            # Build drivers must execute on Linux without adding their native
            # headers, libraries, or pkg-config files to the target search
            # environment. Reference only their executables here; target
            # counterparts remain runtime dependencies for installed PGXS.
            export BISON=${buildPackages.bison}/bin/bison
            export FLEX=${buildPackages.flex}/bin/flex
            export MSGFMT=${buildPackages.gettext}/bin/msgfmt
            export MSGMERGE=${buildPackages.gettext}/bin/msgmerge
            export PKG_CONFIG=${buildPackages.pkg-config}/bin/pkg-config
            export XGETTEXT=${buildPackages.gettext}/bin/xgettext
            export XMLLINT=${buildPackages.libxml2}/bin/xmllint
            export XSLTPROC=${buildPackages.libxslt}/bin/xsltproc

            # PostgreSQL needs native LLVM utilities to generate bitcode, but
            # must compile and link against the Darwin LLVM headers and dylib.
            mkdir -p .aos-native-tools
            cat > .aos-native-tools/llvm-config <<'LLVM_CONFIG_WRAPPER'
            #!${buildPackages.bash}/bin/bash
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
            export TCLSH=${buildPackages.tcl}/bin/tclsh9.0

            # Query the Darwin Perl configuration using the native interpreter.
            # Config.pm is pure Perl and the versions are identical across the
            # build and host package sets, so no target executable is run.
            # Net/Config.pm has the same basename and may sort before the
            # architecture configuration on x86_64. Select the latter
            # explicitly so configure sees useshrplib and libperl.dylib.
            target_perl_config=$(find ${perl.dev}/lib \
              -name Config.pm ! -path '*/Net/Config.pm' -print -quit)
            test -n "$target_perl_config"
            target_perl_archlib=$(dirname "$target_perl_config")
            target_perl_privlib=$(dirname "$target_perl_archlib")
            export PERL=${buildPackages.perl}/bin/perl
            export PERL5LIB="$target_perl_archlib:$target_perl_privlib"

            # Only PostgreSQL's small sysconfig queries need target Python
            # answers. The wrapper delegates every other operation to the
            # native interpreter used for source generation.
            cat > .aos-native-tools/python3 <<'PYTHON_CONFIG_WRAPPER'
            #!${buildPackages.bash}/bin/bash
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

            # CONFIGURE_ARGS is compiled into pg_config and the server, and
            # the generated header is also installed for extensions. Keep the
            # native wrappers active in the build makefiles, but publish only
            # the corresponding Darwin-side tool paths in that metadata.
            sed -i \
              -e "s|$PWD/.aos-native-tools/llvm-config|${llvm}/bin/llvm-config|g" \
              -e "s|$PWD/.aos-native-tools/python3|${python3}/bin/python3|g" \
              -e "s|CC=$CC|CC=${llvm}/bin/clang|g" \
              -e "s|CXX=$CXX|CXX=${llvm}/bin/clang++|g" \
              -e 's|${buildPackages.llvm}|${llvm}|g' \
              -e 's|${buildPackages.gettext}|${gettext}|g' \
              -e 's|${buildPackages.pkg-config}|${pkg-config}|g' \
              -e 's|${buildPackages.perl}|${perl}|g' \
              -e 's|${buildPackages.python3}|${python3}|g' \
              -e 's|${buildPackages.tcl}|${tcl}|g' \
              -e "s| 'PKG_CONFIG_PATH=[^']*'||g" \
              src/include/pg_config.h

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
            # PostgreSQL invokes Clang directly for LLVM bitcode, so retain
            # the libc header path normally injected by the AOS GCC wrapper.
            export CLANG="${llvm}/bin/clang -idirafter ${stdenv.cc.libc.dev}/include"
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
        script =
          if isDarwin
          then ''
            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            ${buildPackages.gnumake}/bin/make -j$NIX_BUILD_CORES world
          ''
          else ''
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
            ${buildPackages.gnumake}/bin/make install-world
            test -f "$out/share/doc/html/index.html"
            test -f "$out/share/man/man1/postgres.1"
            test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"

            # PGXS is target-side tooling. Retarget interpreter and LLVM
            # paths recorded while Linux-native generators built the tree.
            find "$out/lib/pgxs" -type f -exec sed -i \
              -e 's|${buildPackages.perl}|${perl}|g' \
              -e 's|${buildPackages.python3}|${python3}|g' \
              -e 's|${buildPackages.llvm}|${llvm}|g' \
              -e "s|$PWD/.aos-native-tools/llvm-config|${llvm}/bin/llvm-config|g" \
              -e "s|$PWD/.aos-native-tools/python3|${python3}/bin/python3|g" \
              -e "s|$CC|${llvm}/bin/clang|g" \
              -e "s|^CXX = .*|CXX = ${llvm}/bin/clang++|" \
              -e "s|^AR = .*|AR = ${llvm}/bin/llvm-ar|" \
              -e "s|^BISON = .*|BISON = ${bison}/bin/bison|" \
              -e "s|^FLEX = .*|FLEX = ${flex}/bin/flex|" \
              -e "s|^MSGFMT  = .*|MSGFMT  = ${gettext}/bin/msgfmt|" \
              -e "s|^MSGMERGE = .*|MSGMERGE = ${gettext}/bin/msgmerge|" \
              -e "s|^PKG_CONFIG[[:space:]]*= .*|PKG_CONFIG = ${pkg-config}/bin/pkg-config|" \
              -e "s|^TAR[[:space:]]*= .*|TAR = ${tar}/bin/tar|" \
              -e "s|^TCLSH[[:space:]]*= .*|TCLSH = ${tcl}/bin/tclsh9.0|" \
              -e "s|^XGETTEXT = .*|XGETTEXT = ${gettext}/bin/xgettext|" \
              -e "s|^install_bin = .*|install_bin = ${coreutils}/bin/install -c|" \
              -e "s|^MKDIR_P = .*|MKDIR_P = ${coreutils}/bin/mkdir -p|" \
              -e "s|^STRIP[[:space:]]*= .*|STRIP = ${llvm}/bin/llvm-strip|" \
              -e "s|^STRIP_STATIC_LIB = .*|STRIP_STATIC_LIB = ${llvm}/bin/llvm-strip -S|" \
              -e "s|^STRIP_SHARED_LIB = .*|STRIP_SHARED_LIB = ${llvm}/bin/llvm-strip -S|" \
              -e "s|^XMLLINT[[:space:]]*= .*|XMLLINT = ${libxml2}/bin/xmllint|" \
              -e "s|^XSLTPROC[[:space:]]*= .*|XSLTPROC = ${libxslt}/bin/xsltproc|" \
              -e "s|^abs_top_builddir = .*|abs_top_builddir = $out/lib/pgxs/src|" \
              -e "s|^abs_top_srcdir = .*|abs_top_srcdir = $out/lib/pgxs/src|" \
              {} +
          ''
          else ''
            export XML_CATALOG_FILES="${docbook-xsl}/share/xml/docbook/stylesheet/catalog.xml ${docbook-xml}/share/xml/docbook/schema/dtd/4.5/catalog.xml"
            make install-world
            test -f "$out/share/doc/html/index.html"
            test -f "$out/share/man/man1/postgres.1"
            test -n "$(find "$out/share/locale" -name '*.mo' -print -quit)"
            sed -i \
              -e "s|^abs_top_builddir = .*|abs_top_builddir = $out/lib/pgxs/src|" \
              -e "s|^abs_top_srcdir = .*|abs_top_srcdir = $out/lib/pgxs/src|" \
              "$out/lib/pgxs/src/Makefile.global"
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
