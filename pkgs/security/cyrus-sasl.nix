##! Cyrus SASL — Pluggable authentication framework
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  file,
  krb5,
  libxcrypt,
  openssl,
  sqlite,
  stdenv,
  buildPackages,
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

    buildDeps = [gnumake pkg-config file];
    runtimeDeps =
      [krb5 openssl sqlite]
      ++ (
        if stdenv.hostPlatform.isLinux
        then [libxcrypt]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          ''
            tar xf $src
            cd cyrus-sasl-${version}

            # Cyrus SASL 2.1.28 relied on transitive time declarations which
            # current C compilers no longer accept. Both files call time(), and
            # saslutil.c additionally calls clock().
            sed -i '1i #include <time.h>' lib/saslutil.c plugins/cram.c
            # Libtool's generated configure test hard-codes a host FHS path.
            sed -i 's|/usr/bin/file|${buildPackages.file}/bin/file|g' configure
          ''
          + (
            if stdenv.isCross && stdenv.hostPlatform.isDarwin
            then ''
              # Modern Clang rejects pointer-to-array and pointer-to-struct
              # arguments where this legacy scrub helper expects bytes.
              sed -i \
                -e 's/MD5_memset(&k_ipad,/MD5_memset(k_ipad,/' \
                -e 's/MD5_memset(&k_opad,/MD5_memset(k_opad,/' \
                -e 's/MD5_memset(&tk,/MD5_memset(tk,/' \
                -e 's/MD5_memset(&hmac,/MD5_memset((POINTER) \&hmac,/' \
                -e 's/MD5_memset(hmac, 0/MD5_memset((POINTER) hmac, 0/' \
                saslauthd/md5.c
            ''
            else ""
          );
      }
      {
        name = "configure";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            # makemd5 generates a target header and executes on Linux. Isolate
            # its compiler from target SDK paths and arm64 PAC hardening.
            native_cc="$BUILD_CC"
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/cc-for-build <<EOF
            #!$CONFIG_SHELL
            native_hardening=
            for token in \$AOS_HARDENING_ENABLE; do
              case "\$token" in
                pacret) ;;
                *) native_hardening="\$native_hardening \$token" ;;
              esac
            done
            export AOS_HARDENING_ENABLE="\$native_hardening"
            unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
            exec "$native_cc" "\$@"
            EOF
            chmod +x .aos-build-tools/cc-for-build
            export CC_FOR_BUILD="$PWD/.aos-build-tools/cc-for-build"
            export CPPFLAGS_FOR_BUILD=
            export LDFLAGS_FOR_BUILD=

            # MIT Kerberos installs the SPNEGO mechanism and all of the
            # configure test's GSSAPI symbols linked successfully. The final
            # probe enumerates mechanisms at runtime, which a Linux builder
            # cannot do with the Mach-O test executable.
            export ac_cv_gssapi_supports_spnego=yes
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --enable-static \
              --enable-gssapi \
              --enable-scram \
              --with-openssl=${openssl} \
              --with-sqlite3=${sqlite}
          ''
          else ''
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
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            # Keep upstream's replacement SASL2 framework, but root its
            # otherwise hard-coded /Library destination in this package.
            make install framedir="$out/Library/Frameworks/SASL2.framework"
          ''
          else ''
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
