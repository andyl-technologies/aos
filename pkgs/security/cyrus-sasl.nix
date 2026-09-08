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
          if stdenv.isCross
          then
            ''
              # makemd5 generates a target header but executes on the build
              # machine. Isolate its compiler from target paths and hardening.
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

            ''
            + (
              if stdenv.hostPlatform.isDarwin
              then ''
                # Darwin cross builds do not have an emulator for configure's
                # runtime GSSAPI probe. Preserve the established platform cache.
                export ac_cv_gssapi_supports_spnego=yes
              ''
              else if stdenv.targetRunner != null
              then ''
                # Reproduce upstream's runtime test against the target MIT
                # Kerberos library before caching the result for configure.
                cat > .aos-build-tools/gssapi-spnego-probe.c <<'EOF'
                #include <gssapi/gssapi.h>

                int main(void)
                {
                    gss_OID_desc spnego_oid = { 6, (void *) "\x2b\x06\x01\x05\x05\x02" };
                    gss_OID_set mech_set;
                    OM_uint32 min_stat;
                    int have_spnego = 0;

                    if (gss_indicate_mechs(&min_stat, &mech_set) == GSS_S_COMPLETE) {
                        gss_test_oid_set_member(&min_stat, &spnego_oid, mech_set, &have_spnego);
                        gss_release_oid_set(&min_stat, &mech_set);
                    }

                    return (!have_spnego);
                }
                EOF

                if "$CC" .aos-build-tools/gssapi-spnego-probe.c \
                  -lgssapi_krb5 -o .aos-build-tools/gssapi-spnego-probe \
                  && ${stdenv.targetRunner}/bin/aos-run-${stdenv.hostPlatform.system} \
                    .aos-build-tools/gssapi-spnego-probe; then
                  export ac_cv_gssapi_supports_spnego=yes
                else
                  echo 'target GSSAPI library does not advertise SPNEGO' >&2
                  exit 1
                fi
              ''
              else ''
                echo 'cross build cannot run the target GSSAPI SPNEGO probe' >&2
                exit 1
              ''
            )
            + ''
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
