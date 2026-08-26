##! MIT Kerberos — GSSAPI authentication and Kerberos network services
{
  mkDerivation,
  fetchurl,
  gnumake,
  bison,
  pkg-config,
  perl,
  openssl,
  bash,
  stdenv,
  buildPackages,
}: let
  version = "1.22.1";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  bootstrapCmdsRevision = "c71d2d72f48995baaea76148f61002e5299841de";
  bootstrapCmdsSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/bootstrap_cmds/archive/${bootstrapCmdsRevision}.tar.gz"
    ];
    hash = "sha256-SmxCzFs5b2jIQIU5WaKxnDoQDyOybC3EhbRBMTdEvAs=";
  };
  xnuRevision = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea";
  xnuSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/xnu/archive/${xnuRevision}.tar.gz"
    ];
    hash = "sha256-B2MUbStUWbBw2AKqupUmzq1/sNVdDVG6AGmBgDAVCxU=";
  };

  # The Darwin KCM backend is generated from Mach Interface Generator defs.
  # Build Apple's generator for Linux and let it preprocess the defs with the
  # target compiler; target Mach-O executables never run on the build host.
  nativeMig =
    if !isDarwinCross
    then null
    else
      buildPackages.mkDerivation {
        pname = "darwin-mig";
        version = "2026-08-25";
        src = bootstrapCmdsSrc;

        buildDeps = [
          buildPackages.flex
          buildPackages.bison
        ];
        runtimeDeps = [
          buildPackages.bash
          buildPackages.coreutils
          buildPackages.sed
        ];
        propagatedDeps = [];

        phases = [
          {
            name = "unpack";
            script = ''
              tar xf $src
              tar xf ${xnuSrc}
              cd bootstrap_cmds-${bootstrapCmdsRevision}/migcom.tproj
            '';
          }
          {
            name = "build";
            script = ''
              cp -R ${buildPackages.darwin-sdk}/usr/include apple-headers
              chmod -R u+w apple-headers
              flex -o lexxer.c lexxer.l
              bison -y -d parser.y

              # migcom executes on Linux but consumes Darwin's public types.
              # Adapt only its private header copy to the native C runtime.
              sed -i 's/[[:space:]]*__asm("_".*$//' apple-headers/sys/cdefs.h
              sed -i \
                -e 's/__stdinp/stdin/g' \
                -e 's/__stdoutp/stdout/g' \
                -e 's/__stderrp/stderr/g' \
                apple-headers/_stdio.h
              sed -i 's/__error/__errno_location/g' apple-headers/sys/errno.h
              sed -i 's|#include <ctype.h>|#include "aos-mig-ctype.h"|' string.c
              cat > aos-mig-ctype.h <<'EOF'
              #define islower(c) ((unsigned int)((c) - 'a') <= (unsigned int)('z' - 'a'))
              #define toupper(c) (islower(c) ? ((c) - 'a' + 'A') : (c))
              EOF

              buildCC=${buildPackages.stdenv.cc}/bin/cc
              runBuildCC() (
                unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
                unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
                unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH
                unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
                exec "$buildCC" "$@"
              )
              compilerIncludes=$(runBuildCC -print-file-name=include)
              runBuildCC -nostdinc -I. -Iapple-headers -isystem "$compilerIncludes" \
                -Ulinux -U__linux -U__linux__ -D__APPLE__=1 -D__MACH__=1 \
                -D__private_extern__= -D__kernel_ptr_semantics= \
                -D__LITTLE_ENDIAN__=1 -DNDEBUG -DMIG_VERSION='"aos-mig"' \
                -o migcom \
                error.c global.c header.c lexxer.c mig.c y.tab.c \
                routine.c server.c statement.c string.c type.c user.c utils.c
            '';
          }
          {
            name = "install";
            script = ''
              mkdir -p \
                "$out/bin" \
                "$out/libexec" \
                "$out/share/man/man1" \
                "$out/share/mig/mach"
              cp migcom "$out/libexec/migcom"
              cp mig.sh "$out/libexec/mig-driver"
              cp -R ../../xnu-${xnuRevision}/osfmk/mach/. "$out/share/mig/mach/"
              chmod 0755 "$out/libexec/migcom" "$out/libexec/mig-driver"
              sed -i \
                -e '1c #!${buildPackages.bash}/bin/bash' \
                -e 's|`/usr/bin/arch`|`uname -m`|' \
                -e 's|/usr/bin/mktemp|${buildPackages.coreutils}/bin/mktemp|' \
                -e 's|/bin/rmdir|${buildPackages.coreutils}/bin/rmdir|' \
                "$out/libexec/mig-driver"

              cat > "$out/bin/mig" <<'EOF'
              #!${buildPackages.bash}/bin/bash
              set -e
              migcc="''${MIGCC:-''${CC:-cc}}"
              case "''${AOS_TARGET_ARCH:-}" in
                aarch64 | arm64) migarch=arm64 ;;
                x86_64) migarch=x86_64 ;;
                *)
                  case "$("$migcc" -dumpmachine)" in
                    aarch64-* | arm64-*) migarch=arm64 ;;
                    x86_64-*) migarch=x86_64 ;;
                    *) echo "mig: cannot determine target architecture" >&2; exit 1 ;;
                  esac
                  ;;
              esac
              export MIGCC="$migcc"
              export MIGCOM="@out@/libexec/migcom"
              exec "@out@/libexec/mig-driver" \
                -arch "$migarch" -I@out@/share/mig "$@"
              EOF
              sed -i "s|@out@|$out|g" "$out/bin/mig"
              chmod 0755 "$out/bin/mig"
              cp mig.1 migcom.1 "$out/share/man/man1/"
            '';
          }
        ];
      };
in
  mkDerivation {
    pname = "krb5";
    inherit version;

    src = fetchurl {
      urls = [
        "https://kerberos.org/dist/krb5/1.22/krb5-${version}.tar.gz"
      ];
      hash = "sha256-GogyuMrZI+u/E5T2fi789B46SfRgKFpm41reyPoAU68=";
    };

    buildDeps =
      [gnumake bison pkg-config perl]
      ++ (
        if isDarwinCross
        then [nativeMig]
        else []
      );
    runtimeDeps =
      [openssl]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script =
          if isDarwinCross
          then ''
            tar xf $src
            cd krb5-${version}/src

            # Apple's resolver keeps the legacy HEADER and C_IN aliases in
            # its compatibility header. MIT Kerberos still uses those aliases
            # when ns_initparse/res_nsearch are unavailable.
            sed -i \
              '/#include <arpa\/nameser.h>/a #include <arpa/nameser_compat.h>' \
              lib/krb5/os/dnsglue.h

            # Apple's open SDK exposes the public libresolv API, not Libinfo's
            # private dns_open family. Keep DNS realm/KDC discovery by using
            # MIT Kerberos's portable res_init/res_search implementation.
            sed -i \
              's/#if defined(__APPLE__)/#if defined(__APPLE__) \&\& defined(KRB5_USE_PRIVATE_DNS_API)/' \
              lib/krb5/os/dnsglue.c

            # The proprietary Kerberos framework supplies Apple's CCAPI cache.
            # Use the upstream KCM cache backend generated by native MIG instead
            # while retaining the complete Mach RPC cache implementation.
            sed -i \
              -e 's/macos_defccname=API:/macos_defccname=KCM:/' \
              -e 's/MACOS_FRAMEWORK="-framework Kerberos"/MACOS_FRAMEWORK=/' \
              configure
          ''
          else ''
            tar xf $src
            cd krb5-${version}/src
          '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
            # MIT Kerberos insists on executing a constructor/destructor
            # probe. Clang's attributes are supported by Mach-O, but target
            # executables cannot run on the Linux builder, so seed the result.
            export krb5_cv_attr_constructor_destructor=yes,yes
            # Darwin's libc implements POSIX numbered printf conversions.
            # Configure otherwise insists on executing the target probe.
            export ac_cv_printf_positional=yes

            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --with-crypto-impl=openssl \
              --with-tls-impl=openssl
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-shared \
              --with-crypto-impl=openssl \
              --with-tls-impl=openssl
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
            make install
            for script in compile_et k5srvutil krb5-send-pr; do
              [ -f "$out/bin/$script" ] || continue
              sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/$script"
            done
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
        pname = "tool-krb5-config";
        tool = self;
        command = "krb5-config --version";
      };

      soname = testing.mkSONAMECheck {
        pkg = self;
        libs = ["libkrb5.so" "libgssapi_krb5.so"];
      };
    };

    meta = {
      description = "MIT Kerberos and GSSAPI implementation";
      homepage = "https://web.mit.edu/kerberos/";
      license = "MIT";
    };
  }
