##! Native Mach Interface Generator for Darwin OpenJDK cross builds.
##!
##! MIG emits target C sources but is itself a Linux build-time executable.
##! Keep it private to the Java bootstrap helpers so no native ELF enters a
##! published Darwin SDK or target runtime closure.
{
  fetchurl,
  buildPackages,
}: let
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
in
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
  }
