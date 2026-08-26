##! libksba — X.509 and CMS (PKCS#7) library used by GnuPG's gpgsm
{
  mkDerivation,
  fetchurl,
  gnumake,
  libgpg-error,
  bash,
  stdenv,
}: let
  version = "1.8.0";
in
  mkDerivation {
    pname = "libksba";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnupg.org/ftp/gcrypt/libksba/libksba-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/libksba/libksba-${version}.tar.bz2"
      ];
      hash = "sha256-KWuduQlXSfKqEEIC16t/0JrRBxDgB4CnCcl1SxodkpI=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [libgpg-error]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [libgpg-error];

    # The asn1-gentables build tool uses the classic struct hack — a trailing
    # `char name[1]` (src/asn1-gentables.c) that it over-allocates with
    # `xmalloc(sizeof *item + strlen(name))` and then strcpy's the full name
    # into. -fstrict-flex-arrays=3 treats `[1]` as exactly one byte, so
    # _FORTIFY_SOURCE's __strcpy_chk sees object size 1 and aborts ("buffer
    # overflow detected") while generating asn1-tables.c. Step down to level 1,
    # where `[1]` is still honoured as a flexible array; the rest of the
    # hardening (including fortify3) stays on. Mirrors the acl step-down.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libksba-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            # asn1-gentables executes on the Linux build machine. Preserve
            # this package's flexible-array hardening workaround, but remove
            # the target-only arm PAC token and every target SDK/compiler flag.
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

            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-static \
              --with-libgpg-error-prefix=${libgpg-error}
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-static \
              --with-libgpg-error-prefix=${libgpg-error}
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
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/ksba-config"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "X.509 and CMS (PKCS#7) library used by GnuPG's gpgsm";
      homepage = "https://gnupg.org/software/libksba/";
      license = "LGPL-3.0-or-later";
    };
  }
