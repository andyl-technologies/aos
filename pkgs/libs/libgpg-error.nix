##! libgpg-error — error codes and runtime support for the GnuPG stack
{
  mkDerivation,
  fetchurl,
  gnumake,
  bash,
  stdenv,
  buildPackages,
}: let
  version = "1.61";
in
  mkDerivation {
    pname = "libgpg-error";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/libgpg-error/libgpg-error-${version}.tar.bz2"
      ];
      hash = "sha256-eoVBPyvDVPT4qoMrcYrxIuSJZeng65AS7mWcE8Y4XJM=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash]
      else [];
    propagatedDeps = [];

    # libgpg-error ships and installs the yat2m man-page generator
    # (doc/yat2m.c), which uses the trailing `char name[1]` struct hack —
    # over-allocated and strcpy'd into. -fstrict-flex-arrays=3 sizes `[1]` to one
    # byte, so _FORTIFY_SOURCE's __strcpy_chk aborts ("buffer overflow detected")
    # while building yat2m. Step down to level 1 (where `[1]` stays flexible);
    # fortify3 and the rest of the hardening remain on. Mirrors libksba/acl.
    hardeningDisable = ["strictflexarrays3"];
    hardeningEnable = ["strictflexarrays1"];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libgpg-error-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross
          then ''
            # mkerrcodes, mkheader, and yat2m execute on the Linux build
            # machine. Use the native compiler directly so this package's
            # strict-flex-array workaround reaches those helpers; the generic
            # Linux CC_FOR_BUILD wrapper intentionally discards target
            # hardening policy.
            native_cc="${buildPackages.cc}/bin/cc"
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
              --disable-nls
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --disable-static \
              --disable-nls
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
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/gpgrt-config"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "Common error codes and runtime support for the GnuPG stack";
      homepage = "https://gnupg.org/software/libgpg-error/";
      license = "LGPL-2.1-or-later";
    };
  }
