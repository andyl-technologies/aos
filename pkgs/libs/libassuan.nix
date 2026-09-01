##! libassuan — IPC library implementing the Assuan protocol used by GnuPG
{
  mkDerivation,
  fetchurl,
  gnumake,
  libgpg-error,
  bash,
  stdenv,
}: let
  version = "3.0.2";
in
  mkDerivation {
    pname = "libassuan";
    inherit version;

    src = fetchurl {
      urls = [
        "https://gnupg.org/ftp/gcrypt/libassuan/libassuan-${version}.tar.bz2"
        "https://mirrors.dotsrc.org/gcrypt/libassuan/libassuan-${version}.tar.bz2"
      ];
      hash = "sha256-0pMc2tJm5jNRD5lw4aLzRgVeNRuxn5t4kSR1uAdMNvY=";
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

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libassuan-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            # mkheader executes on the Linux build machine. Retain native
            # hardening, except for Darwin arm's target-only PAC mode, and
            # keep every target SDK/compiler flag out of its invocation.
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

            # gpgrt-config is a target shell script. Execute it with the native
            # configure shell while making it resolve the target .pc metadata.
            cat > .aos-build-tools/gpgrt-config <<EOF
            #!$CONFIG_SHELL
            exec "$CONFIG_SHELL" ${libgpg-error}/bin/gpgrt-config "\$@"
            EOF
            chmod +x .aos-build-tools/gpgrt-config
            export GPGRT_CONFIG="$PWD/.aos-build-tools/gpgrt-config"
            export PKG_CONFIG_LIBDIR=
            export PKG_CONFIG_PATH="${libgpg-error}/lib/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"

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
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/libassuan-config"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "IPC library implementing the Assuan protocol used by GnuPG";
      homepage = "https://gnupg.org/software/libassuan/";
      license = "LGPL-2.1-or-later";
    };
  }
