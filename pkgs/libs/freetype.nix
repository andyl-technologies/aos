##! FreeType — font rendering library
{
  mkDerivation,
  fetchurl,
  gnumake,
  zlib,
  bash,
  stdenv,
  buildPackages,
}: let
  version = "2.13.3";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
in
  mkDerivation {
    pname = "freetype";
    inherit version;

    src = fetchurl {
      urls = [
        "https://download.savannah.gnu.org/releases/freetype/freetype-${version}.tar.xz"
      ];
      hash = "sha256-BVA1BmbUJ8dNrrhdWse7NTrLpfdpVjlZlTEanG8GMok=";
    };

    buildDeps = [gnumake];
    runtimeDeps =
      [zlib]
      ++ (
        if stdenv.hostPlatform.isDarwin
        then [bash]
        else []
      );
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd freetype-${version}
        '';
      }
      {
        name = "build";
        script =
          if isDarwinCross
          then ''
            # FreeType builds apinames for the Linux build machine. Isolate
            # that compiler from the surrounding target SDK and arm64-only
            # PAC hardening before passing it through upstream's CC_BUILD.
            native_cc=${buildPackages.cc}/bin/cc
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

            CC_BUILD="$PWD/.aos-build-tools/cc-for-build" \
              $CONFIG_SHELL ./configure \
                $configureFlags \
                --prefix=$out \
                --enable-freetype-config \
                --with-zlib=yes \
                --without-bzip2 \
                --without-png \
                --without-harfbuzz \
                --without-brotli
            make -j$NIX_BUILD_CORES
          ''
          else ''
            $CONFIG_SHELL ./configure \
              $configureFlags \
              --prefix=$out \
              --enable-freetype-config \
              --with-zlib=yes \
              --without-bzip2 \
              --without-png \
              --without-harfbuzz \
              --without-brotli
            make -j$NIX_BUILD_CORES
          '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/freetype-config"
          ''
          else ''
            make install
          '';
      }
    ];

    meta = {
      description = "FreeType — font rendering library";
      homepage = "https://freetype.org";
      license = "FTL OR GPL-2.0-or-later";
    };
  }
