{
  mkDerivation,
  fetchurl,
  gnumake,
  m4,
  gmp,
  stdenv,
}: let
  version = "3.10.1";
in
  mkDerivation {
    pname = "nettle";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ftp.gnu.org/gnu/nettle/nettle-${version}.tar.gz"
        "https://mirrors.dotsrc.org/gnu/nettle/nettle-${version}.tar.gz"
      ];
      hash = "sha256-sPzdf8DN6m6A3PHdhbp5SvDVtKV+Jjl+7jvBkyctkTI=";
    };

    buildDeps = [gnumake m4];
    runtimeDeps = [gmp];
    propagatedDeps = [gmp];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd nettle-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.isCross && stdenv.hostPlatform.isDarwin
          then ''
            export CFLAGS="$CFLAGS \
              -ffile-prefix-map=$PWD=. \
              -fdebug-prefix-map=$PWD=."

            # Nettle compiles and executes hogweed's mini-gmp generator on
            # the build machine. Isolate that compiler from Darwin SDK and
            # architecture flags exported by the cross stdenv.
            native_cc="$BUILD_CC"
            mkdir -p .aos-build-tools
            cat > .aos-build-tools/cc-for-build <<EOF
            #!$CONFIG_SHELL
            unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
            unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
            unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
            exec "$native_cc" "\$@"
            EOF
            chmod +x .aos-build-tools/cc-for-build
            export CC_FOR_BUILD="$PWD/.aos-build-tools/cc-for-build"

            ./configure \
              $configureFlags \
              --prefix=$out \
              --libdir=$out/lib \
              --disable-static \
              --enable-shared \
              --disable-documentation
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --libdir=$out/lib \
              --disable-static \
              --enable-shared \
              --disable-documentation
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
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "Low-level cryptographic library (libnettle + libhogweed)";
      homepage = "https://www.lysator.liu.se/~nisse/nettle/";
      license = "LGPL-3.0-or-later";
    };
  }
