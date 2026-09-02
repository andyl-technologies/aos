{
  mkDerivation,
  fetchurl,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  gnumake,
  ncurses,
  stdenv,
}: let
  version = "5.2.37";
in
  mkDerivation {
    pname = "bash";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/bash/bash-${version}.tar.gz"];
      hash = "1zr1lr6h397qs5fig0g2s6b36arikz2z0yrvgnnqfmqxrlpb56cm";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [ncurses]
      else [];
    postPatch =
      if stdenv.hostPlatform.isDarwin
      then ''
        # tparam.c calls write(2) but relies on an implicit declaration, which
        # modern Clang rejects when cross-compiling Bash for Darwin.
        sed -i '/#include <config.h>/a#include <unistd.h>' lib/termcap/tparam.c
      ''
      else "";
    preConfigure =
      if stdenv.isCross && stdenv.hostPlatform.isDarwin
      then ''
        # Bash generates builtins with a native helper. Prevent the build
        # compiler from inheriting Darwin SDK and target hardening flags.
        native_cc="$BUILD_CC"
        mkdir -p .aos-build-tools
        cat > .aos-build-tools/cc <<EOF
        #!$CONFIG_SHELL
        unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
        unset C_INCLUDE_PATH
        unset CPLUS_INCLUDE_PATH LIBRARY_PATH MACOSX_DEPLOYMENT_TARGET
        unset NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
        exec "$native_cc" "\$@"
        EOF
        chmod +x .aos-build-tools/cc
        export CC_FOR_BUILD="$PWD/.aos-build-tools/cc"
      ''
      else "";
    configureFlags =
      "--without-bash-malloc --disable-nls"
      + (
        if stdenv.hostPlatform.isDarwin
        then " --with-curses"
        else ""
      );
    makeFlags = "-j1";
    postInstall = ''
      [ -f "$out/bin/bash" ] && [ ! -e "$out/bin/sh" ] && ln -s bash "$out/bin/sh"
      rm -f "$out/bin/bashbug"
    '';

    meta = {
      description = "GNU Bourne-Again SHell";
      homepage = "https://www.gnu.org/software/bash/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
