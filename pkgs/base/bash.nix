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
      ''
        # Configure is generated with a host /bin/sh shebang. Run it through the
        # AOS stdenv shell instead of the sandbox host shell.
        sed -i '1c#!${stdenv.shell}' configure
      ''
      + (
        if stdenv.isCross
        then ''
          # tparam.c calls write(2) but relies on an implicit declaration, which
          # current target compilers reject while cross-building Bash.
          sed -i '/#include <config.h>/a#include <unistd.h>' lib/termcap/tparam.c
        ''
        else ""
      );
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
    # Bash's makefiles invoke helper scripts through $(SHELL).
    makeFlags = "SHELL=${stdenv.shell}";
    postInstall = ''
      [ -f "$out/bin/bash" ] && [ ! -e "$out/bin/sh" ] && ln -s bash "$out/bin/sh"
      rm -f "$out/bin/bashbug"

      # Loadable builtins have no shared-library suffix, so the generic fixup
      # cannot identify them by name. Strip their build-only compiler paths.
      for module in "$out/lib/bash"/*; do
        if readelf -h "$module" >/dev/null 2>&1; then
          "$STRIP" --strip-unneeded "$module"
        fi
      done

      # Keep the installed loadable-builtin sample usable on its target host
      # without retaining the Linux cross compiler or native coreutils.
      sed -i \
        -e 's|^INSTALL = .*|INSTALL = install|' \
        -e 's|^CC = .*|CC = cc|' \
        -e 's|^SHOBJ_CC = .*|SHOBJ_CC = cc|' \
        -e 's|^SHELL = .*|SHELL = bash|' \
        "$out/lib/bash/Makefile.inc"
    '';

    meta = {
      description = "GNU Bourne-Again SHell";
      homepage = "https://www.gnu.org/software/bash/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
