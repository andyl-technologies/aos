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
  sourceVersion = "5.3";
  version = "${sourceVersion}p15";

  bashPatch = number: hash:
    fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/bash/bash-${sourceVersion}-patches/bash53-${number}"];
      inherit hash;
    };

  bashPatches = [
    (bashPatch "001" "0zr8wgg1gb67vxn7ws971n1znrdinczymc688ndnpy2a6qs88q0z")
    (bashPatch "002" "009051z55plsy4jmmjdb3ys7li2jraynz99qg7n6a1qk025591g3")
    (bashPatch "003" "1vb0gnrkmz49rcfpxjcxy0v0k5278wrlkljk9gc20nizvk3xjigj")
    (bashPatch "004" "1l27jz4xzrajp0ww0rd7ylir1knrp6043y8j10pz6aam0i2x54cm")
    (bashPatch "005" "17f91flpsdws5hgbwf15zs704568n9j9n9ikiv4knhxzvd9fz8fc")
    (bashPatch "006" "047zjp4hc9q0jrp3fa2a1pihwy1i5j153z9pms8zz3pdxzfrl499")
    (bashPatch "007" "16dj7vx971q4zbagb46nya7mc6530vr5h86nzmy3qid1zyznp5y0")
    (bashPatch "008" "1d1zclczgh6j8kjv9ibycn155n1z783188n399khg2gvrcixfz09")
    (bashPatch "009" "132gy991ayjmr2rynx077rhzr749101y047043zb432bibkhzqzf")
    (bashPatch "010" "0s95wzk3zf8hh58jhz6imhqwj3183z905w7rpwc0qc7awb6g2xng")
    (bashPatch "011" "0cbmpv5nvmk4gzm0nmsvvm1c7ixkqmlx5mrywhxiv8x2bs7xz602")
    (bashPatch "012" "0ws5fnk7rpy6jiji3lws7fja0n5lgzki8i214gqxmbpbkfrpj4yp")
    (bashPatch "013" "007jg69286wam4lqd6ab5gs6zl4k3r29fill251by93yjvd9qbq4")
    (bashPatch "014" "0v398i0s7i5qrz85nfhdkxwcd6baagcclgbqb3ihg1fk06s60hxx")
    (bashPatch "015" "0vpl2h85i3gifnymc5f050mgxckyka9pwsgdgrvgc9zwwbp9rdsm")
  ];
in
  mkDerivation {
    pname = "bash";
    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/bash/bash-${sourceVersion}.tar.gz"];
      hash = "1fii1xaxbng9x0klxmxkm0xhmycngfz72jsgyrna4sgqcmlxhp0d";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [ncurses]
      else [];
    postPatch =
      ''
        # GNU Bash's official patches are authored for -p0 from the unpacked
        # source directory, unlike the repository's usual -p1 patches.
        ${builtins.concatStringsSep "\n" (map (patch: "patch --batch -p0 < ${patch}") bashPatches)}

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
