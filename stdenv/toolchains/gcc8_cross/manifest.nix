# stdenv/toolchains/gcc8_cross/manifest.nix - GCC 8 cross-tier POSIX tool manifest
{
  prev,
  buildPlatform,
  hostPlatform,
  crossGccStage2,
  crossBinutils,
  crossGlibc,
}: let
  tripletBuildHost = [
    "--build=${buildPlatform.config}"
    "--host=${hostPlatform.config}"
  ];

  tripletNoNls = tripletBuildHost ++ ["--disable-nls"];
  autotoolsVars = "AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true";

  crossCompiler = {
    gcc = crossGccStage2;
    binutils = crossBinutils;
    glibc = crossGlibc;
  };

  crossTool = attrs: let
    userBuildDeps = attrs.buildDeps or [];
    userConfigureEnv = attrs.configureEnv or "";
    userMeta = attrs.meta or {};
    passthruAttrs = builtins.removeAttrs attrs ["buildDeps" "configureEnv" "meta"];
  in
    {
      compiler = crossCompiler;
      buildDeps =
        [
          crossGccStage2
          crossBinutils
        ]
        ++ userBuildDeps;
      gccVersion = "8.5.0";
      cc = "${crossGccStage2}/bin/${hostPlatform.config}-gcc";
      cxx = "${crossGccStage2}/bin/${hostPlatform.config}-g++";
      cflags = "-O2 -isystem ${crossGlibc}/include";
      cppflags = "";
      cxxflags = "-O2 -isystem ${crossGlibc}/include";
      ldflags = "-L${crossGlibc}/lib -static";
      configureEnv = ''
        unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH LD_LIBRARY_PATH
        unset PKG_CONFIG_PATH

        mkdir -p "$TMPDIR/crossbin"
        ln -sf "${crossGccStage2}/bin/${hostPlatform.config}-gcc" "$TMPDIR/crossbin/gcc"
        ln -sf "${crossGccStage2}/bin/${hostPlatform.config}-gcc" "$TMPDIR/crossbin/cc"
        ln -sf "${crossGccStage2}/bin/${hostPlatform.config}-g++" "$TMPDIR/crossbin/g++"
        ln -sf "${crossGccStage2}/bin/${hostPlatform.config}-g++" "$TMPDIR/crossbin/c++"
        for tool in ld ar ranlib strip nm objdump size; do
          ln -sf "${crossBinutils}/bin/${hostPlatform.config}-$tool" "$TMPDIR/crossbin/$tool"
        done
        export PATH="$TMPDIR/crossbin:$PATH"

        export LD="${crossBinutils}/bin/${hostPlatform.config}-ld"
        export AR="${crossBinutils}/bin/${hostPlatform.config}-ar"
        export RANLIB="${crossBinutils}/bin/${hostPlatform.config}-ranlib"
        export STRIP="${crossBinutils}/bin/${hostPlatform.config}-strip"
        export NM="${crossBinutils}/bin/${hostPlatform.config}-nm"
        export OBJDUMP="${crossBinutils}/bin/${hostPlatform.config}-objdump"
        export SIZE="${crossBinutils}/bin/${hostPlatform.config}-size"

        # glibc provides mktime; gnulib's cross-compile fallback collides with libc.a.
        export gl_cv_func_working_mktime=yes

        ${userConfigureEnv}
      '';
      meta =
        {
          build = {
            os = "linux";
            cpu = [buildPlatform.parsed.cpu.name];
          };
          execute = {
            os = "linux";
            cpu = [hostPlatform.parsed.cpu.name];
          };
        }
        // userMeta;
    }
    // passthruAttrs;

  fakeScript = name: body: ''
    printf '#!%s\n%s\n' "$AOS_BASH" ${builtins.toJSON body} > "$TMPDIR/fakebin/${name}"
    chmod +x "$TMPDIR/fakebin/${name}"
  '';

  gnuMeta = description: homepage: license: {
    inherit description homepage license;
  };
in {
  bash = crossTool {
    pname = "bash";
    version = "4.4";
    url = "https://mirrors.kernel.org/gnu/bash/bash-4.4.tar.gz";
    hash = "11pcg69yhvfqj51iqm9kxmsinjkdlfz51cjp9mvg727fk60224vw";
    buildDeps = [
      prev.gcc
      prev.glibc
    ];
    makeInfo = "true";
    configureFlags =
      tripletNoNls
      ++ [
        "--without-bash-malloc"
        "bash_cv_func_sigsetjmp=present"
      ];
    preConfigure = ''
      mkdir -p "$TMPDIR/fakebin"
      ${fakeScript "size" "exit 0"}
      ${fakeScript "makeinfo" "exit 0"}
      export PATH="$TMPDIR/fakebin:$PATH"
    '';
    configureEnv = ''
      export CC_FOR_BUILD="${prev.gcc}/bin/gcc"
      export BUILD_CC="${prev.gcc}/bin/gcc"
      export CFLAGS_FOR_BUILD="-O2 -isystem ${prev.glibc}/include"
      export CPPFLAGS_FOR_BUILD="-isystem ${prev.glibc}/include"
      export LDFLAGS_FOR_BUILD="-L${prev.glibc}/lib -static"
      export LIBS_FOR_BUILD=""
    '';
    postConfigure = ''
      sed -i \
        's|^LIBS_FOR_BUILD =.*|LIBS_FOR_BUILD = -L${prev.glibc}/lib -ldl|' \
        support/Makefile
    '';
    postFreeze = ''
            sed -i '/^int lastpipe_opt = 0;/a\
      #if !defined (JOB_CONTROL)\
      #  define job_control 0\
      #endif' execute_cmd.c
    '';
    buildScript = ''
      make -j1 ${autotoolsVars}
    '';
    installScript = ''
      make install ${autotoolsVars}
    '';
    postInstall = ''
      test -x "$out/bin/bash" || { echo "FATAL: bash not installed"; exit 1; }
      if test ! -e "$out/bin/sh"; then
        ln -sf bash "$out/bin/sh"
      fi
      test -x "$out/bin/sh" || { echo "FATAL: sh not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU Bourne-Again SHell, version 4.4" "https://www.gnu.org/software/bash/" "GPL-3.0-or-later";
  };

  coreutils = crossTool {
    pname = "coreutils";
    version = "8.30";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.30.tar.xz";
    hash = "0pp6vvpzw0v6s45yq58cszrh514a5v8jq32321apszw7rbffkslb";
    makeInfo = "true";
    configureInSource = true;
    configureFlags = tripletNoNls;
    postConfigure = ''
      printf '#!%s\necho ".TH dummy 1"\n' "$AOS_BASH" > man/dummy-man
      chmod +x man/dummy-man
      sed -i \
        's|$(src_libstdbuf_so_LDFLAGS) $(LDFLAGS) -o $@|$(src_libstdbuf_so_LDFLAGS) -L${crossGlibc}/lib -o $@|' \
        Makefile
      test -f src/fs.h && touch src/fs.h
      touch .version .tarball-version man/*.1 man/*.x 2>/dev/null || true
    '';
    buildScript = ''
      make -j"$NIX_BUILD_CORES" ${autotoolsVars} -k || true
      test -f src/ls || { echo "FATAL: coreutils binaries not built"; exit 1; }
    '';
    installScript = ''
      make install-exec ${autotoolsVars}
    '';
    postInstall = ''
      for tool in cat chmod cp env false head ln ls mkdir mv printf rm rmdir sleep sort tail tr true wc; do
        test -x "$out/bin/$tool" || { echo "FATAL: coreutils $tool not installed"; exit 1; }
      done
    '';
    meta = gnuMeta "GNU core utilities (ls, cat, cp, mv, etc.), version 8.30" "https://www.gnu.org/software/coreutils/" "GPL-3.0-or-later";
  };

  gnumake = crossTool {
    pname = "gnumake";
    version = "4.3";
    url = "https://mirrors.kernel.org/gnu/make/make-4.3.tar.gz";
    hash = "17z72ib90c3218ic02maxdxy40d3sdxhzbnmxs9myiy25ysxb434";
    makeInfo = "true";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -x "$out/bin/make" || { echo "FATAL: make not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU Make build automation tool, version 4.3" "https://www.gnu.org/software/make/" "GPL-3.0-or-later";
  };

  sed = crossTool {
    pname = "sed";
    version = "4.5";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.5.tar.xz";
    hash = "1hds0a4k5z2llh9qdkxmmvppc2c8xa3j0jx9ljjy231kwz38l6n9";
    makeInfo = "true";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -x "$out/bin/sed" || { echo "FATAL: sed not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU stream editor, version 4.5" "https://www.gnu.org/software/sed/" "GPL-3.0-or-later";
  };

  grep = crossTool {
    pname = "grep";
    version = "3.1";
    url = "https://mirrors.kernel.org/gnu/grep/grep-3.1.tar.xz";
    hash = "0msnadmbcq7a7pk23zyllhmmaa7p7my6kqjgzwqmfrwd3qp68w75";
    makeInfo = "true";
    configureFlags =
      tripletNoNls
      ++ ["--disable-perl-regexp"];
    installScript = ''
      make install-exec ${autotoolsVars}
    '';
    postInstall = ''
      test -x "$out/bin/grep" || { echo "FATAL: grep not installed"; exit 1; }
      test -x "$out/bin/egrep" || { echo "FATAL: egrep not installed"; exit 1; }
      test -x "$out/bin/fgrep" || { echo "FATAL: fgrep not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU grep pattern matching utility, version 3.1" "https://www.gnu.org/software/grep/" "GPL-3.0-or-later";
  };

  gawk = crossTool {
    pname = "gawk";
    version = "4.2.1";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-4.2.1.tar.xz";
    hash = "01giqrnwhndrja2jqw54w92bq8qwclypj75x0758j1axc6brzc2b";
    makeInfo = "true";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -x "$out/bin/gawk" || { echo "FATAL: gawk not installed"; exit 1; }
      if test ! -e "$out/bin/awk"; then
        ln -sf gawk "$out/bin/awk"
      fi
      test -x "$out/bin/awk" || { echo "FATAL: awk not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU awk pattern scanning and processing language, version 4.2.1" "https://www.gnu.org/software/gawk/" "GPL-3.0-or-later";
  };

  findutils = crossTool {
    pname = "findutils";
    version = "4.6.0";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.6.0.tar.gz";
    hash = "0aq6sck5sqpbzia1322fk3zyirkwbn909r7mlb6c2yz49m1fcw9d";
    makeInfo = "true";
    configureFlags = tripletNoNls;
    cppflags = "-isystem ${crossGlibc}/include -D_IO_ftrylockfile -D_IO_IN_BACKUP=0x100 -include sys/sysmacros.h";
    postInstall = ''
      test -x "$out/bin/find" || { echo "FATAL: find not installed"; exit 1; }
      test -x "$out/bin/xargs" || { echo "FATAL: xargs not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU find, xargs, and locate utilities, version 4.6.0" "https://www.gnu.org/software/findutils/" "GPL-3.0-or-later";
  };

  diffutils = crossTool {
    pname = "diffutils";
    version = "3.6";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.6.tar.xz";
    hash = "09n0jhyb372c5203g18flpik9mfl0qk9i33lch1r8y114rlvw2r1";
    makeInfo = "true";
    configureFlags = tripletNoNls;
    installScript = ''
      make install-exec ${autotoolsVars}
    '';
    postUnpack = ''
            if [ -f man/help2man ]; then
              printf '#!%s\nexit 0\n' "$AOS_BASH" > man/help2man
              chmod +x man/help2man
              find . -name '*.1' -exec touch {} + 2>/dev/null || true
            fi
            sed -i '/# define optopt __GETOPT_ID (optopt)/a\
      # ifdef _GETOPT_CORE_H\
      #  undef _GETOPT_CORE_H\
      # endif' lib/getopt-pfx-core.h
            sed -i '/# define option __GETOPT_ID (option)/a\
      # ifdef _GETOPT_EXT_H\
      #  undef _GETOPT_EXT_H\
      # endif' lib/getopt-pfx-ext.h
    '';
    postInstall = ''
      test -x "$out/bin/diff" || { echo "FATAL: diff not installed"; exit 1; }
      test -x "$out/bin/cmp" || { echo "FATAL: cmp not installed"; exit 1; }
      test -x "$out/bin/diff3" || { echo "FATAL: diff3 not installed"; exit 1; }
      test -x "$out/bin/sdiff" || { echo "FATAL: sdiff not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 3.6" "https://www.gnu.org/software/diffutils/" "GPL-3.0-or-later";
  };

  tar = crossTool {
    pname = "tar";
    version = "1.30";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.30.tar.xz";
    hash = "0i9yss8az1nkiw5da1i0ykblbrhns2kax0m3f4nyj1lq0v73fi1j";
    makeInfo = "true";
    configureFlags = tripletNoNls;
    postFreeze = ''
      sed -i '/_GL_WARN_ON_USE (gets,/d' gnu/stdio.in.h 2>/dev/null || true
    '';
    postInstall = ''
      test -x "$out/bin/tar" || { echo "FATAL: tar not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU tar archiving utility, version 1.30" "https://www.gnu.org/software/tar/" "GPL-3.0-or-later";
  };

  gzip = crossTool {
    pname = "gzip";
    version = "1.9";
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.9.tar.xz";
    hash = "0hjbnzqyhbnphcz5z5dwkbkcynjcn32mwqyj5p6ispn0jga31i2n";
    makeInfo = "true";
    configureFlags = tripletBuildHost;
    cppflags = "-isystem ${crossGlibc}/include -D_IO_ftrylockfile -D_IO_IN_BACKUP=0x100";
    postInstall = ''
      test -x "$out/bin/gzip" || { echo "FATAL: gzip not installed"; exit 1; }
      test -x "$out/bin/gunzip" || { echo "FATAL: gunzip not installed"; exit 1; }
      test -x "$out/bin/zcat" || { echo "FATAL: zcat not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU gzip compression utility, version 1.9" "https://www.gnu.org/software/gzip/" "GPL-3.0-or-later";
  };

  patch = crossTool {
    pname = "patch";
    version = "2.7.6";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.7.6.tar.xz";
    hash = "1yiy0xq1ha193yga0canc9ijw4hbd92c93l7ksqlhmzsn2yph39n";
    makeInfo = "true";
    configureFlags = tripletBuildHost;
    postInstall = ''
      test -x "$out/bin/patch" || { echo "FATAL: patch not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU patch file patching utility, version 2.7.6" "https://www.gnu.org/software/patch/" "GPL-3.0-or-later";
  };
}
