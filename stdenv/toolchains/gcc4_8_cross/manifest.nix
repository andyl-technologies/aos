# stdenv/toolchains/gcc4_8_cross/manifest.nix - GCC 4.8 cross-tier POSIX tool manifest
{
  buildPlatform,
  hostPlatform,
  crossGccStage2,
  crossBinutils,
  crossGlibc,
  bzip2,
  xz,
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
      gccVersion = "4.8.5";
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
    version = "4.2";
    url = "https://mirrors.kernel.org/gnu/bash/bash-4.2.tar.gz";
    hash = "sha256-onoReeycCDDGXGql19q2D3zhoqYIYYVw+Wv6culas9g=";
    fetchMode = "url";
    makeInfo = "true";
    configureFlags =
      tripletNoNls
      ++ [
        "--without-bash-malloc"
        "bash_cv_func_sigsetjmp=present"
      ];
    preConfigure = ''
      mkdir -p "$TMPDIR/fakebin"
      # Bash's generated Makefile invokes `autoconf` literally when coarse
      # timestamp resolution makes configure appear stale.  Keep the shipped
      # configure script instead of introducing an unavailable regeneration
      # tool into this early cross tier.
      ${fakeScript "autoconf" "exit 0"}
      ${fakeScript "size" "exit 0"}
      ${fakeScript "makeinfo" "exit 0"}
      export PATH="$TMPDIR/fakebin:$PATH"
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
    meta = gnuMeta "GNU Bourne-Again SHell, version 4.2" "https://www.gnu.org/software/bash/" "GPL-3.0-or-later";
  };

  coreutils = crossTool {
    pname = "coreutils";
    version = "8.22";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.22.tar.xz";
    hash = "sha256-Wz6UmYFSwBfmx11WubmUGI63G/RtQDimQsuRQfb/EhI=";
    fetchMode = "url";
    buildDeps = [xz];
    makeInfo = "true";
    configureInSource = true;
    configureFlags = tripletNoNls;
    postFreeze = ''
      touch -t 200001010200.00 .version .tarball-version src/fs.h src/version.c src/version.h lib/config.hin 2>/dev/null || true
      sed -i '/_GL_WARN_ON_USE (gets,/d' lib/stdio.in.h 2>/dev/null || true
    '';
    postConfigure = ''
      printf '#!%s\necho ".TH dummy 1"\n' "$AOS_BASH" > man/dummy-man
      chmod +x man/dummy-man
      printf '#include <config.h>\nchar const *Version = "8.22";\n' > src/version.c
      printf 'extern char const *Version;\n' > src/version.h
      chmod a-w src/version.c src/version.h
      touch src/fs.h .version .tarball-version man/*.1 man/*.x 2>/dev/null || true
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
    meta = gnuMeta "GNU core utilities (ls, cat, cp, mv, etc.), version 8.22" "https://www.gnu.org/software/coreutils/" "GPL-3.0-or-later";
  };

  gnumake = crossTool {
    pname = "gnumake";
    version = "4.2.1";
    url = "https://mirrors.kernel.org/gnu/make/make-4.2.1.tar.bz2";
    hash = "sha256-1uJivzYBtC0rHk74MQAp4dzyAIPFRGtLeqZwgf3/xYk=";
    fetchMode = "url";
    srcName = "make-4.2.1.tar.bz2";
    buildDeps = [bzip2];
    configureFlags = tripletNoNls;
    postInstall = ''
      test -x "$out/bin/make" || { echo "FATAL: make not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU Make build automation tool, version 4.2.1" "https://www.gnu.org/software/make/" "GPL-3.0-or-later";
  };

  sed = crossTool {
    pname = "sed";
    version = "4.2.2";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.2.2.tar.bz2";
    hash = "sha256-8EjRg42ihMi8l1PkUGuFoeDMHqiZnTb2mVvLlGDN29c=";
    fetchMode = "url";
    buildDeps = [bzip2];
    makeInfo = "true";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -x "$out/bin/sed" || { echo "FATAL: sed not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU stream editor, version 4.2.2" "https://www.gnu.org/software/sed/" "GPL-3.0-or-later";
  };

  grep = crossTool {
    pname = "grep";
    version = "2.20";
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.20.tar.xz";
    hash = "sha256-8K9FK8DQlGS20Im21WoKPBZnLp7ZEY++N7C2rq8GmmU=";
    fetchMode = "url";
    buildDeps = [xz];
    makeInfo = "true";
    configureFlags =
      tripletNoNls
      ++ ["--disable-perl-regexp"];
    postInstall = ''
      test -x "$out/bin/grep" || { echo "FATAL: grep not installed"; exit 1; }
      test -x "$out/bin/egrep" || { echo "FATAL: egrep not installed"; exit 1; }
      test -x "$out/bin/fgrep" || { echo "FATAL: fgrep not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU grep pattern matching utility, version 2.20" "https://www.gnu.org/software/grep/" "GPL-3.0-or-later";
  };

  gawk = crossTool {
    pname = "gawk";
    version = "4.0.2";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-4.0.2.tar.xz";
    hash = "sha256-IeHyjFG1Fg8KS/GnNcYQm0ajvWpD3oCOq8IcF7sCbRM=";
    fetchMode = "url";
    buildDeps = [xz];
    makeInfo = "true";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -x "$out/bin/gawk" || { echo "FATAL: gawk not installed"; exit 1; }
      if test ! -e "$out/bin/awk"; then
        ln -sf gawk "$out/bin/awk"
      fi
      test -x "$out/bin/awk" || { echo "FATAL: awk not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU awk pattern scanning and processing language, version 4.0.2" "https://www.gnu.org/software/gawk/" "GPL-3.0-or-later";
  };

  findutils = crossTool {
    pname = "findutils";
    version = "4.6.0";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.6.0.tar.gz";
    hash = "sha256-3tTJ9zcxzUj+w7a9rMzolkc7bY4zfpYS4WzxQxuxFp0=";
    fetchMode = "url";
    makeInfo = "true";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -x "$out/bin/find" || { echo "FATAL: find not installed"; exit 1; }
      test -x "$out/bin/xargs" || { echo "FATAL: xargs not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU find, xargs, and locate utilities, version 4.6.0" "https://www.gnu.org/software/findutils/" "GPL-3.0-or-later";
  };

  diffutils = crossTool {
    pname = "diffutils";
    version = "3.3";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.3.tar.xz";
    hash = "sha256-ol6JqKtl/e0XMeQYa+G7Jc2pZ4NLbflzWZzc1avfwZw=";
    fetchMode = "url";
    buildDeps = [xz];
    makeInfo = "true";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -x "$out/bin/diff" || { echo "FATAL: diff not installed"; exit 1; }
      test -x "$out/bin/cmp" || { echo "FATAL: cmp not installed"; exit 1; }
      test -x "$out/bin/diff3" || { echo "FATAL: diff3 not installed"; exit 1; }
      test -x "$out/bin/sdiff" || { echo "FATAL: sdiff not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 3.3" "https://www.gnu.org/software/diffutils/" "GPL-3.0-or-later";
  };

  tar = crossTool {
    pname = "tar";
    version = "1.26";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.26.tar.bz2";
    hash = "sha256-WlNp9GRQKlmOk4ApwxDUs6vVHmu439BFZj5hyOqfbUE=";
    fetchMode = "url";
    buildDeps = [bzip2];
    makeInfo = "true";
    configureFlags = tripletNoNls;
    postFreeze = ''
      sed -i '/_GL_WARN_ON_USE (gets,/d' gnu/stdio.in.h 2>/dev/null || true
    '';
    postInstall = ''
      test -x "$out/bin/tar" || { echo "FATAL: tar not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU tar archiving utility, version 1.26" "https://www.gnu.org/software/tar/" "GPL-3.0-or-later";
  };

  gzip = crossTool {
    pname = "gzip";
    version = "1.5";
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.5.tar.xz";
    hash = "sha256-msIKOEGhJGqL7dgA6h+5PvdlIVNdictZOX0mcCa2oXM=";
    fetchMode = "url";
    buildDeps = [xz];
    makeInfo = "true";
    configureFlags = tripletBuildHost;
    postInstall = ''
      test -x "$out/bin/gzip" || { echo "FATAL: gzip not installed"; exit 1; }
      test -x "$out/bin/gunzip" || { echo "FATAL: gunzip not installed"; exit 1; }
      test -x "$out/bin/zcat" || { echo "FATAL: zcat not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU gzip compression utility, version 1.5" "https://www.gnu.org/software/gzip/" "GPL-3.0-or-later";
  };

  patch = crossTool {
    pname = "patch";
    version = "2.7.1";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.7.1.tar.xz";
    hash = "sha256-kSS6RtsKvYc9CZXCyogOgSUmdrtsA+CjffxfYIqbDOs=";
    fetchMode = "url";
    buildDeps = [xz];
    makeInfo = "true";
    configureFlags = tripletBuildHost;
    postInstall = ''
      test -x "$out/bin/patch" || { echo "FATAL: patch not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU patch file patching utility, version 2.7.1" "https://www.gnu.org/software/patch/" "GPL-3.0-or-later";
  };
}
