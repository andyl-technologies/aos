# stdenv/toolchains/gcc3_4_cross/manifest.nix - GCC 3.4 cross-tier POSIX tool manifest
{
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
  autotoolsVars = "AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true";

  crossCompiler = {
    gcc = crossGccStage2;
    binutils = crossBinutils;
    glibc = crossGlibc;
  };

  crossTool = attrs: let
    userConfigureEnv = attrs.configureEnv or "";
  in
    {
      compiler = crossCompiler;
      buildDeps = [
        crossGccStage2
        crossBinutils
      ];
      gccVersion = "3.4.6";
      cc = "${crossGccStage2}/bin/${hostPlatform.config}-gcc";
      cflags = "-O2 -isystem ${crossGlibc}/include";
      cppflags = "";
      ldflags = "-L${crossGlibc}/lib -static -Wl,--whole-archive -lnss_files -lnss_dns -lresolv -Wl,--no-whole-archive";
      configureEnv = ''
        unset CXX CXXFLAGS
        unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH LD_LIBRARY_PATH
        unset PKG_CONFIG_PATH

        mkdir -p "$TMPDIR/crossbin"
        ln -sf "${crossGccStage2}/bin/${hostPlatform.config}-gcc" "$TMPDIR/crossbin/gcc"
        ln -sf "${crossGccStage2}/bin/${hostPlatform.config}-gcc" "$TMPDIR/crossbin/cc"
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
      meta = {
        build = {
          os = "linux";
          cpu = [
            "x86_64"
            "i686"
          ];
        };
        execute = {
          os = "linux";
          cpu = ["x86_64"];
        };
      };
    }
    // attrs;

  fakeScript = name: ''
    printf '#!%s\nexit 0\n' "$AOS_BASH" > "$TMPDIR/fakebin/${name}"
    chmod +x "$TMPDIR/fakebin/${name}"
  '';

  fakeAutotools = ''
    mkdir -p "$TMPDIR/fakebin"
    for tool in autoconf autoheader aclocal automake autoreconf autom4te; do
      printf '#!%s\nexit 0\n' "$AOS_BASH" > "$TMPDIR/fakebin/$tool"
      chmod +x "$TMPDIR/fakebin/$tool"
    done
    export PATH="$TMPDIR/fakebin:$PATH"
  '';

  stripMakefileRegenRules = ''
    find . -name Makefile | while read f; do
      sed -i 's/^Makefile:.*/Makefile:/; s/^config\.status:.*/config.status:/; s/^configure:.*/configure:/' "$f"
    done
  '';
in {
  bash = crossTool {
    pname = "bash";
    version = "3.0";
    url = "https://mirrors.kernel.org/gnu/bash/bash-3.0.tar.gz";
    hash = "1i4brapyyivim7mrrrd9iii4a5yilb2wzh9k6zgcwxh0ycpxrbw7";
    configureFlags =
      tripletNoNls
      ++ [
        "--without-bash-malloc"
        "bash_cv_func_sigsetjmp=present"
      ];
    preConfigure = ''
      mkdir -p "$TMPDIR/fakebin"
      ${fakeScript "size"}
      ${fakeScript "makeinfo"}
      export PATH="$TMPDIR/fakebin:$PATH"
    '';
    buildScript = ''
      make -j1
    '';
    postInstall = ''
      test -x "$out/bin/bash" || { echo "FATAL: bash not installed"; exit 1; }
      if test ! -e "$out/bin/sh"; then
        ln -sf bash "$out/bin/sh"
      fi
      test -x "$out/bin/sh" || { echo "FATAL: sh not installed"; exit 1; }
    '';
  };

  coreutils = crossTool {
    pname = "coreutils";
    version = "5.2.1";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-5.2.1.tar.bz2";
    hash = "1m4gaqhwhpaba4n2qwsdy4spdrqx6aszrl4r8z7av4jdlyq3qckl";
    configureFlags = tripletNoNls;
    postInstall = ''
      for tool in cat chmod cp ln ls mkdir mv rm rmdir; do
        test -x "$out/bin/$tool" || { echo "FATAL: coreutils $tool not installed"; exit 1; }
      done
    '';
  };

  gnumake = crossTool {
    pname = "gnumake";
    version = "3.80";
    url = "https://mirrors.kernel.org/gnu/make/make-3.80.tar.bz2";
    hash = "050qpdwd85y7f9lhkj0i19av2nybn248m26zkl2as47wp2y1daki";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -f "$out/bin/make" || { echo "FATAL: make not installed"; exit 1; }
    '';
  };

  sed = crossTool {
    pname = "sed";
    version = "4.1.2";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.1.2.tar.gz";
    hash = "11rkzxnqjz226ifblx3y003y06kaqnw45ph6jxq2d3dpyliavq2h";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -f "$out/bin/sed" || { echo "FATAL: sed not installed"; exit 1; }
    '';
  };

  grep = crossTool {
    pname = "grep";
    version = "2.5.1";
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.5.1.tar.bz2";
    hash = "0in49mhmxsl52jyzp0qwz31xz8yvyfxsjxx17x1az01d5kvkk11l";
    configureFlags =
      tripletNoNls
      ++ [
        "--disable-perl-regexp"
      ];
    postInstall = ''
      test -f "$out/bin/grep" || { echo "FATAL: grep not installed"; exit 1; }
    '';
  };

  gawk = crossTool {
    pname = "gawk";
    version = "3.1.3";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-3.1.3.tar.bz2";
    hash = "1yhi1nzpwl206jxfm3jxyk377bmyj9lkhiyiwphfmcrg1fyzzrlz";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -f "$out/bin/gawk" || { echo "FATAL: gawk not installed"; exit 1; }
      test -f "$out/bin/gawk" && test ! -f "$out/bin/awk" && ln -sf gawk "$out/bin/awk"
    '';
  };

  findutils = crossTool {
    pname = "findutils";
    version = "4.1.20";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.1.20.tar.gz";
    hash = "1msh5bxc96jmry8gn1zm36ic87fjn8r7ffagzaq70vxavr00l5w8";
    configureFlags = tripletNoNls;
    postUnpack = ''
      : > gnulib/lib/getline.c
      : > gnulib/lib/getline.h
      find . -type f -exec touch {} + 2>/dev/null || true
    '';
    preConfigure = fakeAutotools;
    postConfigure = stripMakefileRegenRules;
    buildScript = ''
      make -j"$NIX_BUILD_CORES" ${autotoolsVars}
    '';
    installScript = ''
      make install ${autotoolsVars}
    '';
    postInstall = ''
      test -f "$out/bin/find" || { echo "FATAL: find not installed"; exit 1; }
      test -f "$out/bin/xargs" || { echo "FATAL: xargs not installed"; exit 1; }
    '';
  };

  diffutils = crossTool {
    pname = "diffutils";
    version = "2.8.1";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-2.8.1.tar.gz";
    hash = "198ja157yardrjq27pr5whbv73mn6hld0s9dfv1lkwdisd7y0k37";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -f "$out/bin/diff" || { echo "FATAL: diff not installed"; exit 1; }
    '';
  };

  tar = crossTool {
    pname = "tar";
    version = "1.14";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.14.tar.gz";
    hash = "1mz6wp9isz9qbc255x0xd6s5g4flpqyj2wdkdsffm0qhiq92yh1r";
    configureFlags = tripletNoNls;
    postInstall = ''
      test -f "$out/bin/tar" || { echo "FATAL: tar not installed"; exit 1; }
    '';
  };

  gzip = crossTool {
    pname = "gzip";
    version = "1.3.5";
    url = "https://alpha.gnu.org/gnu/gzip/gzip-1.3.5.tar.gz";
    hash = "1pkqayhb6rs3aj858wxyga4q3nha8x9y7bn5lbqad4985y5a0hm7";
    postInstall = ''
      test -f "$out/bin/gzip" || { echo "FATAL: gzip not installed"; exit 1; }
    '';
  };

  patch = crossTool {
    pname = "patch";
    version = "2.5.4";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.5.4.tar.gz";
    hash = "0wrlwv5qz02ln3m90yxmwrnv7mgdp2yidarrih1ah9ig5lcdjhmg";
    postInstall = ''
      test -f "$out/bin/patch" || { echo "FATAL: patch not installed"; exit 1; }
    '';
  };
}
