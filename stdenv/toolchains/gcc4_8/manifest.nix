# stdenv/toolchains/gcc4_8/manifest.nix - GCC 4.8 tier POSIX tool manifest
{
  buildPlatform,
  hostPlatform,
  xz,
  bzip2,
  m4,
  flex,
  bison,
  perl,
  autoconf,
  automake,
  texinfo,
  help2man,
}: let
  tripletBuildHost = [
    "--build=${hostPlatform.config}"
    "--host=${hostPlatform.config}"
  ];

  tripletBuildHostTarget =
    tripletBuildHost
    ++ [
      "--target=${hostPlatform.config}"
    ];

  tripletNoNls = tripletBuildHostTarget ++ ["--disable-nls"];
  tripletBuildHostNoNls = tripletBuildHost ++ ["--disable-nls"];
  autotoolsVars = "AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true";
  autotoolsDeps = [
    m4
    flex
    bison
    autoconf
    automake
    texinfo
    help2man
  ];

  gnuMeta = description: homepage: license: {
    inherit description homepage license;
  };

  gcc48 = attrs:
    attrs
    // {
      gccVersion = "4.8.5";
    };
in {
  perl = gcc48 {
    pname = "perl";
    version = "5.16.3";
    url = "https://www.cpan.org/src/5.0/perl-5.16.3.tar.bz2";
    hash = "sha256-xv8frhbCXKsvmg5eilzs0UO+grSmVm4ujjpRA5v9GvY=";
    freezeAutotoolsTimestamps = false;
    configureEnv = ''
      PWD_CMD="$(type -P pwd)"
      export PWD_CMD
    '';
    configureScript = ''
      sed -i "s|'/bin/pwd'|'$PWD_CMD', '/bin/pwd'|" dist/Cwd/Cwd.pm
      sed -i "s|'/bin/pwd'|'$PWD_CMD', '/bin/pwd'|" lib/Cwd.pm 2>/dev/null || true

      sed -i \
        -e "s|/usr/include/errno.h|$AOS_GLIBC/include/errno.h|g" \
        -e "s|/usr/local/include/errno.h|$AOS_GLIBC/include/errno.h|g" \
        ext/Errno/Errno_pm.PL

      ./Configure \
        -des \
        -Dprefix="$out" \
        -Dcc="$CC" \
        -Dar="$AR" \
        -Dnm="$NM" \
        -Dranlib="$RANLIB" \
        -Dsh="$AOS_BASH" \
        -Dlocincpth="$AOS_GLIBC/include" \
        -Dloclibpth="$AOS_GLIBC/lib" \
        -Dglibpth="$AOS_GLIBC/lib" \
        -Dusrinc="$AOS_GLIBC/include" \
        -Dccflags="$CFLAGS" \
        -Dcppflags="$CPPFLAGS" \
        -Dldflags="$LDFLAGS" \
        -Dlddlflags="-shared -L$AOS_GLIBC/lib" \
        -Dlibs="-lm -lpthread -lcrypt" \
        -Uuselargefiles \
        -Dusethreads=n \
        -Duseshrplib=n \
        -Ui_db \
        -Ui_gdbm \
        -Ui_ndbm \
        -Dd_dosuid=undef \
        -Dd_suidsafe=undef \
        -Dman1dir=none \
        -Dman3dir=none

      mkdir -p lib/auto/IO/Compress
      "$AR" cr lib/auto/IO/Compress/Compress.a
    '';
    buildScript = ''
      make -j1
    '';
    installScript = ''
      make install ${autotoolsVars}
    '';
    meta = gnuMeta "Practical Extraction and Report Language, version 5.16.3" "https://www.perl.org/" "Artistic-1.0-Perl OR GPL-1.0-or-later";
  };

  texinfo = gcc48 {
    pname = "texinfo";
    version = "5.1";
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-5.1.tar.xz";
    hash = "sha256-T1vaT1BMWE9bRkR9rwIbUjuwBpYAnW0Yz+wQWl4HJhU=";
    buildDeps = [
      perl
      help2man
    ];
    configureFlags =
      tripletBuildHost
      ++ [
        "--disable-nls"
        "--disable-perl-xs"
      ];
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    postFreeze = ''
      find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true
    '';
    meta = gnuMeta "GNU documentation system, version 5.1" "https://www.gnu.org/software/texinfo/" "GPL-3.0-or-later";
  };

  help2man = gcc48 {
    pname = "help2man";
    version = "1.41.1";
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.41.1.tar.gz";
    hash = "sha256-OmUK2pRTcA40NVdw1PdPJX+x3aGg8k9EuKPB1Mse5A0=";
    fetchMode = "url";
    buildDeps = [perl];
    configureInSource = true;
    configureFlags = [
      "--build=${hostPlatform.config}"
      "--host=${hostPlatform.config}"
    ];
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    meta = gnuMeta "GNU help2man 1.41.1 generates man pages from --help output" "https://www.gnu.org/software/help2man/" "GPL-3.0-or-later";
  };

  m4 = gcc48 {
    pname = "m4";
    version = "1.4.16";
    url = "https://mirrors.kernel.org/gnu/m4/m4-1.4.16.tar.bz2";
    hash = "sha256-tcR+IRdi1HPrOSIdiAIOVKcjT5E2lst/LFKJ5peQx2M=";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletBuildHostNoNls;
    postFreeze = ''
      touch config.hin 2>/dev/null || true
      sed -i '/_GL_WARN_ON_USE (gets,/d' lib/stdio.in.h
    '';
    meta = gnuMeta "GNU m4 macro processor, version 1.4.16" "https://www.gnu.org/software/m4/" "GPL-3.0-or-later";
  };

  flex = gcc48 {
    pname = "flex";
    version = "2.5.37";
    url = "https://sourceforge.net/projects/flex/files/flex-2.5.37.tar.bz2";
    hash = "sha256-yKmh5Z+bOWMv24D7dKJyHHArIlu+fdQ79+c5UvjfqRw=";
    buildDeps = [
      texinfo
      help2man
      m4
    ];
    configureInSource = true;
    configureFlags = tripletBuildHostNoNls;
    configureEnv = ''
      export M4="${m4}/bin/m4"
    '';
    postConfigure = ''
      cp scan.c .c
    '';
    makeFlags = [''SUBDIRS="lib ."''];
    installFlags = [''SUBDIRS="lib ."''];
    postInstall = ''
      [ ! -f "$out/bin/lex" ] && ln -sf flex "$out/bin/lex"
    '';
    meta = gnuMeta "Fast lexical analyzer generator, version 2.5.37" "https://github.com/westes/flex" "BSD-2-Clause";
  };

  bison = gcc48 {
    pname = "bison";
    version = "3.0.4";
    url = "https://mirrors.kernel.org/gnu/bison/bison-3.0.4.tar.xz";
    hash = "1pxj97dfh3iabxcc4g60y739zkd788kf4cv64zb515676lckmj9y";
    buildDeps = [
      texinfo
      help2man
      m4
      perl
      flex
    ];
    configureFlags = tripletBuildHostNoNls;
    configureEnv = ''
      export M4="${m4}/bin/m4"
    '';
    postConfigure = ''
      sed -i '/gets is a security hole/d' lib/stdio.in.h 2>/dev/null || true
    '';
    buildScript = ''
      make -j"$NIX_BUILD_CORES" MAKEINFO=true
    '';
    installScript = ''
      make install MAKEINFO=true
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      cat > "$out/bin/yacc" <<YACC
      #!$AOS_BASH
      exec "$out/bin/bison" -y "\$@"
      YACC
      chmod +x "$out/bin/yacc"
    '';
    meta = gnuMeta "GNU parser generator, version 3.0.4" "https://www.gnu.org/software/bison/" "GPL-3.0-or-later";
  };

  autoconf = gcc48 {
    pname = "autoconf";
    version = "2.69";
    url = "https://mirrors.kernel.org/gnu/autoconf/autoconf-2.69.tar.xz";
    hash = "sha256-tpVLeuvm1/He9UvOAGzup4fc7YTQYp1xWTowDs1rR4I=";
    buildDeps = [
      texinfo
      help2man
      m4
      perl
    ];
    configureInSource = true;
    configureFlags = [
      "--build=${hostPlatform.config}"
      "--host=${hostPlatform.config}"
    ];
    configureEnv = ''
      export M4="${m4}/bin/m4"
      export PERL="${perl}/bin/perl"
    '';
    meta = gnuMeta "GNU Autoconf, version 2.69" "https://www.gnu.org/software/autoconf/" "GPL-3.0-or-later";
  };

  automake = gcc48 {
    pname = "automake";
    version = "1.13.4";
    url = "https://mirrors.kernel.org/gnu/automake/automake-1.13.4.tar.xz";
    hash = "sha256-cHpdXUTmAeF89dLm8Rx9gPPSQoSOr7mBKKM76uoXuS4=";
    buildDeps = [
      texinfo
      help2man
      m4
      perl
      autoconf
    ];
    configureInSource = true;
    configureFlags = [
      "--build=${hostPlatform.config}"
      "--host=${hostPlatform.config}"
    ];
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    postConfigure = ''
      touch doc/amhello-1.0.tar.gz 2>/dev/null || true
      find doc -name '*.info' -exec touch {} + 2>/dev/null || true
    '';
    meta = gnuMeta "GNU Automake, version 1.13.4" "https://www.gnu.org/software/automake/" "GPL-2.0-or-later";
  };

  gperf = gcc48 {
    pname = "gperf";
    version = "3.0.4";
    url = "https://mirrors.kernel.org/gnu/gperf/gperf-3.0.4.tar.gz";
    hash = "12pqgvxmyckqv1b5qhi80qmwkvpvr604w7qckbn1dfkykl96rdgb";
    configureFlags = [
      "--build=${hostPlatform.config}"
      "--host=${hostPlatform.config}"
    ];
    useCxx = true;
    meta = gnuMeta "GNU perfect hash function generator, version 3.0.4" "https://www.gnu.org/software/gperf/" "GPL-3.0-or-later";
  };

  bash = gcc48 {
    pname = "bash";
    version = "4.2";
    url = "https://mirrors.kernel.org/gnu/bash/bash-4.2.tar.gz";
    hash = "sha256-onoReeycCDDGXGql19q2D3zhoqYIYYVw+Wv6culas9g=";
    fetchMode = "url";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags =
      tripletBuildHostTarget
      ++ [
        "--without-bash-malloc"
        "--disable-nls"
      ];
    postFreeze = ''
      find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true
    '';
    postInstall = ''
      [ -f "$out/bin/bash" ] && [ ! -f "$out/bin/sh" ] && ln -sf bash "$out/bin/sh"
    '';
    meta = gnuMeta "GNU Bourne-Again SHell, version 4.2" "https://www.gnu.org/software/bash/" "GPL-3.0-or-later";
  };

  coreutils = gcc48 {
    pname = "coreutils";
    version = "8.22";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.22.tar.xz";
    hash = "sha256-Wz6UmYFSwBfmx11WubmUGI63G/RtQDimQsuRQfb/EhI=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [perl xz];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureInSource = true;
    configureFlags =
      tripletNoNls
      ++ ["--enable-no-install-program=stdbuf"];
    postFreeze = ''
      touch -t 200001010200.00 .version .tarball-version src/fs.h src/version.c src/version.h lib/config.hin 2>/dev/null || true
      sed -i '/_GL_WARN_ON_USE (gets,/d' lib/stdio.in.h 2>/dev/null || true
    '';
    postConfigure = ''
      printf '#!%s\necho ".TH dummy 1"\n' "$AOS_BASH" > man/dummy-man
      chmod +x man/dummy-man
      touch -t 200001010200.00 man/*.1 man/*.x 2>/dev/null || true
    '';
    buildScript = ''
      make -j"$NIX_BUILD_CORES" ${autotoolsVars} -k || true
      test -f src/ls || { echo "FATAL: coreutils binaries not built"; exit 1; }
    '';
    installScript = ''
      make install-exec ${autotoolsVars}
      test -f "$out/bin/ls" || { echo "FATAL: coreutils not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU core utilities (ls, cat, cp, mv, etc.), version 8.22" "https://www.gnu.org/software/coreutils/" "GPL-3.0-or-later";
  };

  gnumake = gcc48 {
    pname = "gnumake";
    version = "4.2.1";
    url = "https://mirrors.kernel.org/gnu/make/make-4.2.1.tar.bz2";
    hash = "sha256-1uJivzYBtC0rHk74MQAp4dzyAIPFRGtLeqZwgf3/xYk=";
    fetchMode = "url";
    srcName = "make-4.2.1.tar.bz2";
    buildDeps = autotoolsDeps ++ [bzip2];
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU Make build automation tool, version 4.2.1" "https://www.gnu.org/software/make/" "GPL-3.0-or-later";
  };

  sed = gcc48 {
    pname = "sed";
    version = "4.2.2";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.2.2.tar.bz2";
    hash = "sha256-8EjRg42ihMi8l1PkUGuFoeDMHqiZnTb2mVvLlGDN29c=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [bzip2];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU stream editor, version 4.2.2" "https://www.gnu.org/software/sed/" "GPL-3.0-or-later";
  };

  grep = gcc48 {
    pname = "grep";
    version = "2.20";
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.20.tar.xz";
    hash = "sha256-8K9FK8DQlGS20Im21WoKPBZnLp7ZEY++N7C2rq8GmmU=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [xz];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags =
      tripletNoNls
      ++ ["--disable-perl-regexp"];
    meta = gnuMeta "GNU grep pattern matching utility, version 2.20" "https://www.gnu.org/software/grep/" "GPL-3.0-or-later";
  };

  gawk = gcc48 {
    pname = "gawk";
    version = "4.0.2";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-4.0.2.tar.xz";
    hash = "sha256-IeHyjFG1Fg8KS/GnNcYQm0ajvWpD3oCOq8IcF7sCbRM=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [xz];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    postInstall = ''
      [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"
    '';
    meta = gnuMeta "GNU awk pattern scanning and processing language, version 4.0.2" "https://www.gnu.org/software/gawk/" "GPL-3.0-or-later";
  };

  findutils = gcc48 {
    pname = "findutils";
    version = "4.6.0";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.6.0.tar.gz";
    hash = "sha256-3tTJ9zcxzUj+w7a9rMzolkc7bY4zfpYS4WzxQxuxFp0=";
    fetchMode = "url";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU find, xargs, and locate utilities, version 4.6.0" "https://www.gnu.org/software/findutils/" "GPL-3.0-or-later";
  };

  diffutils = gcc48 {
    pname = "diffutils";
    version = "3.3";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.3.tar.xz";
    hash = "sha256-ol6JqKtl/e0XMeQYa+G7Jc2pZ4NLbflzWZzc1avfwZw=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [xz];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 3.3" "https://www.gnu.org/software/diffutils/" "GPL-3.0-or-later";
  };

  tar = gcc48 {
    pname = "tar";
    version = "1.26";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.26.tar.bz2";
    hash = "sha256-WlNp9GRQKlmOk4ApwxDUs6vVHmu439BFZj5hyOqfbUE=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [bzip2];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    postFreeze = ''
      sed -i '/_GL_WARN_ON_USE (gets,/d' gnu/stdio.in.h 2>/dev/null || true
    '';
    meta = gnuMeta "GNU tar archiving utility, version 1.26" "https://www.gnu.org/software/tar/" "GPL-3.0-or-later";
  };

  gzip = gcc48 {
    pname = "gzip";
    version = "1.5";
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.5.tar.xz";
    hash = "sha256-msIKOEGhJGqL7dgA6h+5PvdlIVNdictZOX0mcCa2oXM=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [xz];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = [];
    meta = gnuMeta "GNU gzip compression utility, version 1.5" "https://www.gnu.org/software/gzip/" "GPL-3.0-or-later";
  };

  patch = gcc48 {
    pname = "patch";
    version = "2.7.1";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.7.1.tar.xz";
    hash = "sha256-kSS6RtsKvYc9CZXCyogOgSUmdrtsA+CjffxfYIqbDOs=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [xz];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = [];
    meta = gnuMeta "GNU patch file patching utility, version 2.7.1" "https://www.gnu.org/software/patch/" "GPL-3.0-or-later";
  };
}
