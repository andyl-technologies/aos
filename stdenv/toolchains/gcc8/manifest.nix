# stdenv/toolchains/gcc8/manifest.nix - GCC 8 tier POSIX tool manifest
{
  buildPlatform,
  hostPlatform,
  m4,
  flex,
  bison,
  perl,
  autoconf,
  automake,
  texinfo,
  help2man,
}: let
  tripletFlags = [
    "--build=${hostPlatform.config}"
    "--host=${hostPlatform.config}"
    "--target=${hostPlatform.config}"
  ];

  tripletNoNls = tripletFlags ++ ["--disable-nls"];
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
in {
  perl = {
    pname = "perl";
    version = "5.26.3";
    url = "https://www.cpan.org/src/5.0/perl-5.26.3.tar.xz";
    hash = "sha256-dlX8a0Hmw4GPvxGerkHE5IgRhh1u9nRMwXgVHZHP9q4=";
    freezeAutotoolsTimestamps = false;
    configureScript = ''
      sed -i "s|'/bin/pwd'|'$PWD_CMD', '/bin/pwd'|" dist/PathTools/Cwd.pm
      sed -i 's/getcwd()/getcwd() || "."/' dist/PathTools/Cwd.pm 2>/dev/null || true

      sed -i \
        -e "s|/usr/include/errno.h|$AOS_GLIBC/include/errno.h|g" \
        -e "s|/usr/local/include/errno.h|$AOS_GLIBC/include/errno.h|g" \
        ext/Errno/Errno_pm.PL

      ./Configure -des \
        -Dprefix="$out" \
        -Dcc="$CC" \
        -Dccflags="$CFLAGS" \
        -Dldflags="$LDFLAGS" \
        -Dloclibpth="$AOS_GLIBC/lib" \
        -Dlocincpth="$AOS_GLIBC/include" \
        -Dlibs="-lm -lpthread -ldl -lcrypt" \
        -Ddefault_inc_excludes_dot=n \
        -Dusethreads=n \
        -Dusedl=n \
        -Uusedl \
        -Ui_xlocale
    '';
    configureEnv = ''
      PWD_CMD="$(type -P pwd)"
      export PWD_CMD
    '';
    buildScript = ''
      make -j1
    '';
    installScript = ''
      make install ${autotoolsVars}
    '';
    meta = gnuMeta "Practical Extraction and Report Language, version 5.26.3" "https://www.perl.org/" "Artistic-1.0-Perl OR GPL-1.0-or-later";
  };

  texinfo = {
    pname = "texinfo";
    version = "6.5";
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-6.5.tar.xz";
    hash = "sha256-s2LpZW+c3AqrrPmpTIf2lIgEGropkZOTSOOyJxn1jxg=";
    buildDeps = [perl];
    configureFlags =
      tripletFlags
      ++ [
        "--disable-perl-xs"
        "--disable-nls"
      ];
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    postFreeze = ''
      find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true
    '';
    buildScript = ''
      make -k -j"$NIX_BUILD_CORES" ${autotoolsVars} || true
      test -f tp/texi2any || { echo "FATAL: texi2any not built"; exit 1; }
    '';
    installScript = ''
      make install -k ${autotoolsVars} || true
      test -f "$out/bin/makeinfo" || { echo "FATAL: makeinfo not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU documentation system, version 6.5" "https://www.gnu.org/software/texinfo/" "GPL-3.0-or-later";
  };

  help2man = {
    pname = "help2man";
    version = "1.47.6";
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.47.6.tar.xz";
    hash = "sha256-3Qpuz66120hE15b0ml2MJ/nn2Los/17IeY4eLsIfmZ4=";
    buildDeps = [perl];
    configureInSource = true;
    configureFlags = [
      "--build=${hostPlatform.config}"
      "--host=${hostPlatform.config}"
    ];
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    meta = gnuMeta "GNU help2man 1.47.6 generates man pages from --help output" "https://www.gnu.org/software/help2man/" "GPL-3.0-or-later";
  };

  m4 = {
    pname = "m4";
    version = "1.4.19";
    url = "https://mirrors.kernel.org/gnu/m4/m4-1.4.19.tar.xz";
    hash = "02xz8gal0fdc4gzjwyiy1557q31xcpg896yc0y6kd8s5jbynvdmf";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU macro processor, version 1.4.19" "https://www.gnu.org/software/m4/" "GPL-3.0-or-later";
  };

  flex = {
    pname = "flex";
    version = "2.6.1";
    url = "https://github.com/westes/flex/releases/download/v2.6.1/flex-2.6.1.tar.xz";
    hash = "sha256-Q6xMKCZM24E6qIndXVII38cTQstowhHt+ee/I+K7IfI=";
    buildDeps = [
      texinfo
      help2man
      m4
    ];
    configureFlags = tripletNoNls;
    configureEnv = ''
      export M4="${m4}/bin/m4"
    '';
    makeFlags = [''SUBDIRS="lib src"''];
    installFlags = [''SUBDIRS="lib src"''];
    postInstall = ''
      ln -s flex "$out/bin/lex"
    '';
    meta = gnuMeta "Fast lexical analyser generator, version 2.6.1" "https://github.com/westes/flex" "BSD-2-Clause";
  };

  bison = {
    pname = "bison";
    version = "3.8.2";
    url = "https://mirrors.kernel.org/gnu/bison/bison-3.8.2.tar.xz";
    hash = "0w18vf97c1kddc52ljb2x82rsn9k3mffz3acqybhcjfl2l6apn59";
    buildDeps = [
      texinfo
      help2man
      m4
      perl
      flex
    ];
    configureFlags = tripletNoNls;
    configureEnv = ''
      export M4="${m4}/bin/m4"
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      cat > "$out/bin/yacc" <<YACC
      #!$AOS_BASH
      exec "$out/bin/bison" -y "\$@"
      YACC
      chmod +x "$out/bin/yacc"
    '';
    meta = gnuMeta "GNU parser generator, version 3.8.2" "https://www.gnu.org/software/bison/" "GPL-3.0-or-later";
  };

  autoconf = {
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
    configureFlags = tripletFlags;
    configureEnv = ''
      export M4="${m4}/bin/m4"
      export PERL="${perl}/bin/perl"
    '';
    meta = gnuMeta "GNU Autoconf, version 2.69" "https://www.gnu.org/software/autoconf/" "GPL-3.0-or-later";
  };

  automake = {
    pname = "automake";
    version = "1.16.1";
    url = "https://mirrors.kernel.org/gnu/automake/automake-1.16.1.tar.xz";
    hash = "sha256-/5C0Lb7IwKQDZ3OrwmyjjXqpIxj2M6TokJFwvGuNvLE=";
    buildDeps = [
      texinfo
      help2man
      m4
      perl
      autoconf
    ];
    configureFlags = tripletFlags;
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    postConfigure = ''
      mkdir -p t
      touch "$sourceDir/doc/amhello-1.0.tar.gz" 2>/dev/null || true
      find "$sourceDir/doc" -name '*.info' -exec touch {} + 2>/dev/null || true
    '';
    meta = gnuMeta "GNU Automake, version 1.16.1" "https://www.gnu.org/software/automake/" "GPL-2.0-or-later";
  };

  gperf = {
    pname = "gperf";
    version = "3.1";
    url = "https://mirrors.kernel.org/gnu/gperf/gperf-3.1.tar.gz";
    hash = "sha256-8wzbi/Hs3+U1qT28ZQI/ZI1Rmgil4YLnL8MsObnasbE=";
    configureFlags = tripletFlags;
    useCxx = true;
    meta = gnuMeta "GNU perfect hash function generator, version 3.1" "https://www.gnu.org/software/gperf/" "GPL-3.0-or-later";
  };

  python3 = {
    name = "python-3.8.18";
    pname = "python";
    version = "3.8.18";
    url = "https://www.python.org/ftp/python/3.8.18/Python-3.8.18.tar.xz";
    hash = "1nsgfnq51826mrzq4kfviv871z3zjklpfsfhfwc13hry2abn46y8";
    freezeAutotoolsTimestamps = false;
    configureScript = ''
      cat > Modules/Setup.local <<'SETUP_EOF'
      _posixsubprocess _posixsubprocess.c
      select selectmodule.c
      fcntl fcntlmodule.c
      _struct _struct.c
      math mathmodule.c _math.c
      binascii binascii.c
      _contextvars _contextvarsmodule.c
      _sha1 sha1module.c
      _sha256 sha256module.c
      _sha512 sha512module.c
      _md5 md5module.c
      _blake2 _blake2/blake2module.c _blake2/blake2b_impl.c _blake2/blake2s_impl.c
      _sha3 _sha3/sha3module.c
      _random _randommodule.c
      SETUP_EOF

      CC="$CC" \
      CXX="$CXX" \
      CFLAGS="$CFLAGS" \
      LDFLAGS="$LDFLAGS" \
      ./configure \
        --prefix="$out" \
        --build=${buildPlatform.config} \
        --host=${hostPlatform.config} \
        --disable-shared \
        --without-ensurepip \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no
    '';
    postConfigure = ''
      # This bootstrap interpreter intentionally contains only the static
      # modules declared in Setup.local.  Remove both shared-module build
      # prerequisites and the install-time dependency, which otherwise makes
      # native AArch64 builds probe optional host libraries such as libffi.
      sed -i \
        -e '/^build_all:/s/ oldsharedmods sharedmods / /' \
        -e '/^sharedinstall:/,/^$/c\sharedinstall:' \
        Makefile
    '';
    postBuild = ''
      # sharedmods normally creates pybuilddir.txt and the platform sysconfig
      # module as a side effect.  The static-only build still needs that module
      # while installing the standard library.
      ./python -E -S -m sysconfig --generate-posix-vars
    '';
    installScript = ''
      make install SHAREDMODS=""
    '';
    postInstall = ''
      [ -f "$out/bin/python3.8" ] && [ ! -f "$out/bin/python3" ] && ln -sf python3.8 "$out/bin/python3"
      [ -f "$out/bin/python3" ] && [ ! -f "$out/bin/python" ] && ln -sf python3 "$out/bin/python"
    '';
    meta = gnuMeta "Python 3.8.18 minimal interpreter for build scripts" "https://www.python.org/" "PSF-2.0";
  };

  bash = {
    pname = "bash";
    version = "4.4";
    url = "https://mirrors.kernel.org/gnu/bash/bash-4.4.tar.gz";
    hash = "11pcg69yhvfqj51iqm9kxmsinjkdlfz51cjp9mvg727fk60224vw";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags =
      tripletFlags
      ++ [
        "--without-bash-malloc"
        "--disable-nls"
      ];
    postInstall = ''
      [ -f "$out/bin/bash" ] && [ ! -f "$out/bin/sh" ] && ln -sf bash "$out/bin/sh"
    '';
    meta = gnuMeta "GNU Bourne-Again SHell, version 4.4" "https://www.gnu.org/software/bash/" "GPL-3.0-or-later";
  };

  coreutils = {
    pname = "coreutils";
    version = "8.30";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.30.tar.xz";
    hash = "0pp6vvpzw0v6s45yq58cszrh514a5v8jq32321apszw7rbffkslb";
    buildDeps = autotoolsDeps ++ [perl];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU core utilities (ls, cat, cp, mv, etc.), version 8.30" "https://www.gnu.org/software/coreutils/" "GPL-3.0-or-later";
  };

  gnumake = {
    pname = "gnumake";
    version = "4.3";
    url = "https://mirrors.kernel.org/gnu/make/make-4.3.tar.gz";
    hash = "17z72ib90c3218ic02maxdxy40d3sdxhzbnmxs9myiy25ysxb434";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU Make build automation tool, version 4.3" "https://www.gnu.org/software/make/" "GPL-3.0-or-later";
  };

  sed = {
    pname = "sed";
    version = "4.5";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.5.tar.xz";
    hash = "1hds0a4k5z2llh9qdkxmmvppc2c8xa3j0jx9ljjy231kwz38l6n9";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU stream editor, version 4.5" "https://www.gnu.org/software/sed/" "GPL-3.0-or-later";
  };

  grep = {
    pname = "grep";
    version = "3.1";
    url = "https://mirrors.kernel.org/gnu/grep/grep-3.1.tar.xz";
    hash = "0msnadmbcq7a7pk23zyllhmmaa7p7my6kqjgzwqmfrwd3qp68w75";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags =
      tripletNoNls
      ++ ["--disable-perl-regexp"];
    meta = gnuMeta "GNU grep pattern matching utility, version 3.1" "https://www.gnu.org/software/grep/" "GPL-3.0-or-later";
  };

  gawk = {
    pname = "gawk";
    version = "4.2.1";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-4.2.1.tar.xz";
    hash = "01giqrnwhndrja2jqw54w92bq8qwclypj75x0758j1axc6brzc2b";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    postInstall = ''
      [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"
    '';
    meta = gnuMeta "GNU awk pattern scanning and processing language, version 4.2.1" "https://www.gnu.org/software/gawk/" "GPL-3.0-or-later";
  };

  findutils = {
    pname = "findutils";
    version = "4.6.0";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.6.0.tar.gz";
    hash = "0aq6sck5sqpbzia1322fk3zyirkwbn909r7mlb6c2yz49m1fcw9d";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    cppflags = "-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem $AOS_GLIBC/include -D_IO_ftrylockfile -D_IO_IN_BACKUP=0x100 -include sys/sysmacros.h";
    meta = gnuMeta "GNU find, xargs, and locate utilities, version 4.6.0" "https://www.gnu.org/software/findutils/" "GPL-3.0-or-later";
  };

  diffutils = {
    pname = "diffutils";
    version = "3.6";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.6.tar.xz";
    hash = "09n0jhyb372c5203g18flpik9mfl0qk9i33lch1r8y114rlvw2r1";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    postUnpack = ''
      if [ -f man/help2man ]; then
        printf '#!%s\nexit 0\n' "$AOS_BASH" > man/help2man
        chmod +x man/help2man
        find . -name '*.1' -exec touch {} + 2>/dev/null || true
      fi
    '';
    meta = gnuMeta "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 3.6" "https://www.gnu.org/software/diffutils/" "GPL-3.0-or-later";
  };

  tar = {
    pname = "tar";
    version = "1.30";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.30.tar.xz";
    hash = "0i9yss8az1nkiw5da1i0ykblbrhns2kax0m3f4nyj1lq0v73fi1j";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU tar archiving utility, version 1.30" "https://www.gnu.org/software/tar/" "GPL-3.0-or-later";
  };

  gzip = {
    pname = "gzip";
    version = "1.9";
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.9.tar.xz";
    hash = "0hjbnzqyhbnphcz5z5dwkbkcynjcn32mwqyj5p6ispn0jga31i2n";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = [];
    cppflags = "-nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem $AOS_GLIBC/include -D_IO_ftrylockfile -D_IO_IN_BACKUP=0x100";
    meta = gnuMeta "GNU gzip compression utility, version 1.9" "https://www.gnu.org/software/gzip/" "GPL-3.0-or-later";
  };

  patch = {
    pname = "patch";
    version = "2.7.6";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.7.6.tar.xz";
    hash = "1yiy0xq1ha193yga0canc9ijw4hbd92c93l7ksqlhmzsn2yph39n";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = [];
    meta = gnuMeta "GNU patch file patching utility, version 2.7.6" "https://www.gnu.org/software/patch/" "GPL-3.0-or-later";
  };
}
