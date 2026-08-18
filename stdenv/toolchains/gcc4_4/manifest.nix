# stdenv/toolchains/gcc4_4/manifest.nix - GCC 4.4 tier POSIX tool manifest
{
  hostPlatform,
  prev,
  gcc,
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

  thisCompiler = {
    inherit gcc;
    glibc = prev.glibc;
    binutils = prev.binutils;
  };

  prevCompiler = {
    gcc = prev.gcc;
    glibc = prev.glibc;
    binutils = prev.binutils;
  };

  staticProfile = compiler: gccVersion: attrs:
    {
      inherit compiler gccVersion;
      staticNssWrapper = true;
      cflags = "-O2 -isystem ${compiler.glibc}/include";
      cppflags = "-isystem ${compiler.glibc}/include";
      ldflags = "-L${compiler.glibc}/lib -static -Wl,-u,dl_iterate_phdr";
    }
    // attrs;

  thisStatic = staticProfile thisCompiler "4.4.7";
  prevStatic = staticProfile prevCompiler "4.1.2";
in {
  perl = thisStatic {
    pname = "perl";
    version = "5.10.1";
    url = "https://www.cpan.org/src/5.0/perl-5.10.1.tar.bz2";
    hash = "0wfch7jkcwmi5xmsrb7j18fn63hs7qvl958gzy6mfgxar6hj88dk";
    freezeAutotoolsTimestamps = false;
    cflags = "-O2 -I${prev.glibc}/include";
    cppflags = "-I${prev.glibc}/include";
    ldflags = "-L${prev.glibc}/lib";
    configureScript = ''
      rm -rf ext/IO-Compress ext/Errno
      sed -i -e '/^ext\/IO-Compress/d' -e '/^ext\/Errno/d' MANIFEST

      ./Configure \
        -des \
        -Dprefix="$out" \
        -Dcc="$CC" \
        -Dar="$AR" \
        -Dnm="$NM" \
        -Dranlib="$RANLIB" \
        -Dsh="$AOS_BASH" \
        -Dlocincpth="${prev.glibc}/include" \
        -Dloclibpth="${prev.glibc}/lib" \
        -Dglibpth="${prev.glibc}/lib" \
        -Dusrinc="${prev.glibc}/include" \
        -Dccflags="$CFLAGS" \
        -Dcppflags="$CPPFLAGS" \
        -Dldflags="$LDFLAGS" \
        -Dlddlflags="-shared -L${prev.glibc}/lib" \
        -Dlibs="-lm -lpthread -lcrypt" \
        -Uuselargefiles \
        -Dusethreads=n \
        -Duseshrplib=n \
        -Dd_setlocale=undef \
        -Ui_db \
        -Ui_gdbm \
        -Ui_ndbm \
        -Dd_dosuid=undef \
        -Dd_suidsafe=undef \
        -Dman1dir=none \
        -Dman3dir=none

      cat > lib/Errno.pm <<'ERREOF'
      package Errno;
      use strict;
      require Exporter;
      our @ISA = qw(Exporter);
      our @EXPORT_OK = qw(EPERM ENOENT ESRCH EINTR EIO ENXIO E2BIG ENOEXEC EBADF
        ECHILD EAGAIN ENOMEM EACCES EFAULT ENOTBLK EBUSY EEXIST EXDEV ENODEV
        ENOTDIR EISDIR EINVAL ENFILE EMFILE ENOTTY ETXTBSY EFBIG ENOSPC ESPIPE
        EROFS EMLINK EPIPE EDOM ERANGE EDEADLK ENAMETOOLONG ENOLCK ENOSYS
        ENOTEMPTY ELOOP EWOULDBLOCK ENOMSG EIDRM EOVERFLOW EILSEQ ENOTSOCK
        EDESTADDRREQ EMSGSIZE EPROTOTYPE ENOPROTOOPT EPROTONOSUPPORT EOPNOTSUPP
        EAFNOSUPPORT EADDRINUSE EADDRNOTAVAIL ENETDOWN ENETUNREACH ECONNABORTED
        ECONNRESET ENOBUFS EISCONN ENOTCONN ETIMEDOUT ECONNREFUSED EHOSTUNREACH
        EALREADY EINPROGRESS ESTALE EDQUOT);
      our %EXPORT_TAGS = (POSIX => [qw(E2BIG EACCES EADDRINUSE EADDRNOTAVAIL
        EAFNOSUPPORT EAGAIN EALREADY EBADF EBUSY ECHILD ECONNABORTED ECONNREFUSED
        ECONNRESET EDEADLK EDESTADDRREQ EDOM EDQUOT EEXIST EFAULT EFBIG
        EHOSTUNREACH EIDRM EILSEQ EINPROGRESS EINTR EINVAL EIO EISCONN EISDIR
        ELOOP EMFILE EMLINK EMSGSIZE ENAMETOOLONG ENETDOWN ENETRESET ENETUNREACH
        ENFILE ENOBUFS ENODEV ENOENT ENOEXEC ENOLCK ENOMEM ENOMSG ENOPROTOOPT
        ENOSPC ENOSYS ENOTCONN ENOTDIR ENOTEMPTY ENOTSOCK ENOTTY ENXIO
        EOPNOTSUPP EOVERFLOW EPERM EPIPE EPROTONOSUPPORT EPROTOTYPE ERANGE EROFS
        ESRCH ESTALE ETIMEDOUT ETXTBSY EWOULDBLOCK EXDEV)]);
      sub EPERM () {1} sub ENOENT () {2} sub ESRCH () {3} sub EINTR () {4}
      sub EIO () {5} sub ENXIO () {6} sub E2BIG () {7} sub ENOEXEC () {8}
      sub EBADF () {9} sub ECHILD () {10} sub EAGAIN () {11} sub ENOMEM () {12}
      sub EACCES () {13} sub EFAULT () {14} sub ENOTBLK () {15} sub EBUSY () {16}
      sub EEXIST () {17} sub EXDEV () {18} sub ENODEV () {19} sub ENOTDIR () {20}
      sub EISDIR () {21} sub EINVAL () {22} sub ENFILE () {23} sub EMFILE () {24}
      sub ENOTTY () {25} sub ETXTBSY () {26} sub EFBIG () {27} sub ENOSPC () {28}
      sub ESPIPE () {29} sub EROFS () {30} sub EMLINK () {31} sub EPIPE () {32}
      sub EDOM () {33} sub ERANGE () {34} sub EDEADLK () {35}
      sub ENAMETOOLONG () {36} sub ENOLCK () {37} sub ENOSYS () {38}
      sub ENOTEMPTY () {39} sub ELOOP () {40} sub EWOULDBLOCK () {11}
      sub ENOMSG () {42} sub EIDRM () {43} sub EOVERFLOW () {75}
      sub EILSEQ () {84} sub ENOTSOCK () {88} sub EDESTADDRREQ () {89}
      sub EMSGSIZE () {90} sub EPROTOTYPE () {91} sub ENOPROTOOPT () {92}
      sub EPROTONOSUPPORT () {93} sub EOPNOTSUPP () {95} sub EAFNOSUPPORT () {97}
      sub EADDRINUSE () {98} sub EADDRNOTAVAIL () {99} sub ENETDOWN () {100}
      sub ENETUNREACH () {101} sub ENETRESET () {102} sub ECONNABORTED () {103}
      sub ECONNRESET () {104} sub ENOBUFS () {105} sub EISCONN () {106}
      sub ENOTCONN () {107} sub ETIMEDOUT () {110} sub ECONNREFUSED () {111}
      sub EHOSTUNREACH () {113} sub EALREADY () {114} sub EINPROGRESS () {115}
      sub ESTALE () {116} sub EDQUOT () {122}
      sub TIEHASH { bless [] }
      sub FETCH { my ($self, $errname) = @_; my $v = eval "no strict; &$errname"; defined $v && $v == $! + 0 }
      sub STORE { require Carp; Carp::confess("ERRNO hash is read only!") }
      sub EXISTS { my ($self, $errname) = @_; eval { no strict; &$errname }; !$@ }
      tie %!, __PACKAGE__;
      our $VERSION = "1.11";
      1;
      ERREOF

      sed -i "s|'/bin/pwd'|'${prev.coreutils}/bin/pwd', '/bin/pwd'|" lib/Cwd.pm
    '';
    buildScript = ''
      make -j1
    '';
    installScript = ''
      make install ${autotoolsVars} || true
      test -f "$out/bin/perl" || { echo "FATAL: perl not installed"; exit 1; }
      perl_arch="$("$out/bin/perl" -MConfig -e 'print $Config{archname}')"
      "$out/bin/perl" -MAutoSplit -e 'autosplit(shift, shift, 0, 1, 0)' \
        "$out/lib/5.10.1/$perl_arch/POSIX.pm" \
        "$out/lib/5.10.1/$perl_arch/auto"
      test -f "$out/lib/5.10.1/$perl_arch/auto/POSIX/load_imports.al" || {
        echo "FATAL: perl POSIX autoload files not installed"
        exit 1
      }
    '';
    meta = gnuMeta "Practical Extraction and Report Language, version 5.10.1" "https://www.perl.org/" "Artistic-1.0-Perl OR GPL-1.0-or-later";
  };

  texinfo = thisStatic {
    pname = "texinfo";
    version = "4.13";
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-4.13a.tar.gz";
    hash = "012rj0sa6f1jj8namymb68bznq420zfavixm6g9k36jbjb718v78";
    buildDeps = [perl];
    configureInSource = true;
    configureFlags = tripletBuildHostNoNls;
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    postConfigure = ''
      sed -i 's/info //;s/doc //' Makefile
    '';
    meta = gnuMeta "GNU documentation system, version 4.13" "https://www.gnu.org/software/texinfo/" "GPL-3.0-or-later";
  };

  help2man = prevStatic {
    pname = "help2man";
    version = "1.36.4";
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.36.4.tar.gz";
    hash = "sha256-pK2t92tJamvFB5VwIlPs/Lbw0Vm2gDjzGlNiAJNAvKI=";
    fetchMode = "url";
    buildDeps = [perl];
    configureInSource = true;
    configureFlags = tripletBuildHostNoNls;
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    meta = gnuMeta "GNU help2man 1.36.4 generates man pages from --help output" "https://www.gnu.org/software/help2man/" "GPL-3.0-or-later";
  };

  m4 = thisStatic {
    pname = "m4";
    version = "1.4.13";
    url = "https://mirrors.kernel.org/gnu/m4/m4-1.4.13.tar.bz2";
    hash = "1nj3c6fjvl4z73ryags6811w8bj45ij6wfvw9zxccmnp44jl6clb";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletBuildHostNoNls;
    ldflags = "-L${prev.glibc}/lib -static -Wl,-u,dl_iterate_phdr -Wl,--allow-multiple-definition";
    postFreeze = ''
      touch config.hin 2>/dev/null || true
    '';
    postConfigure = ''
      find . -name Makefile | while read f; do
        sed -i 's/^Makefile:.*/Makefile:/; s/^config\.status:.*/config.status:/; s/^configure:.*/configure:/' "$f"
      done
    '';
    buildScript = ''
      make -j"$NIX_BUILD_CORES" ${autotoolsVars} HELP2MAN=true || true
      test -f src/m4 || { echo "FATAL: m4 not built"; exit 1; }
    '';
    installScript = ''
      make install ${autotoolsVars} HELP2MAN=true || true
      test -f "$out/bin/m4" || { echo "FATAL: m4 not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU m4 macro processor, version 1.4.13" "https://www.gnu.org/software/m4/" "GPL-3.0-or-later";
  };

  flex = thisStatic {
    pname = "flex";
    version = "2.5.35";
    url = "https://src.fedoraproject.org/lookaside/pkgs/flex/flex-2.5.35.tar.bz2/10714e50cea54dc7a227e3eddcd44d57/flex-2.5.35.tar.bz2";
    hash = "0nkghq13zhxjcggfb9na8qa0fdv1fdhqwhv4lnskg34lfv8501s9";
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
    postInstall = ''
      [ ! -f "$out/bin/lex" ] && ln -sf flex "$out/bin/lex"
    '';
    meta = gnuMeta "Fast lexical analyzer generator, version 2.5.35" "https://github.com/westes/flex" "BSD-2-Clause";
  };

  bison = thisStatic {
    pname = "bison";
    version = "3.0.4";
    url = "https://mirrors.kernel.org/gnu/bison/bison-3.0.4.tar.xz";
    hash = "1pxj97dfh3iabxcc4g60y739zkd788kf4cv64zb515676lckmj9y";
    buildDeps = [
      texinfo
      help2man
      m4
      flex
      autoconf
      prev.perl
    ];
    cflags = "-O2 -fgnu89-inline -isystem ${prev.glibc}/include";
    configureFlags = tripletBuildHostNoNls;
    configureEnv = ''
      export M4="${m4}/bin/m4"
    '';
    postConfigure = ''
      sed -i '/gets is a security hole/d' lib/stdio.in.h 2>/dev/null || true
      touch "$sourceDir/lib/config.in.h" "$sourceDir/aclocal.m4" 2>/dev/null || true
    '';
    buildScript = ''
      make -j"$NIX_BUILD_CORES" MAKEINFO=true AUTOHEADER=true AUTOCONF=true ACLOCAL=true AUTOMAKE=true
    '';
    installScript = ''
      make install MAKEINFO=true AUTOHEADER=true AUTOCONF=true ACLOCAL=true AUTOMAKE=true
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

  autoconf = {
    pname = "autoconf";
    version = "2.63";
    url = "https://mirrors.kernel.org/gnu/autoconf/autoconf-2.63.tar.bz2";
    hash = "0dr93pzan0q3fwwwsr81sj7mll9k92q0x4n8y0zr8cr2xj2l70p9";
    buildDeps = [
      texinfo
      help2man
      m4
      perl
    ];
    configureInSource = true;
    configureFlags = tripletBuildHost;
    configureEnv = ''
      export M4="${m4}/bin/m4"
      export PERL="${perl}/bin/perl"
    '';
    meta = gnuMeta "GNU Autoconf, version 2.63" "https://www.gnu.org/software/autoconf/" "GPL-3.0-or-later";
  };

  automake = {
    pname = "automake";
    version = "1.11.1";
    url = "https://mirrors.kernel.org/gnu/automake/automake-1.11.1.tar.bz2";
    hash = "0c5z2j7fxchqclm97gmgayl1m6vr73cw2ij1rn95jggp6rb1wrmh";
    buildDeps = [
      texinfo
      help2man
      m4
      perl
      autoconf
    ];
    configureInSource = true;
    freezeAutotoolsTimestamps = false;
    configureFlags =
      tripletBuildHost
      ++ ["--disable-maintainer-mode"];
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    postUnpack = ''
      find . -type f -exec touch {} + 2>/dev/null || true
    '';
    postConfigure = ''
      touch aclocal.m4 Makefile
    '';
    buildScript = ''
      make -j"$NIX_BUILD_CORES" ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true
    '';
    installScript = ''
      make install ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true
    '';
    meta = gnuMeta "GNU Automake, version 1.11.1" "https://www.gnu.org/software/automake/" "GPL-2.0-or-later";
  };

  gperf = thisStatic {
    pname = "gperf";
    version = "3.0.4";
    url = "https://mirrors.kernel.org/gnu/gperf/gperf-3.0.4.tar.gz";
    hash = "12pqgvxmyckqv1b5qhi80qmwkvpvr604w7qckbn1dfkykl96rdgb";
    configureFlags = tripletBuildHost;
    useCxx = true;
    cxxflags = "-O2 -isystem ${prev.glibc}/include";
    meta = gnuMeta "GNU perfect hash function generator, version 3.0.4" "https://www.gnu.org/software/gperf/" "GPL-3.0-or-later";
  };

  bash = prevStatic {
    pname = "bash";
    version = "4.1";
    url = "https://mirrors.kernel.org/gnu/bash/bash-4.1.tar.gz";
    hash = "sha256-P2JxJKg8bTTbUDqSPiBxDTcFc6Kd1dEdbxFtGu574do=";
    fetchMode = "url";
    buildDeps = autotoolsDeps;
    configureFlags =
      tripletNoNls
      ++ ["--without-bash-malloc"];
    postFreeze = ''
      # Bash's Makefile invokes autoconf directly when configure is older than
      # its inputs, bypassing the disabled-maintainer-tool arguments below.
      touch configure
    '';
    # The generated builtins have an undeclared executable-permission
    # dependency in this release and race under a parallel first build.
    buildScript = ''
      make -j1
    '';
    postInstall = ''
      [ -f "$out/bin/bash" ] && [ ! -f "$out/bin/sh" ] && ln -sf bash "$out/bin/sh"
    '';
    meta = gnuMeta "GNU Bourne-Again SHell, version 4.1" "https://www.gnu.org/software/bash/" "GPL-3.0-or-later";
  };

  coreutils = prevStatic {
    pname = "coreutils";
    version = "8.4";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.4.tar.gz";
    hash = "sha256-i7CNP1hD8l0PMGhIzDUUiJIyJn5o2aZt0g4eNj0NAX8=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [perl];
    configureFlags =
      tripletNoNls
      ++ [
        "--enable-no-install-program=stdbuf"
        "ac_cv_func_lchmod=no"
      ];
    postConfigure = ''
      sed -i 's/libstdbuf\.so//g' src/Makefile
    '';
    meta = gnuMeta "GNU core utilities (ls, cat, cp, mv, etc.), version 8.4" "https://www.gnu.org/software/coreutils/" "GPL-3.0-or-later";
  };

  gnumake = prevStatic {
    pname = "gnumake";
    version = "3.82";
    url = "https://mirrors.kernel.org/gnu/make/make-3.82.tar.bz2";
    hash = "sha256-4sGnPxecQMceL+ir+KigaIuEmVOFEphNpKdpWNBAKWY=";
    fetchMode = "url";
    srcName = "make-3.82.tar.bz2";
    buildDeps = autotoolsDeps ++ [bzip2];
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU Make build automation tool, version 3.82" "https://www.gnu.org/software/make/" "GPL-3.0-or-later";
  };

  sed = prevStatic {
    pname = "sed";
    version = "4.2.1";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.2.1.tar.bz2";
    hash = "sha256-KsOzbKN7/rQ8TvQCV3jNZticd6u4Q9kFUqUVp8nSlI8=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [bzip2];
    configureFlags = tripletNoNls;
    postUnpack = ''
      rm -f build-aux/help2man
      ln -sf ${help2man}/bin/help2man build-aux/help2man
    '';
    meta = gnuMeta "GNU stream editor, version 4.2.1" "https://www.gnu.org/software/sed/" "GPL-3.0-or-later";
  };

  grep = prevStatic {
    pname = "grep";
    version = "2.6.3";
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.6.3.tar.gz";
    hash = "sha256-o0Dl0VRNmpZAchlr5ie60+Q0/3qH86V+oVqsy76k1mY=";
    fetchMode = "url";
    buildDeps = autotoolsDeps;
    configureFlags =
      tripletNoNls
      ++ ["--disable-perl-regexp"];
    meta = gnuMeta "GNU grep pattern matching utility, version 2.6.3" "https://www.gnu.org/software/grep/" "GPL-3.0-or-later";
  };

  gawk = prevStatic {
    pname = "gawk";
    version = "3.1.7";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-3.1.7.tar.bz2";
    hash = "sha256-8St2uJY8WkOKVqcyI60prrkAx/AE3rYkL6szJBiO3nE=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [bzip2];
    configureFlags = tripletNoNls;
    postFreeze = ''
      sed -i 's/awklib//g' Makefile.in
    '';
    postInstall = ''
      [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"
    '';
    meta = gnuMeta "GNU awk pattern scanning and processing language, version 3.1.7" "https://www.gnu.org/software/gawk/" "GPL-3.0-or-later";
  };

  findutils = prevStatic {
    pname = "findutils";
    version = "4.4.2";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.4.2.tar.gz";
    hash = "sha256-Q08y0XHLwKXnLPxTcsb8TLDmgfjc5Wag3ltvzNcCtio=";
    fetchMode = "url";
    buildDeps = autotoolsDeps;
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU find, xargs, and locate utilities, version 4.4.2" "https://www.gnu.org/software/findutils/" "GPL-3.0-or-later";
  };

  diffutils = prevStatic {
    pname = "diffutils";
    version = "3.0";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.0.tar.gz";
    hash = "sha256-L7kfZbuuPGBDuFuiOWfycjWxKSjajkBtyRtIsKWJ6Ak=";
    fetchMode = "url";
    buildDeps = autotoolsDeps;
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 3.0" "https://www.gnu.org/software/diffutils/" "GPL-3.0-or-later";
  };

  tar = prevStatic {
    pname = "tar";
    version = "1.23";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.23.tar.bz2";
    hash = "sha256-yTKDctti+7HZTJ5OPO/JYREa9G3kcIW2NTWcAKDuvjY=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [bzip2];
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU tar archiving utility, version 1.23" "https://www.gnu.org/software/tar/" "GPL-3.0-or-later";
  };

  gzip = prevStatic {
    pname = "gzip";
    version = "1.3.12";
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.3.12.tar.gz";
    hash = "sha256-P1Zb4F9/PRr/EXwDDrfHODAFELfQmM7ep5bKjkzVh68=";
    fetchMode = "url";
    buildDeps = autotoolsDeps;
    cflags = "-O2 -D_GNU_SOURCE -DAT_FDCWD=-100 -isystem ${prev.glibc}/include";
    configureFlags = [];
    meta = gnuMeta "GNU gzip compression utility, version 1.3.12" "https://www.gnu.org/software/gzip/" "GPL-3.0-or-later";
  };

  patch = prevStatic {
    pname = "patch";
    version = "2.6.1";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.6.1.tar.bz2";
    hash = "sha256-HRRBOAyS7YVyBJQRQGlkoKmHrv0ii+OruGI+yh887Yo=";
    fetchMode = "url";
    buildDeps = autotoolsDeps ++ [bzip2];
    configureFlags = [];
    meta = gnuMeta "GNU patch file patching utility, version 2.6.1" "https://www.gnu.org/software/patch/" "GPL-3.0-or-later";
  };
}
