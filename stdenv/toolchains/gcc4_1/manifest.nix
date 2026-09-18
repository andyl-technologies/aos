# stdenv/toolchains/gcc4_1/manifest.nix - GCC 4.1 tier POSIX/autotools manifest
{
  buildPlatform,
  hostPlatform,
  prev,
  gcc,
  binutils,
  glibc,
  perl,
  texinfo,
  help2man,
  m4,
  flex,
  bison,
  autoconf,
  automake,
}: let
  tripletBuildHost = [
    "--build=${buildPlatform.config}"
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

  gnuMeta = description: homepage: license: {
    inherit description homepage license;
    build = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
    execute = {
      os = "linux";
      cpu = [
        "x86_64"
        "i686"
      ];
    };
  };

  phase35Compiler = {
    inherit gcc;
    binutils = prev.binutils;
    glibc = prev.glibc;
  };

  fullCompiler = {
    inherit gcc binutils glibc;
  };

  staticProfile = compiler: attrs: let
    userConfigureEnv = attrs.configureEnv or "";
  in
    {
      inherit compiler;
      gccVersion = "4.1.2";
      staticNssWrapper = true;
      cflags = "-O2 -isystem ${compiler.glibc}/include";
      cppflags = "-isystem ${compiler.glibc}/include";
      ldflags = "-L${compiler.glibc}/lib -static -Wl,-u,dl_iterate_phdr";
    }
    // attrs
    // {
      configureEnv = ''
        unset CXX CXXFLAGS
        unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH LD_LIBRARY_PATH
        unset PKG_CONFIG_PATH
        ${userConfigureEnv}
      '';
    };

  phase35Static = staticProfile phase35Compiler;
  fullStatic = staticProfile fullCompiler;

  stripMakefileRegenRules = ''
    find . -name Makefile | while read f; do
      sed -i 's/^Makefile:.*/Makefile:/; s/^config\.status:.*/config.status:/; s/^configure:.*/configure:/' "$f"
    done
  '';

  fakeAutotools = ''
    mkdir -p "$TMPDIR/fakebin"
    for tool in autoconf autoheader aclocal automake autoreconf autom4te; do
      printf '#!%s\nexit 0\n' "$AOS_BASH" > "$TMPDIR/fakebin/$tool"
      chmod +x "$TMPDIR/fakebin/$tool"
    done
    export PATH="$TMPDIR/fakebin:$PATH"
  '';

  withDisabledRegen = attrs: let
    preConfigure = attrs.preConfigure or "";
    postConfigure = attrs.postConfigure or "";
    buildScript =
      attrs.buildScript
      or ''
        make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES" ${autotoolsVars}
      '';
    installScript =
      attrs.installScript
      or ''
        make SHELL="$CONFIG_SHELL" install ${autotoolsVars}
      '';
  in
    attrs
    // {
      preConfigure = ''
        ${fakeAutotools}
        ${preConfigure}
      '';
      postConfigure = ''
        ${stripMakefileRegenRules}
        ${postConfigure}
      '';
      inherit buildScript installScript;
    };
in {
  perl = phase35Static (import ../lib/perl-static.nix {
    inherit (prev) glibc coreutils;
    meta = gnuMeta "Practical Extraction and Report Language, version 5.10.1" "https://www.perl.org/" "Artistic-1.0-Perl OR GPL-1.0-or-later";
  });

  texinfo = phase35Static {
    pname = "texinfo";
    version = "4.13";
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-4.13a.tar.gz";
    hash = "012rj0sa6f1jj8namymb68bznq420zfavixm6g9k36jbjb718v78";
    buildDeps = [
      perl
      help2man
    ];
    configureInSource = true;
    configureFlags = tripletBuildHostNoNls;
    configureEnv = ''
      export PERL="${perl}/bin/perl"
      export LDFLAGS="$LDFLAGS -L$TMPDIR"
      export LIBS="-ltermcap"
    '';
    preConfigure = ''
      cat > "$TMPDIR/termcap_stub.c" <<'TCEOF'
      char *tgetstr(const char *id, char **area) { return (char *)0; }
      int tgetent(char *bp, const char *name) { return 1; }
      int tgetnum(const char *id) { return 80; }
      int tgetflag(const char *id) { return 0; }
      char *tgoto(const char *cm, int destcol, int destline) { return ""; }
      int tputs(const char *str, int affcnt, int (*putc_fn)(int)) { return 0; }
      TCEOF
      "$CC" $CFLAGS -c "$TMPDIR/termcap_stub.c" -o "$TMPDIR/termcap_stub.o"
      "$AR" rcs "$TMPDIR/libtermcap.a" "$TMPDIR/termcap_stub.o"
    '';
    meta = gnuMeta "GNU documentation system, version 4.13" "https://www.gnu.org/software/texinfo/" "GPL-3.0-or-later";
  };

  help2man = phase35Static {
    pname = "help2man";
    version = "1.36.4";
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.36.4.tar.gz";
    hash = "124i3pfk6j1ggpkixsbyxsm374k0yz3n8rdphgkkzzx8cy4ai779";
    buildDeps = [perl];
    configureInSource = true;
    configureFlags = tripletBuildHostNoNls;
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    meta = gnuMeta "GNU help2man 1.36.4 generates man pages from --help output" "https://www.gnu.org/software/help2man/" "GPL-3.0-or-later";
  };

  m4 = phase35Static {
    pname = "m4";
    version = "1.4.9";
    url = "https://mirrors.kernel.org/gnu/m4/m4-1.4.9.tar.bz2";
    hash = "1vxf44182dn77mvx90w3ycyhxzra3msw607ifd8rq46ym9zsiia3";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletBuildHostNoNls;
    postFreeze = ''
      touch config.hin 2>/dev/null || true
    '';
    postConfigure = stripMakefileRegenRules;
    meta = gnuMeta "GNU m4 macro processor, version 1.4.9" "https://www.gnu.org/software/m4/" "GPL-3.0-or-later";
  };

  flex = phase35Static {
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
      touch parse.c parse.h
    '';
    postInstall = ''
      [ ! -f "$out/bin/lex" ] && ln -sf flex "$out/bin/lex"
    '';
    meta = gnuMeta "Fast lexical analyzer generator, version 2.5.35" "https://github.com/westes/flex" "BSD-2-Clause";
  };

  bison = phase35Static {
    pname = "bison";
    version = "2.4.3";
    url = "https://mirrors.kernel.org/gnu/bison/bison-2.4.3.tar.gz";
    hash = "0754bvjsakji89lpvc4yhilgfpqdldz2gbcazqqhmr1ygvgz3m1m";
    buildDeps = [
      texinfo
      help2man
      m4
      flex
    ];
    configureInSource = true;
    configureFlags = tripletBuildHostNoNls;
    configureEnv = ''
      export M4="${m4}/bin/m4"
    '';
    postConfigure = ''
      sed -i '/gets is a security hole/d' lib/stdio.in.h 2>/dev/null || true
      touch doc/cross-options.texi doc/bison.1
      ${stripMakefileRegenRules}
      sed -i \
        -e '/parse-gram\.y/s/:.*/: ;/' \
        -e '/scan-code\.l/s/:.*/: ;/' \
        -e '/scan-gram\.l/s/:.*/: ;/' \
        -e '/scan-skel\.l/s/:.*/: ;/' \
        src/Makefile
      touch src/parse-gram.c src/parse-gram.h \
            src/scan-code.c src/scan-gram.c src/scan-skel.c
    '';
    buildScript = ''
      make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES" MAKEINFO=true
    '';
    installScript = ''
      make SHELL="$CONFIG_SHELL" install MAKEINFO=true
    '';
    postInstall = ''
      mkdir -p "$out/bin"
      cat > "$out/bin/yacc" <<YACC
      #!$AOS_BASH
      exec "$out/bin/bison" -y "\$@"
      YACC
      chmod +x "$out/bin/yacc"
    '';
    meta = gnuMeta "GNU parser generator, version 2.4.3" "https://www.gnu.org/software/bison/" "GPL-3.0-or-later";
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
      unset CXX CXXFLAGS
      unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH LD_LIBRARY_PATH
      unset PKG_CONFIG_PATH
      export M4="${m4}/bin/m4"
      export PERL="${perl}/bin/perl"
    '';
    buildScript = ''
      make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES" ${autotoolsVars}
    '';
    installScript = ''
      make SHELL="$CONFIG_SHELL" install ${autotoolsVars}
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
    configureFlags = tripletBuildHost;
    configureEnv = ''
      unset CXX CXXFLAGS
      unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH LD_LIBRARY_PATH
      unset PKG_CONFIG_PATH
      export PERL="${perl}/bin/perl"
    '';
    postConfigure = ''
      sed -i '/^SUBDIRS/s/ tests//; /^SUBDIRS/s/ doc//' Makefile
    '';
    buildScript = ''
      make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES" ${autotoolsVars}
    '';
    installScript = ''
      make SHELL="$CONFIG_SHELL" install ${autotoolsVars}
    '';
    meta = gnuMeta "GNU Automake, version 1.11.1" "https://www.gnu.org/software/automake/" "GPL-2.0-or-later";
  };

  bash = fullStatic {
    pname = "bash";
    version = "3.2";
    url = "https://mirrors.kernel.org/gnu/bash/bash-3.2.tar.gz";
    hash = "1n8ggjpfbzlfcz891bfms4a5kylz8244m05qx0yw6g5q95b2viwr";
    buildDeps = [
      m4
      flex
      bison
      autoconf
      automake
      texinfo
      help2man
    ];
    configureInSource = true;
    configureFlags =
      tripletNoNls
      ++ ["--without-bash-malloc"];
    buildScript = ''
      # Recursive make processes otherwise regenerate shared headers together.
      make SHELL="$CONFIG_SHELL" -j1 builtins/builtext.h
      test -s builtins/builtext.h && test -s builtins/builtins.c
      # The generator restores old timestamps when output text is unchanged.
      # Mark its verified outputs current before starting recursive consumers.
      touch builtins/builtext.h builtins/builtins.c
      make SHELL="$CONFIG_SHELL" -j1 version.h

      make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES"
    '';
    postInstall = ''
      [ -f "$out/bin/bash" ] && [ ! -f "$out/bin/sh" ] && ln -sf bash "$out/bin/sh"
    '';
    meta = gnuMeta "GNU Bourne-Again SHell, version 3.2" "https://www.gnu.org/software/bash/" "GPL-3.0-or-later";
  };

  coreutils = fullStatic (withDisabledRegen {
    pname = "coreutils";
    version = "5.97";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-5.97.tar.bz2";
    hash = "0xq92cfg0dgd2d4bj1fc8p6ymapbfaavwcl1vhl6nvrqbxfmbkp5";
    buildDeps = [
      texinfo
      help2man
      perl
    ];
    configureInSource = true;
    configureFlags = tripletNoNls;
    postUnpack = ''
      {
        printf '#!%s\n' "$AOS_BASH"
        cat <<'WHEELEOF'
      N=$1
      gawk -v n="$N" '
      BEGIN {
        split("2 3 5 7 11 13 17 19 23 29 31", p)
        prod = 1
        for (i = 1; i <= n; i++) prod *= p[i]
        nc = 0
        for (k = 1; k <= prod; k++) {
          coprime = 1
          for (i = 1; i <= n; i++)
            if (k % p[i] == 0) { coprime = 0; break }
          if (coprime) { nc++; c[nc] = k }
        }
        for (i = 1; i < nc; i++) {
          d = c[i+1] - c[i]
          if (i > 1) printf ","
          if ((i-1) % 16 == 0) printf "\n  "
          else printf " "
          printf "%d", d
        }
        d = c[1] + prod - c[nc]
        printf ", %d,\n", d
      }'
      WHEELEOF
      } > src/wheel-gen.pl
      chmod +x src/wheel-gen.pl

      {
        printf '#!%s\n' "$AOS_BASH"
        cat <<'EMEOF'
      gawk '
      /S_MAGIC_[A-Z0-9_]+/ && /0x[0-9a-fA-F]+/ {
        match($0, /S_MAGIC_[A-Z0-9_]+/)
        name = substr($0, RSTART, RLENGTH)
        match($0, /0x[0-9a-fA-F]+/)
        val = substr($0, RSTART, RLENGTH)
        if (!(name in seen)) {
          printf "#define %s %s\n", name, val
          seen[name] = 1
        }
      }' "$@"
      EMEOF
      } > src/extract-magic
      chmod +x src/extract-magic

      {
        printf '#!%s\n' "$AOS_BASH"
        cat <<'HELPEOF'
      out=""
      next_is_out=""
      for arg; do
        if test -n "$next_is_out"; then
          out="$arg"
          next_is_out=""
          continue
        fi
        case "$arg" in
          -o) next_is_out=1 ;;
        esac
      done
      if test -n "$out"; then
        dir="''${out%/*}"
        if test "$dir" != "$out"; then
          mkdir -p "$dir"
        fi
        printf '.TH DUMMY 1\n' > "$out"
      fi
      exit 0
      HELPEOF
      } > man/help2man
      chmod +x man/help2man

      for d in man tests; do
        if test -d "$d"; then
          printf 'all install install-data install-exec uninstall:\n\t@true\n' > "$d/Makefile.in"
        fi
      done
    '';
    postConfigure = ''
      touch src/dircolors.h src/fs.h src/wheel.h
      touch lib/getdate.c lib/getdate.h
    '';
    meta = gnuMeta "GNU core utilities (ls, cat, cp, mv, etc.), version 5.97" "https://www.gnu.org/software/coreutils/" "GPL-2.0-or-later";
  });

  gnumake = fullStatic (withDisabledRegen {
    pname = "gnumake";
    version = "3.81";
    url = "https://mirrors.kernel.org/gnu/make/make-3.81.tar.bz2";
    hash = "1lvil72fkzv18p3nlgxpibp2s6058a6080fvg56124c75982bywk";
    srcName = "make-3.81.tar.bz2";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU Make build automation tool, version 3.81" "https://www.gnu.org/software/make/" "GPL-2.0-or-later";
  });

  sed = fullStatic (withDisabledRegen {
    pname = "sed";
    version = "4.1.5";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.1.5.tar.gz";
    hash = "166i1j1lhnf9kg85qbf27gqfb89ym5c949a2y7pvf20rh3rlfls3";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletNoNls;
    postUnpack = ''
      rm -f config/help2man
      ln -sf ${help2man}/bin/help2man config/help2man
    '';
    meta = gnuMeta "GNU stream editor, version 4.1.5" "https://www.gnu.org/software/sed/" "GPL-2.0-or-later";
  });

  grep = fullStatic (withDisabledRegen {
    pname = "grep";
    version = "2.5.1";
    url = "https://mirrors.kernel.org/gnu/grep/grep-2.5.1.tar.bz2";
    hash = "0in49mhmxsl52jyzp0qwz31xz8yvyfxsjxx17x1az01d5kvkk11l";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags =
      tripletNoNls
      ++ ["--disable-perl-regexp"];
    meta = gnuMeta "GNU grep pattern matching utility, version 2.5.1" "https://www.gnu.org/software/grep/" "GPL-2.0-or-later";
  });

  gawk = fullStatic (withDisabledRegen {
    pname = "gawk";
    version = "3.1.5";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-3.1.5.tar.bz2";
    hash = "1lppns8zam90fngnm54kmzvdxyi11rvzaq2y153a8jkvymdk7ykv";
    buildDeps = [
      texinfo
      help2man
      bison
    ];
    configureFlags = tripletNoNls;
    buildScript = ''
      make SHELL="$CONFIG_SHELL" -j"$NIX_BUILD_CORES" ${autotoolsVars} MAKEINFO=true
    '';
    installScript = ''
      make SHELL="$CONFIG_SHELL" install ${autotoolsVars} MAKEINFO=true
    '';
    postInstall = ''
      [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"
    '';
    meta = gnuMeta "GNU awk pattern scanning and processing language, version 3.1.5" "https://www.gnu.org/software/gawk/" "GPL-2.0-or-later";
  });

  findutils = fullStatic (withDisabledRegen {
    pname = "findutils";
    version = "4.2.27";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.2.27.tar.gz";
    hash = "008jzg0bapzqz4vnyx00dvl73j3z289p5m3j26km99l2x9xamm92";
    buildDeps = [
      texinfo
      help2man
    ];
    ldflags = "-L${glibc}/lib -static -Wl,-z,muldefs -Wl,-u,dl_iterate_phdr";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU find, xargs, and locate utilities, version 4.2.27" "https://www.gnu.org/software/findutils/" "GPL-2.0-or-later";
  });

  diffutils = fullStatic (withDisabledRegen {
    pname = "diffutils";
    version = "2.8.1";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-2.8.1.tar.gz";
    hash = "198ja157yardrjq27pr5whbv73mn6hld0s9dfv1lkwdisd7y0k37";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 2.8.1" "https://www.gnu.org/software/diffutils/" "GPL-2.0-or-later";
  });

  tar = fullStatic (withDisabledRegen {
    pname = "tar";
    version = "1.15.1";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.15.1.tar.bz2";
    hash = "1fdpksngnia6812pcrxhwrmqkr1w9rrdfy1askbbzvyas4p2slm9";
    buildDeps = [
      bison
      texinfo
      help2man
    ];
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU tar archiving utility, version 1.15.1" "https://www.gnu.org/software/tar/" "GPL-2.0-or-later";
  });

  gzip = fullStatic (withDisabledRegen {
    pname = "gzip";
    version = "1.3.5";
    url = "https://alpha.gnu.org/gnu/gzip/gzip-1.3.5.tar.gz";
    hash = "1pkqayhb6rs3aj858wxyga4q3nha8x9y7bn5lbqad4985y5a0hm7";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletBuildHost;
    meta = gnuMeta "GNU gzip compression utility, version 1.3.5" "https://www.gnu.org/software/gzip/" "GPL-2.0-or-later";
  });

  patch = fullStatic (withDisabledRegen {
    pname = "patch";
    version = "2.5.4";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.5.4.tar.gz";
    hash = "0wrlwv5qz02ln3m90yxmwrnv7mgdp2yidarrih1ah9ig5lcdjhmg";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletBuildHost;
    meta = gnuMeta "GNU patch file patching utility, version 2.5.4" "https://www.gnu.org/software/patch/" "GPL-2.0-or-later";
  });
}
