# stdenv/toolchains/gcc14/manifest.nix - GCC 14 tier POSIX tool manifest
{
  buildPlatform,
  hostPlatform,
  glibc,
  m4,
  flex,
  bison,
  perl,
  autoconf,
  automake,
  texinfo,
  help2man,
  bash,
  coreutils,
  grep,
}: let
  tripletFlags = [
    "--build=${buildPlatform.config}"
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

  gcc14 = attrs:
    attrs
    // {
      gccVersion = "14.3.0";
      cflags = attrs.cflags or "-O2 -isystem ${glibc.dev}/include";
      cppflags = attrs.cppflags or "-isystem ${glibc.dev}/include";
      ldflags = attrs.ldflags or "-L${glibc.static}/lib -L${glibc}/lib -static -no-pie";
    };
in {
  perl = gcc14 {
    pname = "perl";
    version = "5.38.2";
    url = "https://www.cpan.org/src/5.0/perl-5.38.2.tar.xz";
    hash = "1rq336jq0bghfvxrc2y7qpnni2snsszgb3nfimba1alrnf5vw42q";
    freezeAutotoolsTimestamps = false;
    configureEnv = ''
      PWD_CMD="$(type -P pwd)"
      export PWD_CMD
    '';
    configureScript = ''
      sed -i "s|'/bin/pwd'|'$PWD_CMD', '/bin/pwd'|" dist/PathTools/Cwd.pm
      sed -i 's/getcwd()/getcwd() || "."/' dist/PathTools/Cwd.pm 2>/dev/null || true

      sed -i \
        -e "s|/usr/include/errno.h|${glibc.dev}/include/errno.h|g" \
        -e "s|/usr/local/include/errno.h|${glibc.dev}/include/errno.h|g" \
        ext/Errno/Errno_pm.PL

      ./Configure \
        -des \
        -Dprefix="$out" \
        -Dcc="$CC" \
        -Dccflags="-O2 -isystem ${glibc.dev}/include" \
        -Dcppflags="-isystem ${glibc.dev}/include" \
        -Dldflags="-L${glibc.static}/lib -L${glibc}/lib -static -no-pie" \
        -Dlibs="-lm -lpthread" \
        -Dar="$AR" \
        -Dfull_ar="$AR" \
        -Dranlib="$RANLIB" \
        -Dnm="$NM" \
        -Dsh="$AOS_BASH" \
        -Dlocincpth="" \
        -Dloclibpth="" \
        -Dglibpth="${glibc}/lib" \
        -Dusrinc="${glibc.dev}/include" \
        -Uusedl \
        -Uusevendorprefix \
        -Dman1dir=none \
        -Dman3dir=none \
        -Ui_xlocale
    '';
    buildScript = ''
      make -j1
    '';
    installScript = ''
      make install ${autotoolsVars}
    '';
    meta = gnuMeta "Perl programming language 5.38.2" "https://www.perl.org/" "Artistic-1.0-Perl OR GPL-1.0-or-later";
  };

  texinfo = gcc14 {
    pname = "texinfo";
    version = "7.1";
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-7.1.tar.xz";
    hash = "045aswlbs2n367k1n3xga6gh7bmjq5mkw8yd3zz3w8cxb0zkk16b";
    buildDeps = [
      perl
      help2man
    ];
    configureFlags =
      tripletFlags
      ++ [
        "--disable-nls"
        "--disable-perl-xs"
      ];
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    postFreeze = ''
      find . -name '*.info' -exec touch -t 200001010200.00 {} + 2>/dev/null || true
      find . -name '*.1' -exec touch {} + 2>/dev/null || true
    '';
    postConfigure = ''
      mkdir -p tp/Texinfo
      (cd tp && ${perl}/bin/perl \
        "$sourceDir/tp/maintain/regenerate_commands_perl_info.pl" \
        < "$sourceDir/tp/Texinfo/command_data.txt")
      touch tp/Texinfo/Commands.pm
    '';
    buildScript = ''
      make -k -j"$NIX_BUILD_CORES" ${autotoolsVars} || true
      test -f tp/texi2any || { echo "FATAL: texi2any not built"; exit 1; }
    '';
    installScript = ''
      make install -k ${autotoolsVars} || true

      if [ ! -f "$out/bin/texi2any" ]; then
        mkdir -p "$out/bin"
        cp tp/texi2any "$out/bin/texi2any"
        chmod +x "$out/bin/texi2any"
      fi
      [ ! -e "$out/bin/makeinfo" ] && ln -sf texi2any "$out/bin/makeinfo"

      if [ -f install-info/ginstall-info ] && [ ! -f "$out/bin/install-info" ]; then
        cp install-info/ginstall-info "$out/bin/install-info"
        chmod +x "$out/bin/install-info"
      fi

      if [ ! -d "$out/share/texinfo/Texinfo" ]; then
        mkdir -p "$out/share/texinfo"
        cp -r tp/Texinfo "$out/share/texinfo/Texinfo"
      fi

      test -f "$out/bin/makeinfo" || { echo "FATAL: makeinfo not installed"; exit 1; }
      test -f "$out/bin/texi2any" || { echo "FATAL: texi2any not installed"; exit 1; }
    '';
    meta = gnuMeta "GNU Texinfo documentation system 7.1" "https://www.gnu.org/software/texinfo/" "GPL-3.0-or-later";
  };

  help2man = gcc14 {
    pname = "help2man";
    version = "1.49.3";
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.49.3.tar.xz";
    hash = "1hz5jzvgp025wcqlifv23mgb6m8wvk22kgz03g92ha13ympa2i03";
    buildDeps = [perl];
    configureInSource = true;
    configureFlags = [
      "--build=${buildPlatform.config}"
      "--host=${hostPlatform.config}"
    ];
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    meta = gnuMeta "GNU help2man 1.49.3 generates man pages from --help output" "https://www.gnu.org/software/help2man/" "GPL-3.0-or-later";
  };

  m4 = gcc14 {
    pname = "m4";
    version = "1.4.19";
    url = "https://mirrors.kernel.org/gnu/m4/m4-1.4.19.tar.xz";
    hash = "02xz8gal0fdc4gzjwyiy1557q31xcpg896yc0y6kd8s5jbynvdmf";
    buildDeps = [
      texinfo
      help2man
    ];
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU m4 macro processor 1.4.19" "https://www.gnu.org/software/m4/" "GPL-3.0-or-later";
  };

  flex = gcc14 {
    pname = "flex";
    version = "2.6.4";
    url = "https://github.com/westes/flex/releases/download/v2.6.4/flex-2.6.4.tar.gz";
    hash = "05gbq5hklzdfvjjc3hyr98hrm8wkr20ds0y3l7c825va798c04qw";
    buildDeps = [
      texinfo
      help2man
      m4
    ];
    configureFlags = tripletNoNls;
    configureEnv = ''
      export M4="${m4}/bin/m4"
    '';
    postInstall = ''
      ln -s flex "$out/bin/lex"
    '';
    meta = gnuMeta "Fast lexical analyzer generator 2.6.4" "https://github.com/westes/flex" "BSD-2-Clause";
  };

  bison = gcc14 {
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
    postUnpack = ''
      sed -i '1s|#!/usr/bin/perl|#!${perl}/bin/perl|' examples/extexi 2>/dev/null || true
    '';
    postInstall = ''
      cat > "$out/bin/yacc" <<YACC
      #!$AOS_BASH
      exec "$out/bin/bison" -y "\$@"
      YACC
      chmod +x "$out/bin/yacc"
    '';
    meta = gnuMeta "GNU parser generator 3.8.2" "https://www.gnu.org/software/bison/" "GPL-3.0-or-later";
  };

  autoconf = gcc14 {
    pname = "autoconf";
    version = "2.72";
    url = "https://mirrors.kernel.org/gnu/autoconf/autoconf-2.72.tar.xz";
    hash = "1r3922ja9g5ziinpqxgfcc51jhrxvjqnrmc5054jgskylflxc1fp";
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
    meta = gnuMeta "GNU Autoconf 2.72" "https://www.gnu.org/software/autoconf/" "GPL-3.0-or-later";
  };

  automake = gcc14 {
    pname = "automake";
    version = "1.17";
    url = "https://mirrors.kernel.org/gnu/automake/automake-1.17.tar.xz";
    hash = "1nwgz937zikw5avzhvvzf57i917pq0q05s73wqr28abwqxa3bll8";
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
    meta = gnuMeta "GNU Automake 1.17" "https://www.gnu.org/software/automake/" "GPL-2.0-or-later";
  };

  gperf = gcc14 {
    pname = "gperf";
    version = "3.1";
    url = "https://mirrors.kernel.org/gnu/gperf/gperf-3.1.tar.gz";
    hash = "1cdivawkjb635zkq5qd512d533b47w16bg1xm4sybpzcy65xn37k";
    buildDeps = [texinfo];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletFlags;
    useCxx = true;
    cxxflags = "-O2 -isystem ${glibc.dev}/include";
    meta = gnuMeta "GNU perfect hash function generator 3.1" "https://www.gnu.org/software/gperf/" "GPL-3.0-or-later";
  };

  python3 = gcc14 {
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
      sed -i '/^build_all:/s/ sharedmods / /' Makefile
    '';
    installScript = ''
      mkdir -p "$out/bin" "$out/lib/python3.8/lib-dynload" "$out/include/python3.8"

      cp python "$out/bin/python3.8"
      chmod +x "$out/bin/python3.8"

      ./python -E -S -m sysconfig --generate-posix-vars

      cp -R Lib/. "$out/lib/python3.8/"
      if [ -f pybuilddir.txt ]; then
        pybuilddir="$(cat pybuilddir.txt)"
        if [ -d "$pybuilddir" ]; then
          find "$pybuilddir" -maxdepth 1 -type f -name '_sysconfigdata*.py' -exec cp {} "$out/lib/python3.8/" \;
        fi
      fi
      if [ -d build ]; then
        find build -type f -name '_sysconfigdata*.py' -exec cp {} "$out/lib/python3.8/" \;
      fi
      test -n "$(find "$out/lib/python3.8" -maxdepth 1 -type f -name '_sysconfigdata*.py' -print -quit)"

      cp -R Include/. "$out/include/python3.8/"
      cp pyconfig.h "$out/include/python3.8/pyconfig.h"
      [ -f libpython3.8.a ] && cp libpython3.8.a "$out/lib/libpython3.8.a"

      config_dir="$out/lib/python3.8/config-3.8-$("$out/bin/python3.8" -c 'import sysconfig; print(sysconfig.get_config_var("MULTIARCH") or sysconfig.get_platform())')"
      mkdir -p "$config_dir"
      cp Makefile "$config_dir/Makefile"
      cp pyconfig.h "$config_dir/pyconfig.h"
      for setup in Modules/Setup Modules/Setup.local Modules/Setup.config; do
        [ -f "$setup" ] && cp "$setup" "$config_dir/"
      done

      if [ -f python-config ]; then
        cp python-config "$out/bin/python3.8-config"
        sed -i "1s|^#!.*|#!$AOS_BASH|" "$out/bin/python3.8-config"
        chmod +x "$out/bin/python3.8-config"
      fi
      mkdir -p "$out/lib/pkgconfig"
      [ -f Misc/python.pc ] && cp Misc/python.pc "$out/lib/pkgconfig/python-3.8.pc"
      [ -f Misc/python-embed.pc ] && cp Misc/python-embed.pc "$out/lib/pkgconfig/python-3.8-embed.pc"
    '';
    postInstall = ''
      [ -f "$out/bin/python3.8" ] && [ ! -f "$out/bin/python3" ] && ln -sf python3.8 "$out/bin/python3"
      [ -f "$out/bin/python3" ] && [ ! -f "$out/bin/python" ] && ln -sf python3 "$out/bin/python"
      [ -f "$out/bin/python3.8-config" ] && [ ! -f "$out/bin/python3-config" ] && ln -sf python3.8-config "$out/bin/python3-config"
      [ -f "$out/bin/python3-config" ] && [ ! -f "$out/bin/python-config" ] && ln -sf python3-config "$out/bin/python-config"
    '';
    meta = gnuMeta "Python 3.8.18 minimal interpreter for build scripts" "https://www.python.org/" "PSF-2.0";
  };

  bash = gcc14 {
    pname = "bash";
    version = "5.2.37";
    url = "https://mirrors.kernel.org/gnu/bash/bash-5.2.37.tar.gz";
    hash = "012fmryg39p4ynmbg3abp6h1mr2ghbvsjfri66gk1ji3ikbcg01c";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    cflags = "-O2 -isystem ${glibc.dev}/include -Wno-error=implicit-function-declaration";
    configureFlags =
      tripletFlags
      ++ [
        "--without-bash-malloc"
        "--disable-nls"
      ];
    buildScript = ''
      make -j1 ${autotoolsVars}
    '';
    postInstall = ''
      [ -f "$out/bin/bash" ] && [ ! -f "$out/bin/sh" ] && ln -sf bash "$out/bin/sh"
      rm -f "$out/bin/bashbug"
    '';
    meta = gnuMeta "GNU Bourne-Again SHell 5.2.37" "https://www.gnu.org/software/bash/" "GPL-3.0-or-later";
  };

  coreutils = gcc14 {
    pname = "coreutils";
    version = "9.5";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-9.5.tar.xz";
    hash = "0250l3qc7w4l2lx2ws4wqsd2g2g2q0g6w32d9r7d9pgwqmrj2nkh";
    buildDeps = autotoolsDeps ++ [perl];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags =
      tripletNoNls
      ++ [
        "--enable-no-install-program=stdbuf"
        "--enable-single-binary=symlinks"
      ];
    meta = gnuMeta "GNU core utilities 9.5 (ls, cat, cp, mv, etc.)" "https://www.gnu.org/software/coreutils/" "GPL-3.0-or-later";
  };

  gnumake = gcc14 {
    pname = "gnumake";
    version = "4.4";
    url = "https://mirrors.kernel.org/gnu/make/make-4.4.tar.gz";
    hash = "0bpq6mvmgfc7zk69zc3i372qhixvljcjak4q15i7spmbnj30a5if";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU Make 4.4 build automation tool" "https://www.gnu.org/software/make/" "GPL-3.0-or-later";
  };

  sed = gcc14 {
    pname = "sed";
    version = "4.9";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.9.tar.xz";
    hash = "170m9hyxnhnxisvmii5z7m8i446ab97kam10rqjylj70dk8wh169";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU stream editor 4.9" "https://www.gnu.org/software/sed/" "GPL-3.0-or-later";
  };

  grep = gcc14 {
    pname = "grep";
    version = "3.11";
    url = "https://mirrors.kernel.org/gnu/grep/grep-3.11.tar.xz";
    hash = "0pm0zpzmmy6lq5ii03y1nqr1sdjalnwp69i5c926c9dm03v7v0bv";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags =
      tripletNoNls
      ++ ["--disable-perl-regexp"];
    postInstall = ''
      for f in "$out/bin/egrep" "$out/bin/fgrep"; do
        [ -f "$f" ] || continue
        sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$f"
      done
    '';
    meta = gnuMeta "GNU grep 3.11 pattern matching utility" "https://www.gnu.org/software/grep/" "GPL-3.0-or-later";
  };

  gawk = gcc14 {
    pname = "gawk";
    version = "5.3.1";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-5.3.1.tar.xz";
    hash = "1gl40cia5iyil2gdwwy5lsw5nldswp6f707jbja1zfi1ahy1c3kp";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    postInstall = ''
      [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"
      if [ -f "$out/bin/gawkbug" ]; then
        sed -i \
          -e 's|^CC=.*|CC="gcc"|' \
          -e 's|^CFLAGS=.*|CFLAGS=""|' \
          "$out/bin/gawkbug"
      fi
    '';
    meta = gnuMeta "GNU awk 5.3.1 pattern scanning and processing language" "https://www.gnu.org/software/gawk/" "GPL-3.0-or-later";
  };

  findutils = gcc14 {
    pname = "findutils";
    version = "4.10.0";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.10.0.tar.xz";
    hash = "17psmb481vpq03lmi8l4r4nm99v4yg3ri5bn4gyy0z1zzi63ywan";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    postInstall = ''
      if [ -f "$out/bin/updatedb" ]; then
        sed -i 's|sort="[^"]*/bin/sort\([^"]*\)"|sort="${coreutils}/bin/sort\1"|g' \
          "$out/bin/updatedb"
      fi
    '';
    meta = gnuMeta "GNU findutils 4.10.0 (find, xargs, locate)" "https://www.gnu.org/software/findutils/" "GPL-3.0-or-later";
  };

  diffutils = gcc14 {
    pname = "diffutils";
    version = "3.10";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.10.tar.xz";
    hash = "13cxlscmjns6dk4yp0nmmyp1ldjkbag68lmgrizcd5dzz00xi8j7";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    configureEnv = ''
      export PR_PROGRAM="${coreutils}/bin/pr"
    '';
    meta = gnuMeta "GNU diffutils 3.10 (diff, cmp, sdiff, diff3)" "https://www.gnu.org/software/diffutils/" "GPL-3.0-or-later";
  };

  tar = gcc14 {
    pname = "tar";
    version = "1.35";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.35.tar.xz";
    hash = "0cmdg6gq9v04631lfb98xg45la1b0y9r5wyspn97ri11krdlyfqz";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU tar archiving utility 1.35" "https://www.gnu.org/software/tar/" "GPL-3.0-or-later";
  };

  gzip = gcc14 {
    pname = "gzip";
    version = "1.13";
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.13.tar.xz";
    hash = "093w3a12220gzy00qi9zy52mhjlgyyh7kiimsz5xa00fgf81rbp9";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = [];
    postInstall = ''
      for f in "$out/bin/"*; do
        [ -f "$f" ] || continue
        if [ "$(head -c 2 "$f" 2>/dev/null)" = "#!" ]; then
          sed -i \
            "s|/nix/store/[a-z0-9]\{32\}-bash-[^/]*/bin/bash|${bash}/bin/bash|g" \
            "$f"
        fi
      done
      if [ -f "$out/bin/zgrep" ]; then
        sed -i \
          "s|/nix/store/[a-z0-9]\{32\}-grep-[^/]*/bin/grep|${grep}/bin/grep|g" \
          "$out/bin/zgrep"
      fi
    '';
    meta = gnuMeta "GNU gzip 1.13 compression utility" "https://www.gnu.org/software/gzip/" "GPL-3.0-or-later";
  };

  patch = gcc14 {
    pname = "patch";
    version = "2.7.6";
    url = "https://mirrors.kernel.org/gnu/patch/patch-2.7.6.tar.xz";
    hash = "1yiy0xq1ha193yga0canc9ijw4hbd92c93l7ksqlhmzsn2yph39n";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = [];
    meta = gnuMeta "GNU patch 2.7.6 file patching utility" "https://www.gnu.org/software/patch/" "GPL-3.0-or-later";
  };
}
