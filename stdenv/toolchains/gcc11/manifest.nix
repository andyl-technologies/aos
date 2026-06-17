# stdenv/toolchains/gcc11/manifest.nix - GCC 11 tier POSIX tool manifest
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

  gcc11 = attrs: attrs // {gccVersion = "11.5.0";};
in {
  perl = gcc11 {
    pname = "perl";
    version = "5.32.1";
    url = "https://www.cpan.org/src/5.0/perl-5.32.1.tar.xz";
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
        -e "s|/usr/include/errno.h|$AOS_GLIBC/include/errno.h|g" \
        -e "s|/usr/local/include/errno.h|$AOS_GLIBC/include/errno.h|g" \
        ext/Errno/Errno_pm.PL

      ./Configure \
        -des \
        -Dprefix="$out" \
        -Dcc="$CC" \
        -Dccflags="$CFLAGS" \
        -Dldflags="$LDFLAGS" \
        -Dlddlflags="$LDFLAGS" \
        -Dlibs="-lm -lpthread -lc" \
        -Dar="$AR" \
        -Dfull_ar="$AR" \
        -Dranlib="$RANLIB" \
        -Dnm="$NM" \
        -Dsh="$AOS_BASH" \
        -Dlocincpth="" \
        -Dloclibpth="" \
        -Dglibpth="$AOS_GLIBC/lib" \
        -Dusrinc="$AOS_GLIBC/include" \
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
    meta = gnuMeta "Practical Extraction and Report Language, version 5.32.1" "https://www.perl.org/" "Artistic-1.0-Perl OR GPL-1.0-or-later";
  };

  texinfo = gcc11 {
    pname = "texinfo";
    version = "6.7";
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-6.7.tar.xz";
    hash = "0bgzsh574c3qh0s5mbq7iyrd5zfh3x431719yzch7jjg28kidm6r";
    buildDeps = [perl];
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
    meta = gnuMeta "GNU documentation system, version 6.7" "https://www.gnu.org/software/texinfo/" "GPL-3.0-or-later";
  };

  help2man = gcc11 {
    pname = "help2man";
    version = "1.48.5";
    url = "https://mirrors.kernel.org/gnu/help2man/help2man-1.48.5.tar.xz";
    hash = "0d1q54b3pjxss80izg3j7yr76c06fhpx292xaarynx3myiyljwyf";
    buildDeps = [perl];
    configureInSource = true;
    configureFlags = [
      "--build=${hostPlatform.config}"
      "--host=${hostPlatform.config}"
    ];
    configureEnv = ''
      export PERL="${perl}/bin/perl"
    '';
    meta = gnuMeta "GNU help2man 1.48.5 generates man pages from --help output" "https://www.gnu.org/software/help2man/" "GPL-3.0-or-later";
  };

  m4 = gcc11 {
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

  flex = gcc11 {
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
      [ -f "$out/bin/flex" ] && [ ! -f "$out/bin/lex" ] && ln -sf flex "$out/bin/lex"
    '';
    meta = gnuMeta "Fast lexical analyser generator, version 2.6.4" "https://github.com/westes/flex" "BSD-2-Clause";
  };

  bison = gcc11 {
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
      mkdir -p "$out/bin"
      cat > "$out/bin/yacc" <<YACC
      #!$AOS_BASH
      exec "$out/bin/bison" -y "\$@"
      YACC
      chmod +x "$out/bin/yacc"
    '';
    meta = gnuMeta "GNU parser generator, version 3.8.2" "https://www.gnu.org/software/bison/" "GPL-3.0-or-later";
  };

  autoconf = gcc11 {
    pname = "autoconf";
    version = "2.71";
    url = "https://mirrors.kernel.org/gnu/autoconf/autoconf-2.71.tar.xz";
    hash = "048zp73c7gczz1ms5jx8nphgc8xr6xpyb56dbqixcan5a1psh4hm";
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
    meta = gnuMeta "GNU Autoconf, version 2.71" "https://www.gnu.org/software/autoconf/" "GPL-3.0-or-later";
  };

  automake = gcc11 {
    pname = "automake";
    version = "1.16.5";
    url = "https://mirrors.kernel.org/gnu/automake/automake-1.16.5.tar.xz";
    hash = "0pac10hgw6r4kbafdbxg7gpb503fq9a9a31r5hvdh95nd2pcngv0";
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
    meta = gnuMeta "GNU Automake, version 1.16.5" "https://www.gnu.org/software/automake/" "GPL-2.0-or-later";
  };

  gperf = gcc11 {
    pname = "gperf";
    version = "3.1";
    url = "https://mirrors.kernel.org/gnu/gperf/gperf-3.1.tar.gz";
    hash = "1cdivawkjb635zkq5qd512d533b47w16bg1xm4sybpzcy65xn37k";
    buildDeps = [texinfo];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletFlags;
    useCxx = true;
    meta = gnuMeta "GNU perfect hash function generator, version 3.1" "https://www.gnu.org/software/gperf/" "GPL-3.0-or-later";
  };

  python3 = gcc11 {
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

  bash = gcc11 {
    pname = "bash";
    version = "5.1";
    url = "https://mirrors.kernel.org/gnu/bash/bash-5.1.tar.gz";
    hash = "0s7myzmyym3977bg74878g5bkawgw9v9cy74xq7q5s4lavlri524";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
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
    '';
    meta = gnuMeta "GNU Bourne-Again SHell, version 5.1" "https://www.gnu.org/software/bash/" "GPL-3.0-or-later";
  };

  coreutils = gcc11 {
    pname = "coreutils";
    version = "8.32";
    url = "https://mirrors.kernel.org/gnu/coreutils/coreutils-8.32.tar.xz";
    hash = "0zds26w4h65w75x3xpdi32hws3vb3idj5n4pm9zrny4mm6pk36jy";
    buildDeps = autotoolsDeps ++ [perl];
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU core utilities (ls, cat, cp, mv, etc.), version 8.32" "https://www.gnu.org/software/coreutils/" "GPL-3.0-or-later";
  };

  gnumake = gcc11 {
    pname = "gnumake";
    version = "4.3";
    url = "https://mirrors.kernel.org/gnu/make/make-4.3.tar.gz";
    hash = "17z72ib90c3218ic02maxdxy40d3sdxhzbnmxs9myiy25ysxb434";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU Make build automation tool, version 4.3" "https://www.gnu.org/software/make/" "GPL-3.0-or-later";
  };

  sed = gcc11 {
    pname = "sed";
    version = "4.8";
    url = "https://mirrors.kernel.org/gnu/sed/sed-4.8.tar.xz";
    hash = "0r2sc7qf0mybf5x84756lw779q0fiqqxqi94mw6nqslg5ax5gb71";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU stream editor, version 4.8" "https://www.gnu.org/software/sed/" "GPL-3.0-or-later";
  };

  grep = gcc11 {
    pname = "grep";
    version = "3.7";
    url = "https://mirrors.kernel.org/gnu/grep/grep-3.7.tar.xz";
    hash = "18dfjbxp0yi63w9v5vz54gwr44vhnngay20lm51x34bygh6x4m7n";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags =
      tripletNoNls
      ++ ["--disable-perl-regexp"];
    meta = gnuMeta "GNU grep pattern matching utility, version 3.7" "https://www.gnu.org/software/grep/" "GPL-3.0-or-later";
  };

  gawk = gcc11 {
    pname = "gawk";
    version = "5.1.0";
    url = "https://mirrors.kernel.org/gnu/gawk/gawk-5.1.0.tar.xz";
    hash = "0nzwgfhcds1jgijx4181h1nlahzznncd3bq9n4xn6d2lvagqr4qb";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    postInstall = ''
      [ -f "$out/bin/gawk" ] && [ ! -f "$out/bin/awk" ] && ln -sf gawk "$out/bin/awk"
    '';
    meta = gnuMeta "GNU awk pattern scanning and processing language, version 5.1.0" "https://www.gnu.org/software/gawk/" "GPL-3.0-or-later";
  };

  findutils = gcc11 {
    pname = "findutils";
    version = "4.8.0";
    url = "https://mirrors.kernel.org/gnu/findutils/findutils-4.8.0.tar.xz";
    hash = "1506z55lj1qwixpp3mwz7j62hbppcgdr3n440rd0g446a9qjwchl";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU find, xargs, and locate utilities, version 4.8.0" "https://www.gnu.org/software/findutils/" "GPL-3.0-or-later";
  };

  diffutils = gcc11 {
    pname = "diffutils";
    version = "3.7";
    url = "https://mirrors.kernel.org/gnu/diffutils/diffutils-3.7.tar.xz";
    hash = "02zg4lj3r8rp13qvvpa28s3ljqlbvvgpnd1mp6q756xs44hckxw1";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    postUnpack = ''
      sed -i 's/SIGSTKSZ < 16384/8192 < 16384/' lib/c-stack.c 2>/dev/null || true
      if [ -f man/help2man ]; then
        printf '#!%s\nexit 0\n' "$AOS_BASH" > man/help2man
        chmod +x man/help2man
        find . -name '*.1' -exec touch {} + 2>/dev/null || true
      fi
    '';
    meta = gnuMeta "GNU file comparison utilities (diff, cmp, sdiff, diff3), version 3.7" "https://www.gnu.org/software/diffutils/" "GPL-3.0-or-later";
  };

  tar = gcc11 {
    pname = "tar";
    version = "1.34";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.34.tar.xz";
    hash = "0g4ajvyjzazv5lpp2xzcik52yxbp949f80bw3li1zjpjfj0alfp3";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = tripletNoNls;
    meta = gnuMeta "GNU tar archiving utility, version 1.34" "https://www.gnu.org/software/tar/" "GPL-3.0-or-later";
  };

  gzip = gcc11 {
    pname = "gzip";
    version = "1.12";
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.12.tar.xz";
    hash = "005z322837gzb0srn1g1383l7wb21fasgg8mvsrgp3909yhi0r2z";
    buildDeps = autotoolsDeps;
    makeInfo = "${texinfo}/bin/makeinfo";
    configureFlags = [];
    meta = gnuMeta "GNU gzip compression utility, version 1.12" "https://www.gnu.org/software/gzip/" "GPL-3.0-or-later";
  };

  patch = gcc11 {
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
