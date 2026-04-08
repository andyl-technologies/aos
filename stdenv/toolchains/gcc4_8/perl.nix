# stdenv/toolchains/gcc4_8/perl.nix — Perl 5.16.3 (RHEL 7)
#
# Built with THIS tier's GCC 4.8.5 + glibc 2.17.
# Perl uses its own Configure script (not autoconf).
# Minimal build — just enough to run autoconf, automake, texinfo.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://www.cpan.org/src/5.0/perl-5.16.3.tar.bz2";
    hash = "sha256-xv8frhbCXKsvmg5eilzs0UO+grSmVm4ujjpRA5v9GvY=";
  };
in
builtins.derivation {
  name = "perl-5.16.3";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} perl-5.16.3
      cd perl-5.16.3
      chmod -R u+w .

      # Perl's Configure is its own beast — not autoconf-based.
      # Use -des for non-interactive, -Dcc for compiler, etc.
      ./Configure \
        -des \
        -Dprefix="$out" \
        -Dcc="${gcc}/bin/gcc" \
        -Dar="${binutils}/bin/ar" \
        -Dnm="${binutils}/bin/nm" \
        -Dranlib="${binutils}/bin/ranlib" \
        -Dsh="${prev.bash}/bin/bash" \
        -Dlocincpth="${glibc}/include" \
        -Dloclibpth="${glibc}/lib" \
        -Dglibpth="${glibc}/lib" \
        -Dusrinc="${glibc}/include" \
        -Dccflags="-O2 -isystem ${glibc}/include" \
        -Dcppflags="-isystem ${glibc}/include" \
        -Dldflags="-L${glibc}/lib -static" \
        -Dlddlflags="-shared -L${glibc}/lib" \
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

      # Patch Cwd.pm: miniperl can't load XS, so cwd() uses pure Perl fallback.
      # The fallback looks for /bin/pwd which doesn't exist in Nix sandbox,
      # falls through to _perl_getcwd -> abs_path('.') -> infinite loop.
      # Fix: inject our coreutils pwd path so _backtick_pwd is used instead.
      # In perl 5.16.3, the canonical source is dist/Cwd/Cwd.pm;
      # lib/Cwd.pm is only created during make.
      ${prev.sed}/bin/sed -i "s|'/bin/pwd'|'${prev.coreutils}/bin/pwd', '/bin/pwd'|" dist/Cwd/Cwd.pm
      ${prev.sed}/bin/sed -i "s|'/bin/pwd'|'${prev.coreutils}/bin/pwd', '/bin/pwd'|" lib/Cwd.pm 2>/dev/null || true

      # Errno_pm.PL on Linux hardcodes /usr/include/errno.h which doesn't
      # exist in Nix sandbox. Patch to use glibc's errno.h instead.
      ${prev.sed}/bin/sed -i \
        -e "s|/usr/include/errno.h|${glibc}/include/errno.h|g" \
        -e "s|/usr/local/include/errno.h|${glibc}/include/errno.h|g" \
        ext/Errno/Errno_pm.PL

      # IO-Compress is pure Perl but Configure adds it to static_ext.
      # Create empty archive so the linker doesn't fail on missing .a.
      mkdir -p lib/auto/IO/Compress
      ${binutils}/bin/ar cr lib/auto/IO/Compress/Compress.a

      # Build with -j1 to avoid CWD race conditions in ext/ builds
      make -j1
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "Perl 5.16.3 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "Practical Extraction and Report Language, version 5.16.3";
    homepage = "https://www.perl.org/";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
