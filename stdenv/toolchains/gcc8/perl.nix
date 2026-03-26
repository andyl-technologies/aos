# stdenv/toolchains/gcc8/perl.nix — Perl 5.26.3 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
# Perl uses its own Configure script (not autoconf).
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
  src = builtins.fetchTarball {
    url = "https://www.cpan.org/src/5.0/perl-5.26.3.tar.xz";
    sha256 = "sha256-dlX8a0Hmw4GPvxGerkHE5IgRhh1u9nRMwXgVHZHP9q4=";
  };
in
builtins.derivation {
  name = "perl-5.26.3";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir perl-5.26.3 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd perl-5.26.3 && ${prev.tar}/bin/tar xf -)
      cd perl-5.26.3
      chmod -R u+w .

      export LIBRARY_PATH="${glibc}/lib"
      GCC_INCDIR="${gcc}/lib/gcc/${hostPlatform.config}/8.5.0/include"

      # Patch Cwd.pm to work in sandbox:
      # 1. _backtick_pwd() localizes PATH to undef for taint safety, then runs
      #    $pwd_cmd. In Nix sandbox /bin/pwd doesn't exist, so $pwd_cmd falls
      #    back to bare 'pwd' which can't be found without PATH. Fix: add
      #    coreutils pwd to the search list.
      # 2. getcwd() fallback for when POSIX::getcwd is unavailable (miniperl).
      ${prev.sed}/bin/sed -i "s|'/bin/pwd'|'${prev.coreutils}/bin/pwd', '/bin/pwd'|" dist/PathTools/Cwd.pm
      ${prev.sed}/bin/sed -i 's/getcwd()/getcwd() || "."/' dist/PathTools/Cwd.pm 2>/dev/null || true

      # Errno_pm.PL on Linux hardcodes /usr/include/errno.h which doesn't
      # exist in Nix sandbox. Patch to use glibc's errno.h instead.
      ${prev.sed}/bin/sed -i \
        -e "s|/usr/include/errno.h|${glibc}/include/errno.h|g" \
        -e "s|/usr/local/include/errno.h|${glibc}/include/errno.h|g" \
        ext/Errno/Errno_pm.PL

      ./Configure -des \
        -Dprefix="$out" \
        -Dcc="${gcc}/bin/gcc" \
        -Dccflags="-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
        -Dldflags="-L${glibc}/lib -static" \
        -Dloclibpth="${glibc}/lib" \
        -Dlocincpth="${glibc}/include" \
        -Dlibs="-lm -lpthread -ldl -lcrypt" \
        -Ddefault_inc_excludes_dot=n \
        -Dusethreads=n \
        -Dusedl=n \
        -Uusedl \
        -Ui_xlocale

      make -j1
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "Perl 5.26.3 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "Practical Extraction and Report Language, version 5.26.3";
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
