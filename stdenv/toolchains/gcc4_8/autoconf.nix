# stdenv/toolchains/gcc4_8/autoconf.nix — GNU Autoconf 2.69 (RHEL 7)
#
# Built with THIS tier's GCC 4.8.5 + glibc 2.17.
# Autoconf is mostly perl scripts — configure just installs them.
# Needs m4 and perl.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  perl,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/autoconf/autoconf-2.69.tar.xz";
    sha256 = "sha256-tpVLeuvm1/He9UvOAGzup4fc7YTQYp1xWTowDs1rR4I=";
  };
in
builtins.derivation {
  name = "autoconf-2.69";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${m4}/bin:${perl}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir -p autoconf-2.69 && (cd ${src} && tar cf - .) | (cd autoconf-2.69 && tar xf -)
      cd autoconf-2.69
      chmod -R u+w .

      # Touch autotools-generated files to prevent regeneration
      find . -type f -exec touch {} + 2>/dev/null || true

      M4="${m4}/bin/m4" \
      PERL="${perl}/bin/perl" \
      ./configure \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config}

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU Autoconf 2.69 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Autoconf, version 2.69";
    homepage = "https://www.gnu.org/software/autoconf/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
