# stdenv/toolchains/gcc4_8/automake.nix — GNU Automake 1.13.4 (RHEL 7)
#
# Built with THIS tier's GCC 4.8.5 + glibc 2.17.
# Needs autoconf and perl.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  perl,
  autoconf,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/automake/automake-1.13.4.tar.xz";
    sha256 = "sha256-cHpdXUTmAeF89dLm8Rx9gPPSQoSOr7mBKKM76uoXuS4=";
  };
in
builtins.derivation {
  name = "automake-1.13.4";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${m4}/bin:${perl}/bin:${autoconf}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir -p automake-1.13.4 && (cd ${src} && tar cf - .) | (cd automake-1.13.4 && tar xf -)
      cd automake-1.13.4
      chmod -R u+w .

      # Touch autotools-generated files to prevent regeneration
      find . -type f -exec touch {} + 2>/dev/null || true

      PERL="${perl}/bin/perl" \
      ./configure \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config}

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU Automake 1.13.4 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Automake, version 1.13.4";
    homepage = "https://www.gnu.org/software/automake/";
    license = "GPL-2.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
