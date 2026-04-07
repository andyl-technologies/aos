# stdenv/toolchains/gcc4_4/automake.nix — GNU Automake 1.11.1 (RHEL 6)
#
# Built with THIS tier's GCC 4.4.7 + glibc 2.12 from prev.
# Needs autoconf and perl.
#
{
  prev,
  gcc,
  m4,
  perl,
  autoconf,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/automake/automake-1.11.1.tar.bz2";
    hash = "0c5z2j7fxchqclm97gmgayl1m6vr73cw2ij1rn95jggp6rb1wrmh";
  };
in
builtins.derivation {
  name = "automake-1.11.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${perl}/bin:${autoconf}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} automake-1.11.1
      cd automake-1.11.1
      chmod -R u+w .

      # Touch autotools-generated files to prevent regeneration
      find . -type f -exec touch {} + 2>/dev/null || true

      PERL="${perl}/bin/perl" \
      ./configure \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config}

      # Prevent make from regenerating aclocal.m4 (needs not-yet-built aclocal)
      touch aclocal.m4 Makefile

      make -j"$NIX_BUILD_CORES" \
        ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true
      make install \
        ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true

      echo "GNU Automake 1.11.1 installed to $out"
    ''
  ];
}
// {
  meta = {
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
}
