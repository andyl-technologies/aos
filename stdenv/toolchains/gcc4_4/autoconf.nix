# stdenv/toolchains/gcc4_4/autoconf.nix — GNU Autoconf 2.63 (RHEL 6)
#
# Built with THIS tier's GCC 4.4.7 + glibc 2.12 from prev.
# Needs m4 and perl.
#
{
  prev,
  gcc,
  m4,
  perl,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/autoconf/autoconf-2.63.tar.bz2";
    hash = "0dr93pzan0q3fwwwsr81sj7mll9k92q0x4n8y0zr8cr2xj2l70p9";
  };
in
builtins.derivation {
  name = "autoconf-2.63";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${perl}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} autoconf-2.63
      cd autoconf-2.63
      chmod -R u+w .

      # Touch autotools-generated files to prevent regeneration
      find . -type f -exec touch {} + 2>/dev/null || true

      # Autoconf is mostly perl scripts — configure just installs them
      M4="${m4}/bin/m4" \
      PERL="${perl}/bin/perl" \
      ./configure \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config}

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU Autoconf 2.63 installed to $out"
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
