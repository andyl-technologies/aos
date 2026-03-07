# stdenv/toolchains/gcc4_1/autoconf.nix — GNU Autoconf 2.63 (autotools bootstrap)
#
# Built with THIS tier's GCC 4.1.2 + binutils 2.17 + glibc 2.5.
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
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/autoconf/autoconf-2.63.tar.bz2";
    sha256 = "0dr93pzan0q3fwwwsr81sj7mll9k92q0x4n8y0zr8cr2xj2l70p9";
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

      # Prevent make from re-running autotools (we use pre-generated files)
      make -j"$NIX_BUILD_CORES" \
        ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true
      make install \
        ACLOCAL=true AUTOCONF=true AUTOMAKE=true AUTOHEADER=true

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
