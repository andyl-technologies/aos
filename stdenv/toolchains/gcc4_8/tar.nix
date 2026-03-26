# stdenv/toolchains/gcc4_8/tar.nix — GNU tar 1.26 (RHEL 7)
#
# Built with GCC 4.8.5 + glibc 2.17 from this tier.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  fetchSrc =
    {
      name,
      url,
      hash,
    }:
    builtins.derivation {
      inherit name;
      system = buildPlatform.system;
      builder = "builtin:fetchurl";
      inherit url;
      outputHash = hash;
      outputHashMode = "flat";
      outputHashAlgo = "sha256";
      preferLocalBuild = true;
    };

  tar-src = fetchSrc {
    name = "tar-1.26.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/tar/tar-1.26.tar.bz2";
    hash = "sha256-WlNp9GRQKlmOk4ApwxDUs6vVHmu439BFZj5hyOqfbUE=";
  };
in
builtins.derivation {
  name = "tar-1.26";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${autoconf}/bin:${automake}/bin:${texinfo}/bin:${help2man}/bin"

      cd "$TMPDIR"
      tar xjf ${tar-src}

      SRC="$TMPDIR/tar-1.26"
      cd "$SRC"
      chmod -R u+w .
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x install-sh missing mkinstalldirs build-aux/install-sh 2>/dev/null || true
      # Use fixed timestamps to prevent regeneration
      find . -type f -exec touch -t 200001010000.00 {} + 2>/dev/null || true
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch -t 200001010030.00 {} + 2>/dev/null || true
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch -t 200001010100.00 {} + 2>/dev/null || true
      # Touch pre-generated man page so make doesn't try to rebuild it
      find . \( -name '*.1' -o -name '*.info' \) -exec touch -t 200001010200.00 {} + 2>/dev/null || true

      # Fix gnulib gets() warning — glibc 2.17 removed gets() declaration
      ${prev.sed}/bin/sed -i '/_GL_WARN_ON_USE (gets,/d' gnu/stdio.in.h 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$SRC/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU tar 1.26 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU tar archiving utility, version 1.26";
    homepage = "https://www.gnu.org/software/tar/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
