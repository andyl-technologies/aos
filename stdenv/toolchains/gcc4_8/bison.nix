# stdenv/toolchains/gcc4_8/bison.nix — GNU Bison 3.0.4 (RHEL 7)
#
# Built with THIS tier's GCC 4.8.5 + glibc 2.17.
# Needs m4 at runtime. Ships pre-generated parsers.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  flex,
  perl,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/bison/bison-3.0.4.tar.xz";
    hash = "1pxj97dfh3iabxcc4g60y739zkd788kf4cv64zb515676lckmj9y";
  };
in
builtins.derivation {
  name = "bison-3.0.4";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${perl}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # Bison needs m4 at runtime
      export M4="${m4}/bin/m4"

      cd "$TMPDIR"
      cp -r ${src} bison-3.0.4
      cd bison-3.0.4
      chmod -R u+w .

      # Touch .y/.l sources first, then pre-generated .c/.h, then autotools files
      find . -type f \( -name '*.y' -o -name '*.l' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/bison-3.0.4/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} \
        --disable-nls

      # Fix gnulib 'gets' issue (glibc removed gets() declaration)
      ${prev.sed}/bin/sed -i '/gets is a security hole/d' lib/stdio.in.h 2>/dev/null || true

      make -j"$NIX_BUILD_CORES" MAKEINFO=true
      make install MAKEINFO=true

      # Create yacc compatibility wrapper
      printf '#!/bin/sh\nexec %s/bin/bison -y "$@"\n' "$out" > "$out/bin/yacc"
      chmod +x "$out/bin/yacc"

      echo "GNU Bison 3.0.4 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU parser generator, version 3.0.4";
    homepage = "https://www.gnu.org/software/bison/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
