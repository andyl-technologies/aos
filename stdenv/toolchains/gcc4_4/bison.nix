# stdenv/toolchains/gcc4_4/bison.nix — GNU Bison 3.0.4 (upgrade from 2.4.3)
#
# Built with THIS tier's GCC 4.4.7 + binutils 2.20.1 + glibc 2.12.
# Upgrades from bison 2.4.3 (gcc4_1) to satisfy glibc 2.28's bison >= 2.7
# requirement in the gcc8 tier. Ships pre-generated parsers.
#
{
  prev,
  gcc,
  m4,
  flex,
  autoconf,
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
      export PATH="${texinfo}/bin:${help2man}/bin:${autoconf}/bin:${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${prev.perl}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # Bison needs m4 at runtime
      export M4="${m4}/bin/m4"

      cd "$TMPDIR"

      # Need xz to extract .tar.xz — use prev.xz if available, otherwise fall back
      if [ -x "${prev.gzip}/bin/xz" ] 2>/dev/null; then
        XZ="${prev.gzip}/bin/xz"
      else
        # Extract using the xz from prev tier (gcc4_4 doesn't have xz in prev)
        # The source is fetched by Nix, so it's already extracted
        true
      fi

      cp -r ${src} bison-3.0.4
      cd bison-3.0.4
      chmod -R u+w .

      # Touch .y/.l sources first, then pre-generated .c/.h, then autotools files
      find . -type f \( -name '*.y' -o -name '*.l' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

      # CC wrapper: appends NSS libs at link time for static glibc 2.5
      mkdir -p "$TMPDIR/ccwrap"
      cp ${builtins.toFile "cc-wrapper" ''
#!/bin/sh
compile=
for arg; do case "$arg" in -c|-E|-S) compile=1 ;; esac; done
if [ -z "$compile" ]; then
  exec REAL_GCC -isystem GLIBC_INCLUDE "$@" -L GLIBC_LIB -static -Wl,--start-group -Wl,--whole-archive NSS_FILES NSS_DNS NSS_RESOLV -Wl,--no-whole-archive -lc -Wl,--end-group
fi
exec REAL_GCC -isystem GLIBC_INCLUDE "$@"
''} "$TMPDIR/ccwrap/gcc"
      ${prev.sed}/bin/sed -i \
        -e "s|#!/bin/sh|#!${prev.bash}/bin/bash|" \
        -e "s|REAL_GCC|${gcc}/bin/gcc|g" \
        -e "s|NSS_FILES|${prev.glibc}/lib/libnss_files.a|g" \
        -e "s|NSS_DNS|${prev.glibc}/lib/libnss_dns.a|g" \
        -e "s|NSS_RESOLV|${prev.glibc}/lib/libresolv.a|g" \
        -e "s|GLIBC_INCLUDE|${prev.glibc}/include|g" \
        -e "s|GLIBC_LIB|${prev.glibc}/lib|g" \
        "$TMPDIR/ccwrap/gcc"
      chmod +x "$TMPDIR/ccwrap/gcc"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="$TMPDIR/ccwrap/gcc" \
      CFLAGS="-O2 -fgnu89-inline -isystem ${prev.glibc}/include" \
      CPPFLAGS="-isystem ${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static -Wl,-u,dl_iterate_phdr" \
      "$TMPDIR/bison-3.0.4/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} \
        --disable-nls

      # Fix gnulib 'gets' issue (glibc removed gets() declaration)
      ${prev.sed}/bin/sed -i '/gets is a security hole/d' lib/stdio.in.h 2>/dev/null || true

      # Touch generated files to prevent regeneration during build/install
      touch "$TMPDIR/bison-3.0.4/lib/config.in.h" "$TMPDIR/bison-3.0.4/aclocal.m4" 2>/dev/null || true

      make -j"$NIX_BUILD_CORES" \
        MAKEINFO=true AUTOHEADER=true AUTOCONF=true ACLOCAL=true AUTOMAKE=true
      make install \
        MAKEINFO=true AUTOHEADER=true AUTOCONF=true ACLOCAL=true AUTOMAKE=true

      # Create yacc compatibility wrapper
      printf '#!${prev.bash}/bin/bash\nexec %s/bin/bison -y "$@"\n' "$out" > "$out/bin/yacc"
      chmod +x "$out/bin/yacc"

      echo "GNU Bison 3.0.4 installed to $out"
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
