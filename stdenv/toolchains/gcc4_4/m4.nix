# stdenv/toolchains/gcc4_4/m4.nix — GNU m4 1.4.13 (RHEL 6)
#
# Built with THIS tier's GCC 4.4.7 + glibc 2.12 from prev.
# First package in the autotools chain — no dependencies beyond a C compiler.
#
{
  prev,
  gcc,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/m4/m4-1.4.13.tar.bz2";
    hash = "1nj3c6fjvl4z73ryags6811w8bj45ij6wfvw9zxccmnp44jl6clb";
  };
in
builtins.derivation {
  name = "m4-1.4.13";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} m4-1.4.13
      cd m4-1.4.13
      chmod -R u+w .

      # Touch all source files to uniform timestamp, then autotools outputs later
      find . -type f \( -name '*.c' -o -name '*.h' -o -name '*.m4' -o -name '*.ac' -o -name '*.am' \) -exec touch -t 200001010000 {} + 2>/dev/null || true
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' -o -name 'config.hin' \) -exec touch -t 200001010001 {} + 2>/dev/null || true

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
      CFLAGS="-O2 -isystem ${prev.glibc}/include" \
      CPPFLAGS="-isystem ${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static -Wl,-u,dl_iterate_phdr -Wl,--allow-multiple-definition" \
      "$TMPDIR/m4-1.4.13/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} \
        --disable-nls

      # Strip Makefile regeneration rules and doc/ dependencies
      find . -name Makefile | while read f; do
        sed -i 's/^Makefile:.*/Makefile:/; s/^config\.status:.*/config.status:/; s/^configure:.*/configure:/' "$f"
      done

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true HELP2MAN=true || true
      test -f src/m4 || { echo "FATAL: m4 not built"; exit 1; }
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true HELP2MAN=true || true
      test -f "$out/bin/m4" || { echo "FATAL: m4 not installed"; exit 1; }

      echo "GNU m4 1.4.13 installed to $out"
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
