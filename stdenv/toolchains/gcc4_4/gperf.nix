# stdenv/toolchains/gcc4_4/gperf.nix — GNU gperf 3.0.4 (autotools bootstrap)
#
# Built with THIS tier's GCC 4.4.7 (first tier with C++).
# gperf is a perfect hash function generator used by glibc and other packages.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gperf/gperf-3.0.4.tar.gz";
    hash = "12pqgvxmyckqv1b5qhi80qmwkvpvr604w7qckbn1dfkykl96rdgb";
  };
in
builtins.derivation {
  name = "gperf-3.0.4";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} gperf-3.0.4
      cd gperf-3.0.4
      chmod -R u+w .

      # Touch autotools-generated files to prevent regeneration
      find . -type f -exec touch {} + 2>/dev/null || true

      # CC/CXX wrappers: append NSS libs at link time for static glibc 2.5
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
      cp "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"
      ${prev.sed}/bin/sed -i \
        -e "s|REAL_GCC|${gcc}/bin/gcc|g" \
        -e "s|NSS_FILES|${prev.glibc}/lib/libnss_files.a|g" \
        -e "s|NSS_DNS|${prev.glibc}/lib/libnss_dns.a|g" \
        -e "s|NSS_RESOLV|${prev.glibc}/lib/libresolv.a|g" \
        -e "s|GLIBC_INCLUDE|${prev.glibc}/include|g" \
        -e "s|GLIBC_LIB|${prev.glibc}/lib|g" \
        "$TMPDIR/ccwrap/gcc"
      ${prev.sed}/bin/sed -i \
        -e "s|REAL_GCC|${gcc}/bin/g++|g" \
        -e "s|NSS_FILES|${prev.glibc}/lib/libnss_files.a|g" \
        -e "s|NSS_DNS|${prev.glibc}/lib/libnss_dns.a|g" \
        -e "s|NSS_RESOLV|${prev.glibc}/lib/libresolv.a|g" \
        -e "s|GLIBC_INCLUDE|${prev.glibc}/include|g" \
        -e "s|GLIBC_LIB|${prev.glibc}/lib|g" \
        "$TMPDIR/ccwrap/g++"
      chmod +x "$TMPDIR/ccwrap/gcc" "$TMPDIR/ccwrap/g++"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="$TMPDIR/ccwrap/gcc" \
      CXX="$TMPDIR/ccwrap/g++" \
      CFLAGS="-O2 -isystem ${prev.glibc}/include" \
      CXXFLAGS="-O2 -isystem ${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static -Wl,-u,dl_iterate_phdr" \
      "$TMPDIR/gperf-3.0.4/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config}

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      echo "GNU gperf 3.0.4 installed to $out"
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
