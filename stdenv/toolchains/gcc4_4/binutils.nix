# stdenv/toolchains/gcc4_4/binutils.nix — binutils 2.20.1 (RHEL 6)
#
# Built with GCC 4.1.2 from the previous tier.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  help2man,
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

  binutils-src = fetchSrc {
    name = "binutils-2.20.1.tar.bz2";
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.20.1.tar.bz2";
    hash = "sha256-cdN8lkUTM8XAuEsXAWn9yxOLuyc5fcBigZBdlxfI7WQ=";
  };
in
builtins.derivation {
  name = "binutils-2.20.1";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.bash}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.diffutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.bzip2}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${autoconf}/bin:${automake}/bin:${texinfo}/bin:${help2man}/bin"

      cd "$TMPDIR"
      tar xjf ${binutils-src}

      SRC="$TMPDIR/binutils-2.20.1"
      cd "$SRC"
      chmod -R u+w .
      find . -name configure -exec chmod +x {} + 2>/dev/null || true
      find . -name '*.sh' -exec chmod +x {} + 2>/dev/null || true
      chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap 2>/dev/null || true
      # Touch all files first, then touch generated .c/.h files to make them
      # appear newer than their .l/.y/.gperf sources (prevents lex/yacc/gperf
      # regeneration)
      find . -type f -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

      # CC wrapper: injects -isystem for glibc headers (so sub-configures like
      # libiberty find headers even without CPPFLAGS) and appends NSS libs at
      # link time (bypassing libtool reordering)
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
        -e "s|REAL_GCC|${prev.gcc}/bin/gcc|g" \
        -e "s|GLIBC_INCLUDE|${prev.glibc}/include|g" \
        -e "s|NSS_FILES|${prev.glibc}/lib/libnss_files.a|g" \
        -e "s|NSS_DNS|${prev.glibc}/lib/libnss_dns.a|g" \
        -e "s|NSS_RESOLV|${prev.glibc}/lib/libresolv.a|g" \
        -e "s|GLIBC_LIB|${prev.glibc}/lib|g" \
        "$TMPDIR/ccwrap/gcc"
      chmod +x "$TMPDIR/ccwrap/gcc"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="$TMPDIR/ccwrap/gcc" \
      CFLAGS="-O2 -isystem ${prev.glibc}/include" \
      CPPFLAGS="-isystem ${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static -Wl,-u,dl_iterate_phdr" \
      "$SRC/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-shared --disable-nls \
        --disable-gdb --disable-gdbserver --disable-libdecnumber --disable-readline --disable-sim \
        --with-sysroot=/ \
        --program-transform-name=

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"

      echo "binutils 2.20.1 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU tools for manipulating binaries, version 2.20.1";
    homepage = "https://www.gnu.org/software/binutils/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
