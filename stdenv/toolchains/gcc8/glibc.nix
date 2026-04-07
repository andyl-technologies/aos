# stdenv/toolchains/gcc8/glibc.nix — glibc 2.28 (RHEL 8)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + linux-headers 4.18.
# glibc requires out-of-tree build.
#
{
  prev,
  gcc,
  binutils,
  linuxHeaders,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/glibc/glibc-2.28.tar.xz";
    hash = "0lyg4znbrzixpbcwp4jkv7kv41dlk597xdizclgkc4fllz2gshzx";
  };
in
builtins.derivation {
  name = "glibc-2.28";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.bison}/bin:${prev.m4}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${prev.flex}/bin:${prev.autoconf}/bin:${prev.automake}/bin:${prev.texinfo}/bin:${prev.help2man}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir glibc-2.28 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd glibc-2.28 && ${prev.tar}/bin/tar xf -)
      cd glibc-2.28
      chmod -R u+w .

      # Patch plural.y: replace bison 2.7+ directive with 2.4 equivalent
      ${prev.sed}/bin/sed -i 's/%define api.pure full/%pure-parser/' intl/plural.y

      # Touch gperf inputs first, then outputs, so make doesn't regenerate
      find . -type f -name '*.gperf' -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f -name '*-kw.h' -exec touch {} + 2>/dev/null || true

      # Out-of-tree build (required by glibc)
      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      AR="${binutils}/bin/ar" \
      RANLIB="${binutils}/bin/ranlib" \
      CFLAGS="-O2 -Wno-error=maybe-uninitialized" \
      "$TMPDIR/glibc-2.28/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} \
        --host=${hostPlatform.config} \
        --with-headers="${linuxHeaders}/include" \
        --disable-profile \
        --disable-nscd \
        --disable-timezone-tools \
        --enable-static-nss \
        --disable-multi-arch \
        --without-gd \
        --without-selinux \
        libc_cv_forced_unwind=yes \
        libc_cv_c_cleanup=yes

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true
      make install  AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO=true

      # Copy linux headers into glibc output for downstream use
      cp -r --no-preserve=mode,ownership "${linuxHeaders}/include/linux" "$out/include/" 2>/dev/null || true
      cp -r --no-preserve=mode,ownership "${linuxHeaders}/include/asm" "$out/include/" 2>/dev/null || true
      cp -r --no-preserve=mode,ownership "${linuxHeaders}/include/asm-generic" "$out/include/" 2>/dev/null || true

      echo "glibc 2.28 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU C Library, version 2.28";
    homepage = "https://www.gnu.org/software/libc/";
    license = "LGPL-2.1-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
