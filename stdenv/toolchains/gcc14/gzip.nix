# stdenv/toolchains/gcc14/gzip.nix — GNU gzip 1.13 (RHEL 10)
#
# Production GNU gzip built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
#
{
  prev,
  bash,
  grep,
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
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gzip/gzip-1.13.tar.xz";
    sha256 = "093w3a12220gzy00qi9zy52mhjlgyyh7kiimsz5xa00fgf81rbp9";
  };
in
  builtins.derivation {
    name = "gzip-1.13";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${autoconf}/bin:${automake}/bin:${texinfo}/bin:${help2man}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        mkdir gzip-1.13 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd gzip-1.13 && ${prev.tar}/bin/tar xf -)
        cd gzip-1.13
        chmod -R u+w .

        # Break all hardlinks in doc/ (version.texi/stamp-vti, versionmaint.texi/stamp-1, etc.)
        find doc -type f -links +1 -exec sh -c 'cp "$1" "$1.tmp" && mv "$1.tmp" "$1"' _ {} \; 2>/dev/null || true

        # Touch autotools inputs first, then generated .c/.h, then autotools outputs
        find . -type f \( -name '*.y' -o -name '*.l' -o -name 'Makefile.am' -o -name 'configure.ac' -o -name 'configure.in' -o -name 'acinclude.m4' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true
        find . -name '*.info' -exec touch -t 200001010200.00 {} + 2>/dev/null || true
        find . -name '*.1' -exec touch {} + 2>/dev/null || true

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        export LIBRARY_PATH="${glibc}/lib"
        CC="${gcc}/bin/gcc" \
        CFLAGS="-O2 -isystem ${glibc.dev}/include" \
        CPPFLAGS="-isystem ${glibc.dev}/include" \
        LDFLAGS="-L${glibc.static}/lib -L${glibc}/lib -static -no-pie" \
        "$TMPDIR/gzip-1.13/configure" \
          --prefix="$out"

        make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
        make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

        # gzip ships 12 wrapper scripts (gunzip, gzexe, uncompress,
        # zcat, zcmp, zdiff, zegrep, zfgrep, zforce, zgrep, zmore,
        # znew) whose shebangs are substituted from CONFIG_SHELL (=
        # prev.bash-5.1); zgrep also embeds a default grep path from
        # PATH (= prev.grep-3.7); gzexe additionally bakes the bash
        # path into comments AND into a second shebang inside its
        # self-extracting-archive template (line ~148). Any of these
        # references pins the entire mes/tcc/cross-* bootstrap chain
        # (~700 MiB) into the runtime closure of any consumer. Rewrite
        # every occurrence (not just the shebang) to same-tier paths.
        # Defensive fix: gzip isn't in the runtime closure today but
        # was briefly during the build-leaks audit.
        for f in "$out/bin/"*; do
          [ -f "$f" ] || continue
          # Only rewrite scripts (skip ELF binaries / symlinks).
          if [ "$(head -c 2 "$f" 2>/dev/null)" = "#!" ]; then
            ${prev.sed}/bin/sed -i \
              "s|/nix/store/[a-z0-9]\\{32\\}-bash-[^/]*/bin/bash|${bash}/bin/bash|g" \
              "$f"
          fi
        done
        if [ -f "$out/bin/zgrep" ]; then
          ${prev.sed}/bin/sed -i \
            "s|/nix/store/[a-z0-9]\\{32\\}-grep-[^/]*/bin/grep|${grep}/bin/grep|g" \
            "$out/bin/zgrep"
        fi

        echo "GNU gzip 1.13 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU gzip 1.13 compression utility";
      homepage = "https://www.gnu.org/software/gzip/";
      license = "GPL-3.0-or-later";
      build = {
        os = "linux";
      };
      execute = {
        os = "linux";
      };
    };
  }
