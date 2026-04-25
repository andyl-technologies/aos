# stdenv/toolchains/gcc4_1/flex.nix — flex 2.5.35 (autotools bootstrap)
#
# Built with THIS tier's GCC 4.1.2 + binutils 2.17 + glibc 2.5.
# Self-bootstrapping: ships pre-generated scan.c so no existing flex needed.
# Installs a `lex` symlink for compatibility.
#
{
  prev,
  gcc,
  m4,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://src.fedoraproject.org/lookaside/pkgs/flex/flex-2.5.35.tar.bz2/10714e50cea54dc7a227e3eddcd44d57/flex-2.5.35.tar.bz2";
    sha256 = "0nkghq13zhxjcggfb9na8qa0fdv1fdhqwhv4lnskg34lfv8501s9";
  };
in
  builtins.derivation {
    name = "flex-2.5.35";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        cp -r ${src} flex-2.5.35
        cd flex-2.5.35
        chmod -R u+w .

        # Touch source files first, then generated outputs
        find . -type f \( -name '*.l' -o -name '*.y' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
        sleep 1
        find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

        CC="${gcc}/bin/gcc -static" \
        CFLAGS="-O2 -I${prev.glibc}/include" \
        LDFLAGS="-L${prev.glibc}/lib -static -Wl,--whole-archive ${prev.glibc}/lib/libnss_files.a ${prev.glibc}/lib/libnss_dns.a ${prev.glibc}/lib/libresolv.a -Wl,--no-whole-archive -Wl,--defsym=__res_iclose=0 -Wl,-u,dl_iterate_phdr" \
        ./configure \
          --prefix="$out" \
          --build=${hostPlatform.config} --host=${hostPlatform.config} \
          --disable-nls

        # The Makefile's scan.c rule runs: $(FLEX) -o.c scan.l; sed ... .c > scan.c
        # Without flex, the .c intermediate is never created and sed fails.
        # Provide .c as a copy of the pre-generated scan.c so the rule succeeds.
        cp scan.c .c

        # Touch pre-generated parser outputs so make doesn't try to regenerate
        # them from parse.y (which requires yacc/bison, not available yet).
        touch parse.c parse.h

        make -j"$NIX_BUILD_CORES"
        make install

        # Create lex compatibility symlink
        [ ! -f "$out/bin/lex" ] && ln -sf flex "$out/bin/lex"

        echo "flex 2.5.35 installed to $out"
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
