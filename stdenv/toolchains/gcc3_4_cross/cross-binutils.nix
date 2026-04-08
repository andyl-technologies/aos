# stdenv/toolchains/gcc3_4_cross/cross-binutils.nix — Phase 1
#
# Cross binutils 2.15: runs on i686, targets x86_64.
# Produces x86_64-unknown-linux-gnu-{as,ld,ar,...} prefixed tools.
#
{
  prev,
  buildPlatform,
  hostPlatform,
  ...
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.15.tar.bz2";
    hash = "1igaw1vps1j0l8zmm4npazjwj287kwxd1rqbbgy39nsrxg9njp5d";
  };
in
builtins.derivation {
  name = "cross-binutils-2.15";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${prev.gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.patch}/bin:${prev.bash}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # Dummy lex/flex for configure checks
      mkdir -p "$TMPDIR/fakebin"
      printf '#!${prev.bash}/bin/bash\nprintf "int main(){return 0;}\nint yywrap(){return 1;}\n" > lex.yy.c\n' > "$TMPDIR/fakebin/lex"
      printf '#!${prev.bash}/bin/bash\nprintf "int main(){return 0;}\nint yywrap(){return 1;}\n" > lex.yy.c\n' > "$TMPDIR/fakebin/flex"
      chmod +x "$TMPDIR/fakebin/lex" "$TMPDIR/fakebin/flex"
      export PATH="$TMPDIR/fakebin:$PATH"

      # Copy source to writable dir — libiberty/regex.c declares
      # 'char *malloc()' (K&R style) which conflicts with glibc 2.3.4's
      # 'void *malloc(size_t)' from stdlib.h. Remove the K&R declarations.
      cp -r ${src} "$TMPDIR/src"
      chmod -R u+w "$TMPDIR/src"
      sed -i '/^char \*malloc ();$/d' "$TMPDIR/src/libiberty/regex.c"
      sed -i '/^char \*realloc ();$/d' "$TMPDIR/src/libiberty/regex.c"

      # Touch pre-generated parser/lexer .c/.h files so make doesn't try to
      # regenerate them via bison/yacc/flex (which aren't available at this
      # bootstrap stage).  The cp -r above resets timestamps, making .y/.l
      # sources appear newer than their generated outputs.
      find "$TMPDIR/src" -name '*.info' -print | xargs touch
      for f in ld/ldlex.c ld/ldgram.c ld/ldgram.h \
               gas/itbl-parse.c gas/itbl-parse.h gas/itbl-lex.c \
               binutils/arlex.c binutils/arparse.c binutils/arparse.h \
               binutils/deflex.c binutils/defparse.c binutils/defparse.h \
               binutils/rclex.c binutils/rcparse.c binutils/rcparse.h \
               binutils/syslex.c binutils/sysinfo.c binutils/sysinfo.h; do
        test -f "$TMPDIR/src/$f" && touch "$TMPDIR/src/$f"
      done

      # Create a static-only lib directory — glibc 2.3.4 has .so files
      # which libtool will try to link dynamically even with -static.
      mkdir -p "$TMPDIR/static-lib"
      for f in "${prev.glibc}/lib/"*.a "${prev.glibc}/lib/"*.o; do
        test -f "$f" && ln -sf "$f" "$TMPDIR/static-lib/"
      done

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      # Wrapper gcc that always links statically against our glibc.
      # Needed because libtool and bfd/doc sub-Makefiles drop LDFLAGS.
      mkdir -p "$TMPDIR/cc-wrapper"
      printf '%s\n' '#!${prev.bash}/bin/bash' \
        "exec ${prev.gcc}/bin/gcc -L$TMPDIR/static-lib -static \"\$@\"" \
        > "$TMPDIR/cc-wrapper/gcc"
      chmod +x "$TMPDIR/cc-wrapper/gcc"
      ln -sf "$TMPDIR/cc-wrapper/gcc" "$TMPDIR/cc-wrapper/cc"

      CC="$TMPDIR/cc-wrapper/gcc" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L$TMPDIR/static-lib -static" \
      "$TMPDIR/src/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} \
        --host=${buildPlatform.config} \
        --target=${hostPlatform.config} \
        --disable-shared --disable-nls \
        --disable-gdb --disable-gdbserver --disable-libdecnumber --disable-readline --disable-sim \
        --with-sysroot=/

      make -j"$NIX_BUILD_CORES"
      make install

      echo "Cross binutils 2.15 (${buildPlatform.config} → ${hostPlatform.config}) installed to $out"
    ''
  ];
}
