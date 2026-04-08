# stdenv/toolchains/gcc4_1/binutils.nix — binutils 2.17 (RHEL 5)
#
# Built with THIS tier's GCC 4.1.2 and the previous tier's glibc.
#
{
  prev,
  gcc,
  m4,
  flex,
  bison,
  texinfo,
  buildPlatform,
  hostPlatform,
}:
let
  inherit (import ../../../lib/derivations.nix { system = builtins.currentSystem; }) fetchTarball;

  src = fetchTarball {
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.17.tar.bz2";
    hash = "054ilydpm1i4clgm2f2ffddwl0047n0cnibyqm60rwa1vizgxw2i";
  };
in
builtins.derivation {
  name = "binutils-2.17";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin:${bison}/bin:${texinfo}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # Create helper directories up front
      mkdir -p "$TMPDIR/static-lib" "$TMPDIR/fakebin"

      # Create static-only lib directory — avoids picking up .so files.
      for f in "${prev.glibc}/lib/"*.a "${prev.glibc}/lib/"*.o; do
        test -f "$f" && ln -sf "$f" "$TMPDIR/static-lib/"
      done

      # GCC wrapper that always passes -static — libtool strips -static
      # from CC args, but the wrapper ensures it's always present.
      printf '#!${prev.bash}/bin/bash\nexec ${gcc}/bin/gcc -static -L'"$TMPDIR"'/static-lib "$@"\n' \
        > "$TMPDIR/fakebin/gcc"
      printf '#!${prev.bash}/bin/bash\nexec ${gcc}/bin/gcc -static -L'"$TMPDIR"'/static-lib "$@"\n' \
        > "$TMPDIR/fakebin/cc"
      chmod +x "$TMPDIR/fakebin/gcc" "$TMPDIR/fakebin/cc"

      export CC="$TMPDIR/fakebin/gcc"
      export CFLAGS="-O2 -I${prev.glibc}/include"
      export LDFLAGS="-L$TMPDIR/static-lib -static"

      cd "$TMPDIR"
      cp -r ${src} binutils-2.17
      cd binutils-2.17
      chmod -R u+w .

      # Touch pre-built .info files and pre-generated parser/lexer .c/.h files
      # so make doesn't try to regenerate them (we don't have makeinfo/flex/bison).
      find . -name '*.info' -print | xargs touch
      find . -name '*.c' -newer . -print | xargs touch 2>/dev/null || true
      # Ensure generated .c files are newer than .l and .y sources
      for f in ld/ldlex.c ld/ldgram.c ld/ldgram.h \
               gas/itbl-parse.c gas/itbl-parse.h gas/itbl-lex.c \
               binutils/arlex.c binutils/arparse.c binutils/arparse.h \
               binutils/deflex.c binutils/defparse.c binutils/defparse.h \
               binutils/rclex.c binutils/rcparse.c binutils/rcparse.h \
               binutils/syslex.c binutils/sysinfo.c binutils/sysinfo.h; do
        test -f "$f" && touch "$f"
      done

      export PATH="$TMPDIR/fakebin:$PATH"

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      MAKEINFO="${texinfo}/bin/makeinfo" \
      "$TMPDIR/binutils-2.17/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-shared --disable-nls \
        --disable-werror \
        --with-sysroot=/ \
        --program-transform-name=

      make -j"$NIX_BUILD_CORES" MAKEINFO="${texinfo}/bin/makeinfo"
      make install MAKEINFO="${texinfo}/bin/makeinfo"

      echo "binutils 2.17 installed to $out"
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
