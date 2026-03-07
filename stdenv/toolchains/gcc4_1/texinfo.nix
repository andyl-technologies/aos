# stdenv/toolchains/gcc4_1/texinfo.nix — GNU Texinfo 4.13a (autotools bootstrap)
#
# Built with THIS tier's GCC 4.1.2 + binutils 2.17 + glibc 2.5.
# Provides `makeinfo`. Needs perl.
#
{
  prev,
  gcc,
  perl,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/texinfo/texinfo-4.13a.tar.gz";
    sha256 = "012rj0sa6f1jj8namymb68bznq420zfavixm6g9k36jbjb718v78";
  };
in
builtins.derivation {
  name = "texinfo-4.13";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${perl}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} texinfo-4.13
      cd texinfo-4.13
      chmod -R u+w .

      # Touch autotools-generated files to prevent regeneration
      find . -type f -exec touch {} + 2>/dev/null || true

      # The info reader needs termcap — provide minimal stubs
      cat > "$TMPDIR/termcap_stub.c" << 'TCEOF'
char *tgetstr(const char *id, char **area) { return (char *)0; }
int tgetent(char *bp, const char *name) { return 1; }
int tgetnum(const char *id) { return 80; }
int tgetflag(const char *id) { return 0; }
char *tgoto(const char *cm, int destcol, int destline) { return ""; }
int tputs(const char *str, int affcnt, int (*putc_fn)(int)) { return 0; }
TCEOF
      ${gcc}/bin/gcc -static -O2 -I${prev.glibc}/include -c "$TMPDIR/termcap_stub.c" -o "$TMPDIR/termcap_stub.o"
      ${prev.binutils}/bin/ar rcs "$TMPDIR/libtermcap.a" "$TMPDIR/termcap_stub.o"

      CC="${gcc}/bin/gcc -static" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -L$TMPDIR -static -Wl,--whole-archive ${prev.glibc}/lib/libnss_files.a ${prev.glibc}/lib/libnss_dns.a ${prev.glibc}/lib/libresolv.a -Wl,--no-whole-archive -Wl,--defsym=__res_iclose=0 -Wl,-u,dl_iterate_phdr" \
      LIBS="-ltermcap" \
      PERL="${perl}/bin/perl" \
      ./configure \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES"
      make install

      echo "GNU Texinfo 4.13 installed to $out"
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
