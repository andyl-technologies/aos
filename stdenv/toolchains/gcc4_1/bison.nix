# stdenv/toolchains/gcc4_1/bison.nix — GNU Bison 2.4.3 (autotools bootstrap)
#
# Built with THIS tier's GCC 4.1.2 + binutils 2.17 + glibc 2.5.
# Ships pre-generated parsers so no existing bison needed.
# Needs m4 at runtime. Installs a `yacc` compatibility wrapper.
#
{
  prev,
  gcc,
  m4,
  flex,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/bison/bison-2.4.3.tar.gz";
    sha256 = "0754bvjsakji89lpvc4yhilgfpqdldz2gbcazqqhmr1ygvgz3m1m";
  };
in
builtins.derivation {
  name = "bison-2.4.3";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${texinfo}/bin:${help2man}/bin:${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin:${m4}/bin:${flex}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      # Bison needs m4 at runtime
      export M4="${m4}/bin/m4"

      cd "$TMPDIR"
      cp -r ${src} bison-2.4.3
      cd bison-2.4.3
      chmod -R u+w .

      # Touch .y/.l sources first, then pre-generated .c/.h, then autotools files
      find . -type f \( -name '*.y' -o -name '*.l' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} + 2>/dev/null || true
      sleep 1
      find . \( -name 'configure' -o -name 'Makefile.in' -o -name 'aclocal.m4' -o -name 'config.h.in' \) -exec touch {} + 2>/dev/null || true

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc -static" \
      CFLAGS="-O2 -I${prev.glibc}/include" \
      LDFLAGS="-L${prev.glibc}/lib -static -Wl,--whole-archive ${prev.glibc}/lib/libnss_files.a ${prev.glibc}/lib/libnss_dns.a ${prev.glibc}/lib/libresolv.a -Wl,--no-whole-archive -Wl,--defsym=__res_iclose=0 -Wl,-u,dl_iterate_phdr" \
      "$TMPDIR/bison-2.4.3/configure" \
        --prefix="$out" \
        --build=${hostPlatform.config} --host=${hostPlatform.config} \
        --disable-nls

      # Fix gnulib 'gets' issue (glibc removed gets() declaration)
      ${prev.sed}/bin/sed -i '/gets is a security hole/d' lib/stdio.in.h 2>/dev/null || true

      make -j"$NIX_BUILD_CORES" MAKEINFO=true
      make install MAKEINFO=true

      # Create yacc compatibility wrapper
      printf '#!/bin/sh\nexec %s/bin/bison -y "$@"\n' "$out" > "$out/bin/yacc"
      chmod +x "$out/bin/yacc"

      echo "GNU Bison 2.4.3 installed to $out"
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
