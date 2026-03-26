# stdenv/toolchains/gcc14/bison.nix — GNU Bison 3.8.2 (RHEL 10)
#
# GNU parser generator built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  m4,
  flex,
  perl,
  texinfo,
  help2man,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/bison/bison-3.8.2.tar.xz";
    sha256 = "0w18vf97c1kddc52ljb2x82rsn9k3mffz3acqybhcjfl2l6apn59";
  };
in
builtins.derivation {
  name = "bison-3.8.2";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true MAKEINFO="${texinfo}/bin/makeinfo"
      export PATH="${texinfo}/bin:${help2man}/bin:${perl}/bin:${m4}/bin:${flex}/bin:${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"
      export M4="${m4}/bin/m4"

      cd "$TMPDIR"
      mkdir bison-3.8.2 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd bison-3.8.2 && ${prev.tar}/bin/tar xf -)
      cd bison-3.8.2
      chmod -R u+w .

      # Fix Perl shebang in examples/extexi
      ${prev.sed}/bin/sed -i '1s|#!/usr/bin/perl|#!${perl}/bin/perl|' examples/extexi 2>/dev/null || true

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
      CFLAGS="-O2 -isystem ${glibc}/include" \
      CPPFLAGS="-isystem ${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static -no-pie" \
      "$TMPDIR/bison-3.8.2/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --disable-nls

      make -j"$NIX_BUILD_CORES" AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true
      make install AUTOCONF=true AUTOHEADER=true ACLOCAL=true AUTOMAKE=true

      # Create yacc wrapper
      cat > "$out/bin/yacc" <<'YACC'
      #!/bin/sh
      exec bison -y "$@"
      YACC
      chmod +x "$out/bin/yacc"

      echo "GNU Bison 3.8.2 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU parser generator 3.8.2";
    homepage = "https://www.gnu.org/software/bison/";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
