# stdenv/bootstrap/stage7-gcc.nix — GCC 2.95.3 self-hosted (glibc)
#
# Recompiles GCC 2.95.3 using itself (stage 6's gcc-tcc) but now
# linking against real glibc 2.2.5 instead of Mes libc. The output is
# a "clean" GCC whose binaries and wrapper embed glibc paths, making
# it the first compiler in the chain that produces dynamically-linked
# ELF executables (or static ones against glibc).
#
# Builder: bash 2.05b (stage 4).
#
# Build approach: ./configure && make && make install (standard GCC build).
# cc1 path: lib/gcc-lib/target/2.95.3/ (2.95.x convention).
#
{
  gcc, # Output of stage6-gcc-tcc.nix (GCC compiled by TCC, Mes libc)
  binutils, # Output of stage6-binutils-tcc.nix
  glibc, # Output of stage7-glibc.nix
  linuxHeaders, # Output of stage5-linux-headers.nix
  posix-tools, # Output of stage1-posix-tools.nix
  bash, # Output of stage4-bash.nix
  gnumake, # Output of stage5-gnumake-tcc.nix
  sed, # Output of stage5-sed-tcc.nix
  grep, # Output of stage5-grep-tcc.nix
  buildPlatform,
  ...
}:
let
  system = buildPlatform.system;

  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-2.95.3/gcc-core-2.95.3.tar.gz";
    sha256 = "sha256-GTd54N/wNHJMk9wQoDSAr6m9mzF23/mqSNSHNELDWfk=";
  };

  target = "i686-linux-gnu";

  # GCC wrapper script template — placeholders replaced at build time.
  # This wrapper embeds glibc include/lib paths and the dynamic linker
  # so that programs compiled by this GCC link against glibc by default.
  gcc-wrapper = builtins.toFile "gcc-wrapper" ''
    exec "REAL" \
      -B"GCCLIB/" \
      -B"BINUTILS/bin/" \
      -isystem "GLIBC/include" \
      -isystem "LINUXHDRS/include" \
      -L"GLIBC/lib" \
      -Wl,-dynamic-linker,"GLIBC/lib/ld-linux.so.2" \
      "$@"
  '';

in
builtins.derivation {
  name = "gcc-2.95.3";
  inherit system;
  builder = "${bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu

      TOOLS=${posix-tools}/bin
      export PATH="${
        builtins.concatStringsSep ":" (
          builtins.map (p: "${p}/bin") [
            gcc
            binutils
            gnumake
            sed
            grep
            bash
            posix-tools
          ]
        )
      }"
      export CONFIG_SHELL="${bash}/bin/bash"
      export SHELL="${bash}/bin/bash"
      export MAKE="${gnumake}/bin/make"

      # ── Out-of-tree build directory ────────────────────────────────────
      # fetchTarball source is read-only; GCC supports out-of-tree builds
      BUILD=$TMPDIR/build
      mkdir $BUILD
      cd $BUILD

      # ── Configure ──────────────────────────────────────────────────────
      echo "==> Configuring GCC 2.95.3"
      CC="${gcc}/bin/gcc" \
      CFLAGS="-I${glibc}/include -I${linuxHeaders}/include -static" \
      LDFLAGS="-static -L${glibc}/lib" \
      ${src}/configure \
        --prefix=$out \
        --build=i686-unknown-linux-gnu \
        --host=i686-unknown-linux-gnu \
        --target=${target} \
        --enable-languages=c \
        --disable-shared \
        --disable-nls \
        --disable-multilib \
        --with-gnu-as \
        --with-gnu-ld \
        --with-as=${binutils}/bin/as \
        --with-ld=${binutils}/bin/ld

      # ── Build ──────────────────────────────────────────────────────────
      echo "==> Building GCC 2.95.3"
      $MAKE CC="${gcc}/bin/gcc" \
        CFLAGS="-I${glibc}/include -I${linuxHeaders}/include -static" \
        LDFLAGS="-static -L${glibc}/lib" \
        SHELL=${bash}/bin/bash

      # ── Install ────────────────────────────────────────────────────────
      echo "==> Installing GCC 2.95.3"
      $MAKE install \
        SHELL=${bash}/bin/bash

      # ── Create wrapper ─────────────────────────────────────────────────
      # Rename the real gcc binary and install a wrapper that passes glibc
      # include/lib paths and the dynamic linker, so downstream packages
      # link against glibc by default.
      GCCLIB=$out/lib/gcc-lib/${target}/2.95.3

      mv $out/bin/gcc $out/bin/gcc-real

      $TOOLS/cp ${gcc-wrapper} $out/bin/gcc
      $TOOLS/replace --file $out/bin/gcc --output $out/bin/gcc --match-on "REAL" --replace-with "$out/bin/gcc-real"
      $TOOLS/replace --file $out/bin/gcc --output $out/bin/gcc --match-on "GCCLIB" --replace-with "$GCCLIB"
      $TOOLS/replace --file $out/bin/gcc --output $out/bin/gcc --match-on "BINUTILS" --replace-with "${binutils}"
      $TOOLS/replace --file $out/bin/gcc --output $out/bin/gcc --match-on "LINUXHDRS" --replace-with "${linuxHeaders}"
      $TOOLS/replace --file $out/bin/gcc --output $out/bin/gcc --match-on "GLIBC" --replace-with "${glibc}"
      $TOOLS/chmod 750 $out/bin/gcc

      echo "GCC 2.95.3 (self-hosted, glibc) installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Compiler Collection 2.95.3 — self-hosted, linked against glibc";
    homepage = "https://gcc.gnu.org/";
    license = "GPL-2.0-or-later";
    platforms = [ "i686-linux" ];
  };
}
