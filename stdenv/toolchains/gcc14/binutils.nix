# stdenv/toolchains/gcc14/binutils.nix — binutils 2.41 (RHEL 10)
#
# Modern binutils built with THIS tier's GCC 14.3.0 and the previous
# tier's glibc. Provides the production linker and assembler.
#
{
  prev,
  gcc,
  buildPlatform,
  hostPlatform,
}: let
  src = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/binutils/binutils-2.41.tar.xz";
    sha256 = "0shr30dgkifjzlgqgsf0f0nmb8ffbqrkh93w54bnz4sk4v0s7lgi";
  };
in
  builtins.derivation {
    name = "binutils-2.41";
    system = buildPlatform.system;
    builder = "${prev.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -eu
        export PATH="${prev.coreutils}/bin:${gcc}/bin:${prev.binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
        export CONFIG_SHELL="${prev.bash}/bin/bash"

        cd "$TMPDIR"
        cp -r ${src} binutils-2.41
        cd binutils-2.41
        chmod -R u+w .

        mkdir -p "$TMPDIR/build"
        cd "$TMPDIR/build"

        CC="${gcc}/bin/gcc" CXX="${gcc}/bin/g++" \
        CFLAGS="-O2 -I${prev.glibc}/include" \
        CXXFLAGS="-O2 -I${prev.glibc}/include" \
        LDFLAGS="-L${prev.glibc}/lib -static" \
        "$TMPDIR/binutils-2.41/configure" \
          --prefix="$out" \
          --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
          --disable-shared --disable-nls \
          --disable-gdb --disable-gdbserver --disable-libdecnumber \
          --disable-readline --disable-sim \
          --disable-werror \
          --with-sysroot=/ \
          --program-transform-name=

        make -j"$(nproc)"
        make install

        echo "binutils 2.41 installed to $out"
      ''
    ];
  }
  // {
    meta = {
      description = "GNU binutils 2.41 — linker, assembler, and binary utilities";
      homepage = "https://www.gnu.org/software/binutils/";
      license = "GPL-3.0-or-later";
      build = {os = "linux";};
      execute = {os = "linux";};
    };
  }
