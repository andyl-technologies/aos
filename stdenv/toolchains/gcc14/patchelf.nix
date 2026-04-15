# stdenv/toolchains/gcc14/patchelf.nix — patchelf 0.18.0
#
# Utility for modifying ELF executables, built with THIS tier's GCC 14.3.0.
# Needed in the stdenv so all packages can patch interpreters and RPATHs.
#
{
  prev,
  gcc,
  binutils,
  glibc,
  buildPlatform,
  hostPlatform,
}:
let
  src = builtins.fetchTarball {
    url = "https://github.com/NixOS/patchelf/releases/download/0.18.0/patchelf-0.18.0.tar.bz2";
    sha256 = "0s328cmgrbhsc344q323dhg70h8lf8532ywjf8jwjirxq6a5h06w";
  };
in
builtins.derivation {
  name = "patchelf-0.18.0";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir patchelf-0.18.0 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd patchelf-0.18.0 && ${prev.tar}/bin/tar xf -)
      cd patchelf-0.18.0
      chmod -R u+w .

      export LIBRARY_PATH="${glibc}/lib"
      # No -isystem ${glibc}/include here: the wrapped gcc already provides
      # glibc headers via -idirafter (see toolchains/gcc14/default.nix:50).
      # Using -isystem places glibc's stdlib.h *before* the C++ stdlib dir,
      # which breaks #include_next <stdlib.h> in <cstdlib> once gccRaw's
      # specs file no longer has a live -idirafter fallback.
      CC="${gcc}/bin/gcc" \
      CXX="${gcc}/bin/g++" \
      CFLAGS="-O2" \
      CXXFLAGS="-O2" \
      LDFLAGS="-L${glibc}/lib -static -no-pie" \
      ./configure \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config}

      make -j"$NIX_BUILD_CORES"
      make install

      echo "patchelf 0.18.0 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "Utility for modifying ELF executables and libraries";
    homepage = "https://github.com/NixOS/patchelf";
    license = "GPL-3.0-or-later";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
