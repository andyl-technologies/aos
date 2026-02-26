# stdenv/toolchains/gcc14/bash.nix — Bash 5.2.37 (RHEL 10)
#
# Production Bash built with THIS tier's GCC 14.3.0 + binutils 2.41 + glibc 2.39.
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
    url = "https://mirrors.kernel.org/gnu/bash/bash-5.2.37.tar.gz";
    sha256 = "012fmryg39p4ynmbg3abp6h1mr2ghbvsjfri66gk1ji3ikbcg01c";
  };
in
builtins.derivation {
  name = "bash-5.2.37";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      cp -r ${src} bash-5.2.37
      cd bash-5.2.37
      chmod -R u+w .

      mkdir -p "$TMPDIR/build"
      cd "$TMPDIR/build"

      CC="${gcc}/bin/gcc" \
      CFLAGS="-O2 -I${glibc}/include" \
      LDFLAGS="-L${glibc}/lib -static" \
      "$TMPDIR/bash-5.2.37/configure" \
        --prefix="$out" \
        --build=${buildPlatform.config} --host=${hostPlatform.config} --target=${hostPlatform.config} \
        --without-bash-malloc \
        --disable-nls

      make -j"$(nproc)"
      make install

      [ -f "$out/bin/bash" ] && [ ! -f "$out/bin/sh" ] && ln -sf bash "$out/bin/sh"

      echo "Bash 5.2.37 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "GNU Bourne-Again SHell 5.2.37";
    homepage = "https://www.gnu.org/software/bash/";
    license = "GPL-3.0-or-later";
    build = { os = "linux"; };
    execute = { os = "linux"; };
  };
}
