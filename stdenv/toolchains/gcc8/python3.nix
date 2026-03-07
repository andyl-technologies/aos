# stdenv/toolchains/gcc8/python3.nix — Python 3.8.18 (minimal)
#
# Built with THIS tier's GCC 8.5.0 + binutils 2.30 + glibc 2.28.
# Minimal Python interpreter needed by glibc 2.34+ build scripts
# (gen-as-const.py, etc.). No optional modules (ssl, zlib, etc.).
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
    url = "https://www.python.org/ftp/python/3.8.18/Python-3.8.18.tar.xz";
    sha256 = "1nsgfnq51826mrzq4kfviv871z3zjklpfsfhfwc13hry2abn46y8";
  };
in
builtins.derivation {
  name = "python-3.8.18";
  system = buildPlatform.system;
  builder = "${prev.bash}/bin/bash";
  args = [
    "-c"
    ''
      set -eu
      export PATH="${prev.coreutils}/bin:${gcc}/bin:${binutils}/bin:${prev.gnumake}/bin:${prev.sed}/bin:${prev.grep}/bin:${prev.gawk}/bin:${prev.findutils}/bin:${prev.tar}/bin:${prev.gzip}/bin:${prev.diffutils}/bin:${prev.bash}/bin:${prev.patch}/bin"
      export CONFIG_SHELL="${prev.bash}/bin/bash"

      cd "$TMPDIR"
      mkdir Python-3.8.18 && (cd ${src} && ${prev.tar}/bin/tar cf - .) | (cd Python-3.8.18 && ${prev.tar}/bin/tar xf -)
      cd Python-3.8.18
      chmod -R u+w .

      export LIBRARY_PATH="${glibc}/lib"
      GCC_INCDIR="${gcc}/lib/gcc/${hostPlatform.config}/8.5.0/include"

      # Make essential C extension modules built-in (statically linked into
      # the interpreter). Must be created BEFORE configure so makesetup
      # includes them in the build rules. Our gcc defaults to -static which
      # conflicts with -shared used for .so extension modules.
      cat > Modules/Setup.local << 'SETUP_EOF'
_posixsubprocess _posixsubprocess.c
select selectmodule.c
fcntl fcntlmodule.c
_struct _struct.c
math mathmodule.c _math.c
binascii binascii.c
_contextvars _contextvarsmodule.c
_sha1 sha1module.c
_sha256 sha256module.c
_sha512 sha512module.c
_md5 md5module.c
_blake2 _blake2/blake2module.c _blake2/blake2b_impl.c _blake2/blake2s_impl.c
_sha3 _sha3/sha3module.c
_random _randommodule.c
SETUP_EOF

      ./configure \
        --prefix="$out" \
        --build=${buildPlatform.config} \
        --host=${hostPlatform.config} \
        --disable-shared \
        --without-ensurepip \
        ac_cv_file__dev_ptmx=yes \
        ac_cv_file__dev_ptc=no \
        CC="${gcc}/bin/gcc" \
        CXX="${gcc}/bin/g++" \
        CFLAGS="-O2 -nostdinc -isystem $GCC_INCDIR -isystem $GCC_INCDIR-fixed -isystem ${glibc}/include" \
        LDFLAGS="-L${glibc}/lib -static"

      # Skip building shared extension modules (can't link -shared with -static)
      ${prev.sed}/bin/sed -i '/^build_all:/s/ sharedmods / /' Makefile

      make -j"$NIX_BUILD_CORES"
      make install SHAREDMODS=""

      # Ensure python3/python symlinks exist
      [ -f "$out/bin/python3.8" ] && [ ! -f "$out/bin/python3" ] && ln -sf python3.8 "$out/bin/python3"
      [ -f "$out/bin/python3" ] && [ ! -f "$out/bin/python" ] && ln -sf python3 "$out/bin/python"

      echo "Python 3.8.18 installed to $out"
    ''
  ];
}
// {
  meta = {
    description = "Python 3.8.18 — minimal interpreter for build scripts";
    homepage = "https://www.python.org/";
    license = "PSF-2.0";
    build = {
      os = "linux";
    };
    execute = {
      os = "linux";
    };
  };
}
