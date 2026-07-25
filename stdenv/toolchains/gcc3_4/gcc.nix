# stdenv/toolchains/gcc3_4/gcc.nix - GCC 3.4.6 (C only, RHEL 4)
#
# First toolchain GCC, built by bootstrap GCC 2.95.3.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
  ...
}: let
  gccSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-3.4.6/gcc-3.4.6.tar.bz2";
    sha256 = "09v2s3ij1pxng9k3z4w98058lvd2m98jywiv5xfiwzxvnp1n5jwq";
  };

  linuxSrc = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.9.tar.bz2";
    sha256 = "1hrnvjlgr4alcs1xcvc98c4vx3bmnc42idp3bav8jnvd0n4kwmq2";
  };

  mkGcc = import ../lib/mk-gcc.nix {
    inherit
      prev
      buildPlatform
      hostPlatform
      targetPlatform
      ;
  };
in
  mkGcc {
    version = "3.4.6";
    src = gccSrc;
    postUnpack = ''
      ${prev.sed}/bin/sed -i \
        "s|native_system_header_dir=/usr/include|native_system_header_dir=${prev.glibc}/include|g" \
        gcc/configure
    '';
    configureEnv = [
      ''CC="${prev.gcc}/bin/gcc"''
      ''CFLAGS="-O2 -static -DSSIZE_MAX=0x7fffffff"''
      ''LDFLAGS="-B${prev.glibc}/lib -static"''
    ];
    configureFlags = [
      "--enable-languages=c"
      "--disable-shared"
      "--disable-nls"
      "--disable-threads"
      "--disable-multilib"
      "--disable-bootstrap"
      "--disable-libssp"
      "--disable-libgomp"
      "--disable-libmudflap"
      "--program-transform-name="
    ];
    postConfigure = ''
      make configure-gcc
      ${prev.sed}/bin/sed -i \
        "s|^SYSTEM_HEADER_DIR.*|SYSTEM_HEADER_DIR = ${prev.glibc}/include|" \
        gcc/Makefile

      mkdir -p "$out/${targetPlatform.config}/sys-include"
      for item in "${prev.glibc}/include"/*; do
        ln -sf "$item" "$out/${targetPlatform.config}/sys-include/"
      done
      cp -r ${linuxSrc}/include/linux "$out/${targetPlatform.config}/sys-include/"
      cp -r ${linuxSrc}/include/asm-i386 "$out/${targetPlatform.config}/sys-include/asm"
      cp -r ${linuxSrc}/include/asm-generic "$out/${targetPlatform.config}/sys-include/"
      ln -sf "$out/${targetPlatform.config}/sys-include" "$out/${targetPlatform.config}/include"
    '';
    # This tier exports a C compiler, not the target runtime collection carried
    # by the full GCC source archive. The top-level default also descends into
    # libstdc++, boehm-gc, and libffi even with --enable-languages=c.
    buildCommands = ''
      make -j"$NIX_BUILD_CORES" all-gcc \
        BOOT_CFLAGS="-O2 -static" \
        CFLAGS_FOR_TARGET="-O2 -I${prev.glibc}/include" \
        LDFLAGS_FOR_TARGET="-B${prev.glibc}/lib -L${prev.glibc}/lib -static"
    '';
    installCommands = ''
      make install-gcc
    '';
    postInstall = ''
      "${prev.binutils}/bin/ar" crs "$out/lib/gcc/${targetPlatform.config}/3.4.6/libgcc_eh.a"

      for f in "${prev.glibc}/lib/"*.o "${prev.glibc}/lib/"*.a; do
        test -f "$f" && ln -sf "$f" "$out/lib/"
      done
    '';
    finalMessage = "GCC 3.4.6 installed to $out";
    meta = {
      description = "GNU Compiler Collection, version 3.4.6 (C only)";
      homepage = "https://gcc.gnu.org/";
      license = "GPL-2.0-or-later";
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
      target = {
        os = "linux";
        cpu = [
          "x86_64"
          "i686"
        ];
      };
    };
  }
