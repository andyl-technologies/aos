# stdenv/toolchains/gcc4_1/gcc.nix - GCC 4.1.2 (C only, RHEL 5)
#
# Built by GCC 3.4.6 from the previous tier. No GMP/MPFR is needed.
{
  prev,
  buildPlatform,
  hostPlatform,
  targetPlatform,
}: let
  gccSrc = builtins.fetchTarball {
    url = "https://mirrors.kernel.org/gnu/gcc/gcc-4.1.2/gcc-core-4.1.2.tar.bz2";
    sha256 = "0fzi14bjj39lx9s8ppkrlarbmga8j51p7f4qnm3w4rh13z6gnz87";
  };

  linuxSrc = builtins.fetchTarball {
    url = "https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.18.tar.bz2";
    sha256 = "0ad6d97c1z5z79gafbxsd9d9wq4f21hmvp52s91dysqk24fkbdbx";
  };

  asmDirMap = {
    x86_64 = "asm-x86_64";
    i686 = "asm-i386";
  };
  asmDir =
    asmDirMap.${hostPlatform.constraints.cpu}
    or (throw "unsupported CPU for linux headers: ${hostPlatform.constraints.cpu}");

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
    version = "4.1.2";
    sourceDir = "gcc-core-4.1.2";
    src = gccSrc;
    postUnpack = ''
      # The cross-tier sed 4.1.2 binary is static glibc 2.3.4 userspace.
      # Its in-place mode segfaults on newer 6.12 kernels, while the same
      # transform through stdout is stable. Rewrite the original inode so
      # executable modes and source permissions stay intact.
      rewriteWithPrevSed() {
        file="$1"
        shift
        ${prev.sed}/bin/sed "$@" "$file" > "$file.tmp-sed"
        ${prev.coreutils}/bin/cat "$file.tmp-sed" > "$file"
        ${prev.coreutils}/bin/rm "$file.tmp-sed"
      }

      touch gcc/gengtype-lex.c gcc/gengtype-yacc.c gcc/gengtype-yacc.h

      rewriteWithPrevSed gcc/config/i386/i386.c 's/ix86_attribute_table\[\]/ix86_attribute_table[10]/'
      rewriteWithPrevSed libiberty/alloca.c 's/C_alloca/alloca/g'
      rewriteWithPrevSed include/libiberty.h 's/C_alloca/alloca/g'
    '';
    configureEnv = [
      ''CC="${prev.gcc}/bin/gcc"''
      ''CPP="${prev.gcc}/bin/gcc -E"''
      ''CFLAGS="-O2 -static -I${prev.glibc}/include"''
      ''LDFLAGS="-static -L${prev.glibc}/lib"''
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
      ''--with-native-system-header-dir="${prev.glibc}/include"''
      "--without-headers"
      "--program-transform-name="
    ];
    postConfigure = ''
      make configure-gcc
      rewriteWithPrevSed gcc/Makefile \
        "s|^SYSTEM_HEADER_DIR.*|SYSTEM_HEADER_DIR = ${prev.glibc}/include|"

      mkdir -p "$out/${targetPlatform.config}/sys-include"
      for item in "${prev.glibc}/include"/*; do
        ln -sf "$item" "$out/${targetPlatform.config}/sys-include/"
      done
      rm -f "$out/${targetPlatform.config}/sys-include/linux" \
            "$out/${targetPlatform.config}/sys-include/asm" \
            "$out/${targetPlatform.config}/sys-include/asm-generic"
      cp -r ${linuxSrc}/include/linux "$out/${targetPlatform.config}/sys-include/"
      cp -r ${linuxSrc}/include/${asmDir} "$out/${targetPlatform.config}/sys-include/asm"
      cp -r ${linuxSrc}/include/asm-generic "$out/${targetPlatform.config}/sys-include/"
      ln -sf "$out/${targetPlatform.config}/sys-include" "$out/${targetPlatform.config}/include"
    '';
    makeFlags = [
      ''BOOT_CFLAGS="-O2 -static"''
      ''CFLAGS_FOR_TARGET="-O2 -I${prev.glibc}/include"''
      ''LDFLAGS_FOR_TARGET="-L${prev.glibc}/lib -static"''
    ];
    postInstall = ''
      "${prev.binutils}/bin/ar" crs "$out/lib/gcc/${targetPlatform.config}/4.1.2/libgcc_eh.a"

      for f in "${prev.glibc}/lib/"*.o "${prev.glibc}/lib/"*.a; do
        test -f "$f" && ln -sf "$f" "$out/lib/"
      done

      mkdir -p "$out/${targetPlatform.config}/bin"
      for tool in as ld ar nm ranlib strip objcopy objdump; do
        test -f "${prev.binutils}/bin/$tool" && \
          ln -sf "${prev.binutils}/bin/$tool" "$out/${targetPlatform.config}/bin/$tool"
      done
    '';
    finalMessage = "GCC 4.1.2 installed to $out";
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
      target = {
        os = "linux";
        cpu = [
          "x86_64"
          "i686"
        ];
      };
    };
  }
