# stdenv/cc-wrapper.nix — Compiler and linker wrapper script generator
#
# Creates wrapper scripts for gcc, g++, and ld that inject correct
# -isystem, -L, -rpath, and -dynamic-linker flags.
#
{
  cc,
  libc,
  binutils_,
  shell,
  coreutils,
  hostPlatform,
  storeDir ? "/nix/store",
}:
let
  system = hostPlatform.system;
  targetTriple = hostPlatform.config;
  dynamicLinker = "${libc}/lib/${hostPlatform.dynamicLinker}";

  mkdir = "${coreutils}/bin/mkdir";
  cat = "${coreutils}/bin/cat";
  chmod = "${coreutils}/bin/chmod";
  ln = "${coreutils}/bin/ln";
  echo = "${coreutils}/bin/echo";

  wrapperDrv = builtins.derivation {
    name = "aos-cc-wrapper";
    inherit system;
    builder = shell;
    args = [
      "-c"
      ''
        set -eu

        ${mkdir} -p $out/bin
        ${mkdir} -p $out/nix-support

        # ── gcc wrapper ──────────────────────────────────────────────
        ${cat} > $out/bin/gcc << 'WRAPPER_EOF'
        #!${shell}
        set -eu

        extra_cflags=""
        extra_ldflags=""
        linking=true

        for arg in "$@"; do
          case "$arg" in
            -c|-S|-E) linking=false ;;
          esac
        done

        extra_cflags="$extra_cflags -isystem ${libc}/include"

        if [ "$linking" = true ]; then
          extra_ldflags="$extra_ldflags -L${libc}/lib"
          extra_ldflags="$extra_ldflags -Wl,-rpath,${libc}/lib"
          extra_ldflags="$extra_ldflags -Wl,--dynamic-linker=${dynamicLinker}"
          extra_ldflags="$extra_ldflags -Wl,-rpath-link,${libc}/lib"
          extra_ldflags="$extra_ldflags -L${cc}/lib"
          extra_ldflags="$extra_ldflags -Wl,-rpath,${cc}/lib"
          extra_ldflags="$extra_ldflags -B${libc}/lib"
        fi

        hardening_flags="-fstack-protector-strong -D_FORTIFY_SOURCE=2"

        exec ${cc}/bin/gcc $extra_cflags $hardening_flags "$@" $extra_ldflags
        WRAPPER_EOF
                ${chmod} +x $out/bin/gcc

                # ── g++ wrapper ──────────────────────────────────────────────
                ${cat} > $out/bin/g++ << 'WRAPPER_EOF'
        #!${shell}
        set -eu

        extra_cflags=""
        extra_ldflags=""
        linking=true

        for arg in "$@"; do
          case "$arg" in
            -c|-S|-E) linking=false ;;
          esac
        done

        extra_cflags="$extra_cflags -isystem ${libc}/include"
        extra_cflags="$extra_cflags -isystem ${cc}/include/c++/"

        if [ "$linking" = true ]; then
          extra_ldflags="$extra_ldflags -L${libc}/lib"
          extra_ldflags="$extra_ldflags -Wl,-rpath,${libc}/lib"
          extra_ldflags="$extra_ldflags -Wl,--dynamic-linker=${dynamicLinker}"
          extra_ldflags="$extra_ldflags -Wl,-rpath-link,${libc}/lib"
          extra_ldflags="$extra_ldflags -L${cc}/lib"
          extra_ldflags="$extra_ldflags -Wl,-rpath,${cc}/lib"
          extra_ldflags="$extra_ldflags -B${libc}/lib"
        fi

        hardening_flags="-fstack-protector-strong -D_FORTIFY_SOURCE=2"

        exec ${cc}/bin/g++ $extra_cflags $hardening_flags "$@" $extra_ldflags
        WRAPPER_EOF
                ${chmod} +x $out/bin/g++

                # ── cc/c++ symlinks ──────────────────────────────────────────
                ${ln} -s gcc $out/bin/cc
                ${ln} -s g++ $out/bin/c++

                # ── ld wrapper ───────────────────────────────────────────────
                ${cat} > $out/bin/ld << 'WRAPPER_EOF'
        #!${shell}
        set -eu

        extra_flags=""
        extra_flags="$extra_flags -L${libc}/lib"
        extra_flags="$extra_flags -rpath ${libc}/lib"
        extra_flags="$extra_flags --dynamic-linker ${dynamicLinker}"
        extra_flags="$extra_flags -rpath-link ${libc}/lib"
        extra_flags="$extra_flags -L${cc}/lib"
        extra_flags="$extra_flags -rpath ${cc}/lib"
        extra_flags="$extra_flags -z relro -z now"

        exec ${binutils_}/bin/ld $extra_flags "$@"
        WRAPPER_EOF
                ${chmod} +x $out/bin/ld

                # ── binutils pass-through wrappers ────────────────────────────
                for tool in ar as nm objcopy objdump ranlib readelf size strings strip; do
                  ${cat} > $out/bin/$tool << TOOL_EOF
        #!${shell}
        exec ${binutils_}/bin/$tool "\$@"
        TOOL_EOF
                  ${chmod} +x $out/bin/$tool
                done

                # ── pkg-config wrapper ────────────────────────────────────────
                ${cat} > $out/bin/pkg-config << 'WRAPPER_EOF'
        #!${shell}
        export PKG_CONFIG_PATH="${libc}/lib/pkgconfig:''${PKG_CONFIG_PATH:-}"
        exec pkg-config "$@"
        WRAPPER_EOF
                ${chmod} +x $out/bin/pkg-config

                # ── nix-support metadata ──────────────────────────────────────
                ${echo} "${cc}"        > $out/nix-support/orig-cc
                ${echo} "${libc}"      > $out/nix-support/orig-libc
                ${echo} "${binutils_}" > $out/nix-support/orig-binutils
                ${echo} "${system}"    > $out/nix-support/system
                ${echo} "-isystem ${libc}/include" > $out/nix-support/cc-cflags
                ${echo} "-L${libc}/lib -Wl,-rpath,${libc}/lib" > $out/nix-support/cc-ldflags
                ${echo} "${dynamicLinker}" > $out/nix-support/dynamic-linker
      ''
    ];
  };
in
wrapperDrv
// {
  inherit cc libc;
  binutils = binutils_;
  isWrapper = true;
  targetPrefix = "";
  inherit targetTriple;
  constraints = {
    build = null;
    execute = hostPlatform.constraints;
    target = hostPlatform.constraints;
  };
}
