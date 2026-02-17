# stdenv/cc-wrapper.nix — Compiler and linker wrapper script generator
#
# Creates wrapper scripts for gcc, g++, and ld that:
#   - Set correct -isystem paths for headers
#   - Set -L paths for library search
#   - Set -rpath for runtime library resolution
#   - Prevent leaking of build-time paths into runtime
#
# The wrappers are shell scripts that invoke the real compiler/linker
# with the correct flags prepended.
#
{
  cc, # Path to the unwrapped GCC installation
  libc, # Path to the glibc installation
  binutils_, # Path to binutils installation
  storeDir ? "/nix/store",
  system ? "x86_64-linux",
}: let
  # Determine the target triple from the system string
  targetTriple =
    if system == "x86_64-linux"
    then "x86_64-unknown-linux-gnu"
    else if system == "aarch64-linux"
    then "aarch64-unknown-linux-gnu"
    else throw "cc-wrapper: unsupported system '${system}'";

  # GCC version subdirectory (for internal headers)
  # This is determined at build time; we parameterize it.
  gccLibDir = "${cc}/lib/gcc/${targetTriple}";

  wrapperDrv = builtins.derivation {
    name = "aos-cc-wrapper";
    inherit system;
    builder = "/bin/sh";
    args = [
      "-c"
      ''
              set -eu

              mkdir -p $out/bin
              mkdir -p $out/nix-support

              # -----------------------------------------------------------------------
              # gcc wrapper
              # -----------------------------------------------------------------------
              cat > $out/bin/gcc << 'WRAPPER_EOF'
        #!/bin/sh
        # AOS GCC wrapper — adds system include and library paths
        set -eu

        extra_cflags=""
        extra_ldflags=""
        linking=true
        compiling=true

        # Detect if we are only compiling (not linking)
        for arg in "$@"; do
          case "$arg" in
            -c|-S|-E) linking=false ;;
          esac
        done

        # System include paths (glibc headers + GCC internal headers)
        extra_cflags="$extra_cflags -isystem ${libc}/include"

        # When linking, add library paths and rpath
        if [ "$linking" = true ]; then
          extra_ldflags="$extra_ldflags -L${libc}/lib"
          extra_ldflags="$extra_ldflags -Wl,-rpath,${libc}/lib"

          # Dynamic linker path
          extra_ldflags="$extra_ldflags -Wl,--dynamic-linker=${libc}/lib/ld-linux-x86-64.so.2"

          # Prevent build-time paths from leaking: use -rpath-link for transitive deps
          extra_ldflags="$extra_ldflags -Wl,-rpath-link,${libc}/lib"

          # Add GCC runtime library path
          extra_ldflags="$extra_ldflags -L${cc}/lib"
          extra_ldflags="$extra_ldflags -Wl,-rpath,${cc}/lib"

          # Link against the correct CRT objects
          extra_ldflags="$extra_ldflags -B${libc}/lib"
        fi

        # Hardening flags (always enabled for AOS)
        hardening_flags="-fstack-protector-strong -D_FORTIFY_SOURCE=2"

        exec ${cc}/bin/gcc $extra_cflags $hardening_flags "$@" $extra_ldflags
        WRAPPER_EOF
              chmod +x $out/bin/gcc

              # -----------------------------------------------------------------------
              # g++ wrapper
              # -----------------------------------------------------------------------
              cat > $out/bin/g++ << 'WRAPPER_EOF'
        #!/bin/sh
        # AOS G++ wrapper — adds system include and library paths
        set -eu

        extra_cflags=""
        extra_ldflags=""
        linking=true

        for arg in "$@"; do
          case "$arg" in
            -c|-S|-E) linking=false ;;
          esac
        done

        # System include paths
        extra_cflags="$extra_cflags -isystem ${libc}/include"
        # C++ standard library headers (from GCC installation)
        extra_cflags="$extra_cflags -isystem ${cc}/include/c++/"

        # Linking flags
        if [ "$linking" = true ]; then
          extra_ldflags="$extra_ldflags -L${libc}/lib"
          extra_ldflags="$extra_ldflags -Wl,-rpath,${libc}/lib"
          extra_ldflags="$extra_ldflags -Wl,--dynamic-linker=${libc}/lib/ld-linux-x86-64.so.2"
          extra_ldflags="$extra_ldflags -Wl,-rpath-link,${libc}/lib"
          extra_ldflags="$extra_ldflags -L${cc}/lib"
          extra_ldflags="$extra_ldflags -Wl,-rpath,${cc}/lib"
          extra_ldflags="$extra_ldflags -B${libc}/lib"
        fi

        hardening_flags="-fstack-protector-strong -D_FORTIFY_SOURCE=2"

        exec ${cc}/bin/g++ $extra_cflags $hardening_flags "$@" $extra_ldflags
        WRAPPER_EOF
              chmod +x $out/bin/g++

              # -----------------------------------------------------------------------
              # cc symlink (many build systems look for 'cc')
              # -----------------------------------------------------------------------
              ln -s gcc $out/bin/cc
              ln -s g++ $out/bin/c++

              # -----------------------------------------------------------------------
              # ld wrapper
              # -----------------------------------------------------------------------
              cat > $out/bin/ld << 'WRAPPER_EOF'
        #!/bin/sh
        # AOS ld wrapper — adds library search paths and rpath
        set -eu

        extra_flags=""

        # Library search paths
        extra_flags="$extra_flags -L${libc}/lib"
        extra_flags="$extra_flags -rpath ${libc}/lib"
        extra_flags="$extra_flags --dynamic-linker ${libc}/lib/ld-linux-x86-64.so.2"
        extra_flags="$extra_flags -rpath-link ${libc}/lib"

        # GCC runtime libraries
        extra_flags="$extra_flags -L${cc}/lib"
        extra_flags="$extra_flags -rpath ${cc}/lib"

        # Full RELRO for security (AOS default)
        extra_flags="$extra_flags -z relro -z now"

        exec ${binutils_}/bin/ld $extra_flags "$@"
        WRAPPER_EOF
              chmod +x $out/bin/ld

              # -----------------------------------------------------------------------
              # Binutils pass-through wrappers
              # -----------------------------------------------------------------------
              for tool in ar as nm objcopy objdump ranlib readelf size strings strip; do
                cat > $out/bin/$tool << TOOL_EOF
        #!/bin/sh
        exec ${binutils_}/bin/$tool "\$@"
        TOOL_EOF
                chmod +x $out/bin/$tool
              done

              # -----------------------------------------------------------------------
              # pkg-config wrapper (sets PKG_CONFIG_PATH)
              # -----------------------------------------------------------------------
              cat > $out/bin/pkg-config << 'WRAPPER_EOF'
        #!/bin/sh
        # AOS pkg-config wrapper
        export PKG_CONFIG_PATH="${libc}/lib/pkgconfig:''${PKG_CONFIG_PATH:-}"
        exec pkg-config "$@"
        WRAPPER_EOF
              chmod +x $out/bin/pkg-config

              # -----------------------------------------------------------------------
              # nix-support metadata files
              # -----------------------------------------------------------------------
              # These files record the wrapper's configuration for introspection.
              echo "${cc}"        > $out/nix-support/orig-cc
              echo "${libc}"      > $out/nix-support/orig-libc
              echo "${binutils_}" > $out/nix-support/orig-binutils
              echo "${system}"    > $out/nix-support/system

              # Propagated include and library paths
              echo "-isystem ${libc}/include" > $out/nix-support/cc-cflags
              echo "-L${libc}/lib -Wl,-rpath,${libc}/lib" > $out/nix-support/cc-ldflags

              # Record the dynamic linker path
              echo "${libc}/lib/ld-linux-x86-64.so.2" > $out/nix-support/dynamic-linker
      ''
    ];
  };
in
  wrapperDrv
  // {
    # Expose metadata for other parts of the build system
    inherit cc libc;
    binutils = binutils_;
    isWrapper = true;
    targetPrefix = "";
    inherit targetTriple;
  }
