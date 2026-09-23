##! Native Clang driver for the Linux ARM64 Workers runtime.
{
  buildPackages,
  stdenv,
  glibc,
}: let
  compiler = buildPackages.llvm;
  bash = buildPackages.bash;
  targetGcc = stdenv.cc.cc;
  triple = stdenv.hostPlatform.config;
in
  assert stdenv.isCross && stdenv.hostPlatform.system == "aarch64-linux";
    buildPackages.mkDerivation {
      pname = "workerd-cross-clang";
      inherit (compiler) version;
      targetPlatform = stdenv.hostPlatform;
      runtimeDeps = [compiler bash targetGcc stdenv.binutils glibc glibc.dev glibc.static];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin"
            cat > "$out/bin/compiler" <<'COMPILER'
            #!${bash}/bin/bash
            set -eu

            compiling=false
            c_source=false
            cxx_source=false
            for argument in "$@"; do
              case "$argument" in
                -c|-S|-E|-M|-MM|-fsyntax-only) compiling=true ;;
                *.c|*.s|*.S) c_source=true ;;
                *.cc|*.cp|*.cpp|*.cxx|*.C) cxx_source=true ;;
              esac
            done

            driver="${compiler}/bin/clang++"
            if [ "$compiling" = true ] && [ "$c_source" = true ] && [ "$cxx_source" = false ]; then
              driver="${compiler}/bin/clang"
            fi

            gcc_directory="${targetGcc}/lib/gcc/${triple}/${targetGcc.version}"
            runtime_directory="${targetGcc}/${triple}/lib64"
            common_flags=(
              "--target=${triple}"
              "--gcc-install-dir=$gcc_directory"
              "-idirafter" "${glibc.dev}/include"
              "-B${glibc}/lib" "-B$gcc_directory"
            )

            if [ "$compiling" = true ]; then
              exec "$driver" "''${common_flags[@]}" "$@"
            fi

            # Prefer dynamic target glibc; use its static output only for the
            # compatibility archives of libraries merged into modern libc.
            # Bazel runs native generators and packages target binaries from
            # these links, so both must be complete ELF files. Group Bazel's
            # static archives to resolve cycles when linking with GNU BFD.
            exec "$driver" "''${common_flags[@]}" -Wl,--start-group "$@" -Wl,--end-group \
              -fuse-ld=${stdenv.binutils}/bin/${triple}-ld.bfd \
              -L${glibc}/lib -L"$gcc_directory" -L"$runtime_directory" \
              -L${glibc.static}/lib -latomic \
              -Wl,-dynamic-linker,${glibc}/lib/${stdenv.hostPlatform.dynamicLinker} \
              -Wl,-rpath,${glibc}/lib -Wl,-rpath,"$runtime_directory"
            COMPILER
            chmod +x "$out/bin/compiler"
            ln -s compiler "$out/bin/clang"
            ln -s compiler "$out/bin/clang++"
          '';
        }
      ];

      meta = {
        description = "AOS Clang driver for cross-building the ARM64 Workers runtime";
        license = "Apache-2.0";
      };
    }
