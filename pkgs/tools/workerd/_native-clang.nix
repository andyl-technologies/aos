##! Native compiler wrappers for the modern Workers runtime and its generators.
{
  mkDerivation,
  llvm,
  bash,
  sed,
  bootstrapTools,
  gcc,
}: let
  buildLlvm = llvm;
  buildBash = bash;
  buildSed = sed;
  buildBootstrapTools = bootstrapTools;
  buildGcc = gcc;
  isCross = false;
in
  mkDerivation {
    pname = "workerd-native-clang";
    inherit (llvm) version;
    runtimeDeps = [llvm bash sed bootstrapTools];
    phases = [
      {
        name = "install";
        script = ''
          BT="${buildBootstrapTools}"
          REAL_CC=$(cat "$BT/nix-support/orig-cc")
          REAL_LIBC=$(cat "$BT/nix-support/orig-libc")
          REAL_LIBC_DEV=$(cat "$BT/nix-support/orig-libc-dev")
          GCC_DIR=$(echo "$REAL_CC"/lib/gcc/x86_64-unknown-linux-gnu/*)
          DL=$(echo "$REAL_LIBC"/lib/ld-linux-x86-64.so.*)

          mkdir -p "$out/bin"

          # workerd's .bazelrc forces `-stdlib=libc++` for both target and host
          # configs. AOS clang must find libc++'s C++ headers (<cstddef> etc.) for
          # that to work; with `--gcc-install-dir` present, clang would otherwise
          # search GCC's libstdc++ headers, and `-no-canonical-prefixes` stops it
          # from auto-locating its own `include/c++/v1`. Without these, capnp's
          # `kj/memory.h` fails with `no type named 'nullptr_t' in namespace 'std'`.
          # Inject the libc++ include dirs as `-isystem` (so they sort before the
          # `-idirafter` glibc headers, and `#include_next` chains stay correct).
          LIBCXX_INC="${buildLlvm}/include/c++/v1"
          LIBCXX_INC_TARGET="${buildLlvm}/include/x86_64-unknown-linux-gnu/c++/v1"

          # Prefer dynamic glibc over the bootstrap GCC's static libc archive.
          # Mixing static libc startup code with a dynamic interpreter breaks
          # TLS initialization. compiler-rt and libunwind provide the matching
          # LLVM exception runtime without depending on libgcc_eh.a.
          LINK_COMMON="-L$REAL_LIBC/lib --gcc-install-dir=$GCC_DIR -B$REAL_LIBC/lib -B$GCC_DIR -fuse-ld=lld --rtlib=compiler-rt --unwindlib=libunwind -L${buildLlvm}/lib/x86_64-unknown-linux-gnu -Wl,-dynamic-linker=$DL -Wl,-rpath,$REAL_LIBC/lib"

          {
            printf '%s\n' '#!${buildBash}/bin/bash'
            printf '%s\n' 'case " $* " in'
            printf '%s\n' '  *" -c "*|*" -E "*|*" -S "*|*" -fsyntax-only "*)'
            # Bazel can route generated C exec tools through the C wrapper while its
            # global workerd flags still request libc++. Hide GCC's libstdc++ headers
            # before adding LLVM libc++; otherwise <cmath> reaches GCC's <math.h> and
            # mixes two incompatible C++ standard-library implementations.
            printf '%s\n' "    exec ${buildLlvm}/bin/clang -nostdinc++ -isystem $LIBCXX_INC_TARGET -isystem $LIBCXX_INC --gcc-install-dir=$GCC_DIR -idirafter $REAL_LIBC_DEV/include -B$REAL_LIBC/lib -B$GCC_DIR \"\$@\" ;;"
            printf '%s\n' 'esac'
            # Bazel's generated response files can retain the auto-detected GNU C++
            # runtime even though workerd explicitly selects libc++. Remove that one
            # library before appending libc++abi/libunwind; mixing the ABI runtimes
            # produces duplicate symbols in native generators such as capnp_tool.
            printf '%s\n' 'link_args=()'
            printf '%s\n' 'for arg in "$@"; do'
            printf '%s\n' '  case "$arg" in'
            printf '%s\n' '    -lstdc++) continue ;;'
            printf '%s\n' "    @*) response_file=\"\''${arg#@}\"; if [ -f \"\$response_file\" ]; then ${buildSed}/bin/sed -i '/^[[:space:]]*-lstdc++[[:space:]]*\$/d; s/[[:space:]]-lstdc++\([[:space:]]\|\$\)/\1/g' \"\$response_file\"; fi ;;"
            printf '%s\n' '  esac'
            printf '%s\n' '  link_args+=("$arg")'
            printf '%s\n' 'done'
            printf '%s\n' "exec ${buildLlvm}/bin/clang $LINK_COMMON \"\''${link_args[@]}\""
          } > "$out/bin/clang"
          chmod +x "$out/bin/clang"

          {
            printf '%s\n' '#!${buildBash}/bin/bash'
            printf '%s\n' 'case " $* " in'
            printf '%s\n' '  *" -c "*|*" -E "*|*" -S "*|*" -fsyntax-only "*)'
            printf '%s\n' "    exec ${buildLlvm}/bin/clang++ -isystem $LIBCXX_INC_TARGET -isystem $LIBCXX_INC --gcc-install-dir=$GCC_DIR -idirafter $REAL_LIBC_DEV/include -B$REAL_LIBC/lib -B$GCC_DIR \"\$@\" ;;"
            printf '%s\n' 'esac'
            # -nostdlib++: link the explicit static libc++ (.bazelrc -l:libc++.a) plus
            # libc++abi/libunwind appended as linkopts, never clang's default
            # libstdc++, so the two C++ runtimes never collide.
            printf '%s\n' 'link_args=()'
            printf '%s\n' 'for arg in "$@"; do'
            printf '%s\n' '  case "$arg" in'
            printf '%s\n' '    -lstdc++) continue ;;'
            printf '%s\n' "    @*) response_file=\"\''${arg#@}\"; if [ -f \"\$response_file\" ]; then ${buildSed}/bin/sed -i '/^[[:space:]]*-lstdc++[[:space:]]*\$/d; s/[[:space:]]-lstdc++\([[:space:]]\|\$\)/\1/g' \"\$response_file\"; fi ;;"
            printf '%s\n' '  esac'
            printf '%s\n' '  link_args+=("$arg")'
            printf '%s\n' 'done'
            printf '%s\n' "exec ${buildLlvm}/bin/clang++ -nostdlib++ $LINK_COMMON \"\''${link_args[@]}\""
          } > "$out/bin/clang++"
          chmod +x "$out/bin/clang++"

          # Provide the remaining LLVM binutils Bazel's clang toolchain expects.
          for t in ld.lld lld llvm-ar ar llvm-nm nm llvm-objcopy objcopy \
                   llvm-objdump objdump llvm-strip strip llvm-dwp dwp \
                   llvm-cov cov llvm-profdata profdata llvm-symbolizer; do
            if [ -e "${buildLlvm}/bin/$t" ]; then
              ln -sf "${buildLlvm}/bin/$t" "$out/bin/$t"
            fi
          done
          # Bazel's unix cc toolchain calls `ar` and the gcov tool; alias clang as cc.
          ln -sf "$out/bin/clang" "$out/bin/cc"
          ln -sf "$out/bin/clang++" "$out/bin/c++"

        '';
      }
      {
        name = "check";
        script = ''
          cat > exception.cc <<'CPP'
          #include <stdexcept>
          int main() {
            try { throw std::runtime_error("runtime test"); }
            catch (const std::exception&) { return 0; }
            return 1;
          }
          CPP
          "$out/bin/clang++" -stdlib=libc++ -c exception.cc -o exception.o
          "$out/bin/clang++" exception.o -l:libc++.a -lc++abi -lunwind -o exception
          ./exception
        '';
      }
    ];
  }
