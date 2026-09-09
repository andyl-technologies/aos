##! Exercises installed Clang and its C++ runtimes inside the hosted-toolchain VM.
##! The caller provides hosted.c and invalid.c from its C compiler checks.
{
  llvm,
  glibc,
  gcc,
}: ''
  llvm=${llvm}
  libc=${glibc}
  libc_dev=${glibc.dev}
  runtime="$llvm/lib/aarch64-unknown-linux-gnu"
  gcc_dir=$(echo ${gcc}/lib/gcc/aarch64-unknown-linux-gnu/*)

  # Raw Clang needs the same AOS include and library locations as ccWrapper.
  # glibc's compatibility archives (including libpthread.a) live in static.
  clang_flags=(
    --sysroot=/
    "--gcc-install-dir=$gcc_dir"
    -idirafter "$libc_dev/include"
    "-B$libc/lib"
    "-L$libc/lib"
    "-L$libc_dev/lib"
    "-L${glibc.static}/lib"
    "-Wl,-dynamic-linker=$libc/lib/ld-linux-aarch64.so.1"
    "-Wl,-rpath,$libc/lib"
  )

  "$llvm/bin/clang" "''${clang_flags[@]}" hosted.c -o clang-c
  test "$(./clang-c)" = "hosted C result: 42"

  # Resolve libc++ independently of an application's search paths. This catches
  # a missing sibling-library RUNPATH even when a consumer directly links libc++abi.
  "$libc/lib/ld-linux-aarch64.so.1" --list "$runtime/libc++.so.1.0" > libcxx.dependencies
  grep -F "$runtime/libc++abi.so.1" libcxx.dependencies

  cat > runtime.cc <<'SOURCE'
  #include <filesystem>
  #include <iostream>
  #include <stdexcept>
  #include <thread>
  #include <vector>

  int main() {
      int result = 0;
      std::thread worker([&] {
          std::vector<int> values{19, 23};
          result = values.at(0) + values.at(1);
      });
      worker.join();

      try {
          throw std::runtime_error("runtime exception");
      } catch (const std::exception& error) {
          if (std::string(error.what()) != "runtime exception") {
              return 1;
          }
      }

      std::filesystem::path path("/tmp/../tmp/runtime.cc");
      if (path.lexically_normal() != "/tmp/runtime.cc") {
          return 2;
      }
      std::cout << "LLVM runtime result: " << result << '\n';
  }
  SOURCE

  "$llvm/bin/clang++" "''${clang_flags[@]}" \
    -std=c++17 -stdlib=libc++ -rtlib=compiler-rt -unwindlib=libunwind \
    -isystem "$llvm/include/c++/v1" \
    -L"$runtime" -Wl,-rpath,"$runtime" -pthread runtime.cc -o llvm-runtime
  test "$(./llvm-runtime)" = "LLVM runtime result: 42"
  "$llvm/bin/llvm-readelf" -d llvm-runtime > runtime.dynamic
  grep -Fq 'libc++.so.1' runtime.dynamic

  if "$llvm/bin/clang" "''${clang_flags[@]}" invalid.c -o invalid-clang \
      >invalid-clang.stdout 2>invalid-clang.stderr; then
    echo 'Clang accepted malformed C' >&2
    exit 1
  fi
  test -s invalid-clang.stderr
''
