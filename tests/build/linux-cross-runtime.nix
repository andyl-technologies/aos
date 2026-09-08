# Static libc and packaged GCC runtime qualification for AArch64 Linux cross builds.
{pkgs}: let
  buildSystem = pkgs.stdenv.buildPlatform.system;
  targetSystem = "aarch64-linux";
  cross = import ../.. {
    system = buildSystem;
    crossSystem = targetSystem;
  };
  gccLibs = cross.pkgs.gcc-libs;
  targetLibc = cross.stdenv.glibc;
  targetRunner = cross.stdenv.targetRunner;
  targetBinutils = cross.stdenv.binutils;
in
  assert cross.stdenv.isCross;
  assert cross.stdenv.hostPlatform.system == targetSystem;
  assert gccLibs.platforms.host.system == targetSystem;
  assert gccLibs.system == buildSystem;
  assert targetRunner != null;
    cross.stdenv.mkDerivation {
      pname = "linux-cross-runtime-aarch64";
      version = "0";
      src = null;
      dontStrip = true;
      dontPatchELF = true;
      dontNukeRefs = true;

      phases = [
        {
          name = "qualify-runtime";
          script = ''
            fail() {
              echo "linux-cross-runtime: FAIL: $*" >&2
              exit 1
            }

            check_contains() {
              description=$1
              pattern=$2
              path=$3

              grep -Fq -- "$pattern" "$path" || fail "$description"
            }

            check_needed_set() {
              description=$1
              path=$2
              shift 2

              ${targetBinutils}/bin/readelf -dW "$path" | \
                sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p' | \
                sort > actual-needed
              : > expected-needed
              if test "$#" -gt 0; then
                printf '%s\n' "$@" | sort > expected-needed
              fi
              if ! cmp -s expected-needed actual-needed; then
                echo "$description has an unexpected NEEDED set" >&2
                diff -u expected-needed actual-needed >&2 || true
                exit 1
              fi
            }

            check_aarch64() {
              description=$1
              path=$2

              ${targetBinutils}/bin/readelf -hW "$path" > elf-header
              check_contains "$description is not an AArch64 ELF" \
                'Machine:                           AArch64' elf-header
            }

            check_interpreter() {
              description=$1
              path=$2
              expected=$3

              ${targetBinutils}/bin/readelf -lW "$path" | \
                sed -n 's/.*\[Requesting program interpreter: \(.*\)\]/\1/p' \
                > actual-interpreter
              test "$(wc -l < actual-interpreter)" -eq 1 || \
                fail "$description does not have exactly one interpreter"
              test "$(cat actual-interpreter)" = "$expected" || \
                fail "$description has an unexpected interpreter"
            }

            mkdir -p "$out/bin"
            runner=${targetRunner}/bin/aos-run-${targetSystem}

            # Disable sqrt folding so both static links must consume glibc's
            # libm.a linker script.
            "$CC" -static -fno-builtin-sqrt \
              ${./linux-cross-static-math.c} -lm \
              -o "$out/bin/linux-cross-static-c-math"
            "$CXX" -static -fno-builtin-sqrt \
              ${./linux-cross-static-math.cpp} -lm \
              -o "$out/bin/linux-cross-static-cxx-math"

            # Load the repackaged runtime explicitly. This verifies that its
            # indirect libgcc_s edge resolves without the compiler output.
            "$CXX" -Wl,--as-needed -fno-exceptions \
              -L${gccLibs}/lib \
              -Wl,-t \
              ${./linux-cross-cxx-runtime.cpp} \
              -o "$out/bin/linux-cross-gcc-libs-cxx" \
              > gcc-libs-link.trace 2>&1
            check_contains 'C++ link did not consume packaged libstdc++' \
              '${gccLibs}/lib/libstdc++.so' gcc-libs-link.trace
            check_contains 'C++ link did not consume packaged libgcc_s' \
              '${gccLibs}/lib/libgcc_s.so' gcc-libs-link.trace
            ${cross.buildPackages.patchelf}/bin/patchelf \
              --set-rpath '${gccLibs}/lib:${targetLibc}/lib' \
              "$out/bin/linux-cross-gcc-libs-cxx"

            "$runner" "$out/bin/linux-cross-static-c-math" 9 > static-c.out
            test "$(cat static-c.out)" = 'AOS static C math passed'
            "$runner" "$out/bin/linux-cross-static-cxx-math" 9 > static-cxx.out
            test "$(cat static-cxx.out)" = 'AOS static C++ math passed'
            "$runner" "$out/bin/linux-cross-gcc-libs-cxx" > gcc-libs-cxx.out
            test "$(cat gcc-libs-cxx.out)" = \
              'AOS packaged C++ runtime passed: 10'

            for executable in \
              "$out/bin/linux-cross-static-c-math" \
              "$out/bin/linux-cross-static-cxx-math" \
              "$out/bin/linux-cross-gcc-libs-cxx"; do
              check_aarch64 'runtime probe' "$executable"
            done
            for executable in \
              "$out/bin/linux-cross-static-c-math" \
              "$out/bin/linux-cross-static-cxx-math"; do
              ${targetBinutils}/bin/readelf -lW "$executable" > program-headers
              if grep -F INTERP program-headers >/dev/null; then
                fail "static runtime probe has an interpreter: $executable"
              fi
            done

            printf '%s\n' \
              libgcc_s.so \
              libgcc_s.so.1 \
              libstdc++.so \
              libstdc++.so.6 \
              libstdc++.so.6.0.33 \
              | sort > expected-runtime-files
            find ${gccLibs}/lib -mindepth 1 -maxdepth 1 -printf '%f\n' | \
              sort > actual-runtime-files
            if ! cmp -s expected-runtime-files actual-runtime-files; then
              echo 'gcc-libs does not preserve the five-file runtime surface' >&2
              diff -u expected-runtime-files actual-runtime-files >&2 || true
              exit 1
            fi

            test "$(readlink ${gccLibs}/lib/libstdc++.so)" = \
              'libstdc++.so.6.0.33'
            test "$(readlink ${gccLibs}/lib/libstdc++.so.6)" = \
              'libstdc++.so.6.0.33'
            check_contains 'libgcc_s linker script lost its shared/static group' \
              'GROUP ( libgcc_s.so.1 -lgcc )' \
              ${gccLibs}/lib/libgcc_s.so

            libgcc=${gccLibs}/lib/libgcc_s.so.1
            libstdcxx=${gccLibs}/lib/libstdc++.so.6.0.33
            for runtime in "$libgcc" "$libstdcxx"; do
              check_aarch64 'packaged GCC runtime' "$runtime"
            done
            test "$(${cross.buildPackages.patchelf}/bin/patchelf \
              --print-rpath "$libgcc")" = '${targetLibc}/lib' || \
              fail 'packaged libgcc_s has an unexpected RPATH'
            test "$(${cross.buildPackages.patchelf}/bin/patchelf \
              --print-rpath "$libstdcxx")" = \
              '${gccLibs}/lib:${targetLibc}/lib' || \
              fail 'packaged libstdc++ has an unexpected RPATH'
            test "$(${cross.buildPackages.patchelf}/bin/patchelf \
              --print-soname "$libgcc")" = 'libgcc_s.so.1'
            test "$(${cross.buildPackages.patchelf}/bin/patchelf \
              --print-soname "$libstdcxx")" = 'libstdc++.so.6'
            check_needed_set 'packaged libgcc_s' "$libgcc" libc.so.6
            check_needed_set 'packaged libstdc++' "$libstdcxx" \
              libm.so.6 libc.so.6 libgcc_s.so.1

            dynamicProbe="$out/bin/linux-cross-gcc-libs-cxx"
            targetLoader='${targetLibc}/lib/${cross.stdenv.hostPlatform.dynamicLinker}'
            check_interpreter 'gcc-libs C++ probe' "$dynamicProbe" \
              "$targetLoader"
            test "$(${cross.buildPackages.patchelf}/bin/patchelf \
              --print-rpath "$dynamicProbe")" = \
              '${gccLibs}/lib:${targetLibc}/lib'
            check_needed_set 'gcc-libs C++ probe' "$dynamicProbe" \
              libstdc++.so.6 libc.so.6 \
              ${cross.stdenv.hostPlatform.dynamicLinker}

            check_aarch64 'target dynamic loader' "$targetLoader"
            check_needed_set 'target dynamic loader' "$targetLoader"

            printf 'PASS\n' > "$out/result"
            echo 'linux-cross-runtime: PASS' >&2
          '';
        }
      ];
    }
