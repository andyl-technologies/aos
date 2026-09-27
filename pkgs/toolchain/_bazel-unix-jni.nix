##! Linux JNI library for Bazel's source bootstrap.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  bazelSource,
  sourceVersion ? "7.7.1",
}: let
  version = sourceVersion;
  buildJdk = buildPackages.openjdk-21;
  isX86 = stdenv.hostPlatform.system == "x86_64-linux";
  isArm = stdenv.hostPlatform.system == "aarch64-linux";
  bazelCpu =
    if isX86
    then "k8"
    else "aarch64";
  blake3Flags =
    if isX86
    then "-DBLAKE3_NO_AVX512"
    else "-DBLAKE3_USE_NEON=1";
  blake3Source = fetchurl {
    urls = ["https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/1.5.1.tar.gz"];
    hash = "sha256-gizTf3AVLlmFQz0sUMj2suyDqvEaoxvp/nFIapF0Tzc=";
  };
in
  assert isX86 || isArm;
    mkDerivation {
      pname = "bazel-unix-jni";
      inherit version;
      src = bazelSource;

      buildDeps = [buildJdk];
      runtimeDeps = [];

      phases = [
        {
          name = "unpack";
          script = ''
            mkdir bazel-src
            cp -a "$src"/. bazel-src/
            chmod -R u+w bazel-src
            tar xf ${blake3Source}
            mv BLAKE3-1.5.1 blake3
            cd bazel-src
          '';
        }
        {
          name = "build";
          script = ''
            export JAVA_HOME=${buildJdk}
            mkdir objects
            set --

            native_common_source="${
              if builtins.compareVersions version "9.0.0" >= 0
              then "src/main/native/common.cc"
              else ""
            }"
            for source in $native_common_source \
              src/main/native/process.cc \
              src/main/native/unix_jni.cc \
              src/main/native/unix_jni_linux.cc \
              src/main/native/latin1_jni_path.cc \
              src/main/native/blake3_jni.cc \
              src/main/cpp/util/logging.cc \
              src/main/cpp/util/md5.cc \
              src/main/cpp/util/port.cc \
              src/main/cpp/util/strings.cc; do
              object="objects/$(basename "$source").o"
              c++ -std=c++17 -O2 -fPIC -DBLAZE_OPENSOURCE \
                '-DBLAZE_JAVA_CPU="${bazelCpu}"' -I. -I../blake3 \
                -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
                -c "$source" -o "$object"
              set -- "$@" "$object"
            done

            for source in \
              ../blake3/c/blake3.c \
              ../blake3/c/blake3_dispatch.c \
              ../blake3/c/blake3_portable.c; do
              object="objects/$(basename "$source").o"
              cc -O2 -fPIC ${blake3Flags} -I../blake3 \
                -c "$source" -o "$object"
              set -- "$@" "$object"
            done

            ${
              if isX86
              then ''
                for source in \
                  ../blake3/c/blake3_avx2_x86-64_unix.S \
                  ../blake3/c/blake3_sse2_x86-64_unix.S \
                  ../blake3/c/blake3_sse41_x86-64_unix.S; do
                  object="objects/$(basename "$source").o"
                  cc -fPIC -c "$source" -o "$object"
                  set -- "$@" "$object"
                done
              ''
              else ''
                object=objects/blake3_neon.c.o
                cc -O2 -fPIC -DBLAKE3_USE_NEON=1 -I../blake3 \
                  -c ../blake3/c/blake3_neon.c -o "$object"
                set -- "$@" "$object"
              ''
            }

            c++ -shared -Wl,-soname,libunix_jni.so -o libunix_jni.so "$@"
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/lib" "$out/share/licenses/bazel-unix-jni"
            cp libunix_jni.so "$out/lib/libunix_jni.so"
            cp LICENSE "$out/share/licenses/bazel-unix-jni/BAZEL-LICENSE"
            cp ../blake3/LICENSE "$out/share/licenses/bazel-unix-jni/BLAKE3-LICENSE"
          '';
        }
      ];
    }
