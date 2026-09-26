##! Bazel's zstd JNI archive compiled from the pinned upstream source tree.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  version ? "1.5.2-3",
}: let
  sourceHash =
    if version == "1.5.2-3"
    then "sha256-KO0KaJWFVu5JaZddD5cP8MeB0tWbY/UD8gguZpoCqQQ="
    else if version == "1.5.5-11"
    then "sha256-Nm0OH6L3lF+389ZTe9PmdSkmu/f8ywrgSwG2eyLQm5c="
    else throw "Unsupported zstd JNI source version: ${version}";
  buildJdk = buildPackages.openjdk-17;
  javaArchitecture =
    if stdenv.hostPlatform.isAarch64
    then "aarch64"
    else "amd64";
in
  assert stdenv.hostPlatform.isLinux;
  assert stdenv.hostPlatform.isAarch64 || stdenv.hostPlatform.isx86_64;
    mkDerivation {
      pname = "bazel-zstd-jni";
      inherit version;
      src = fetchurl {
        urls = ["https://codeload.github.com/luben/zstd-jni/tar.gz/refs/tags/v${version}"];
        hash = sourceHash;
      };

      buildDeps = [buildJdk buildPackages.findutils buildPackages.python3];
      runtimeDeps = [];

      phases = [
        {
          name = "unpack";
          script = ''
            tar xf "$src"
            cd zstd-jni-${version}

            python3 - <<'PY'
            from pathlib import Path

            compiled_suffixes = {
                ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
                ".wasm", ".exe", ".bin", ".zip",
            }
            compiled_signatures = (
                bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
                bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
                bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
            )
            for path in Path(".").rglob("*"):
                if not path.is_file():
                    continue
                if path.suffix.lower() in compiled_suffixes:
                    raise SystemExit(f"Compiled payload in zstd JNI source: {path}")
                if path.read_bytes()[:8].startswith(compiled_signatures):
                    raise SystemExit(f"Compiled payload in zstd JNI source: {path}")
            PY
          '';
        }
        {
          name = "build";
          script = ''
            export JAVA_HOME=${buildJdk}
            export PATH="$JAVA_HOME/bin:$PATH"

            mkdir -p generated/com/github/luben/zstd/util classes
            cat > generated/com/github/luben/zstd/util/ZstdVersion.java <<'JAVA'
            package com.github.luben.zstd.util;

            public class ZstdVersion {
                public static final String VERSION = "${version}";
            }
            JAVA
            find src/main/java generated -type f -name '*.java' -print > java-sources
            javac --release 8 -proc:none -encoding UTF-8 \
              -d classes @java-sources

            # Upstream's JNI sources include the matching zstd C sources.
            # Compile them together so the Java API and native implementation
            # carry the same pinned version in one archive.
            mkdir -p objects
            find src/main/native -type f -name '*.c' -print > native-sources
            ${
              if stdenv.hostPlatform.isx86_64
              then ''find src/main/native -type f -name '*.S' -print >> native-sources''
              else ""
            }
            while IFS= read -r source_file; do
              object_file="objects/$(printf '%s' "$source_file" | tr / _).o"
              cc -std=c99 -fPIC -O2 -pthread \
                -DZSTD_LEGACY_SUPPORT=4 -DZSTD_MULTITHREAD=1 \
                -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" \
                -Isrc/main/native -Isrc/main/native/common \
                -Isrc/main/native/compress -Isrc/main/native/decompress \
                -Isrc/main/native/dictBuilder -Isrc/main/native/legacy \
                -c "$source_file" -o "$object_file"
            done < native-sources

            mkdir -p classes/linux/${javaArchitecture}
            cc -shared -pthread -Wl,--version-script=libzstd-jni.so.map \
              objects/*.o \
              -o classes/linux/${javaArchitecture}/libzstd-jni-${version}.so
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/maven/com/github/luben/zstd-jni/${version}" \
              "$out/share/licenses/zstd-jni"
            jar --create --file "$out/maven/com/github/luben/zstd-jni/${version}/zstd-jni-${version}.jar" \
              --no-manifest --date=1980-01-01T00:00:02Z -C classes .
            cp LICENSE "$out/share/licenses/zstd-jni/LICENSE"
          '';
        }
      ];
    }
