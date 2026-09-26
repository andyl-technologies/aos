##! LZ4 Java and its JNI library rebuilt from pinned text sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "1.4.1";
  buildJdk = buildPackages.openjdk-21;
  isX86 = stdenv.hostPlatform.system == "x86_64-linux";
  isArm = stdenv.hostPlatform.system == "aarch64-linux";
  javaArch =
    if isX86
    then "amd64"
    else "aarch64";

  nativeFiles = [
    {
      path = "jni/net_jpountz_lz4_LZ4JNI.c";
      hash = "sha256-ENnPIEp70XM/I5SGgKmeKKm/A9gdOuVR/MH0hLL0omQ=";
    }
    {
      path = "jni/net_jpountz_xxhash_XXHashJNI.c";
      hash = "sha256-ZfD9ZpGstTkLBFXKquZfXTuaEaWo93483Aie+cl/t6Y=";
    }
    {
      path = "lz4/lz4.c";
      hash = "sha256-G2h7gni7zcKzMurKH9Wyq5lHOXeN2UqPRM8rEeiIO+g=";
    }
    {
      path = "lz4/lz4.h";
      hash = "sha256-qnm+3omHGQVc0j0fSxMsohyVnKO2x8vYsuwaSI8ga58=";
    }
    {
      path = "lz4/lz4hc.c";
      hash = "sha256-Ph3CjmLTzKh7WvmL7tlHS+nb1PQB8SKnx3h50IxzxL8=";
    }
    {
      path = "lz4/lz4hc.h";
      hash = "sha256-wtiipIq+hgpN2sMuYCeJ800S0hyAsAJReu9NNOaLBXs=";
    }
    {
      path = "xxhash/xxhash.c";
      hash = "sha256-Kz/ybq1aiuBCxBQ4Z0FIUr0pjKwzMxpmWFZOAPFRXAk=";
    }
    {
      path = "xxhash/xxhash.h";
      hash = "sha256-RrdL1UtP7OJJ2M/IcVEwJJWTEVB/OvD0uPXdfdlasFM=";
    }
  ];
  stageNativeFiles = builtins.concatStringsSep "\n" (builtins.map (file: let
      source = fetchurl {
        urls = ["https://raw.githubusercontent.com/lz4/lz4-java/${version}/src/${file.path}"];
        inherit (file) hash;
      };
    in ''
      mkdir -p native/${builtins.dirOf file.path}
      cp ${source} native/${file.path}
    '')
    nativeFiles);

  apacheLicense = fetchurl {
    urls = ["https://raw.githubusercontent.com/lz4/lz4-java/${version}/LICENSE.txt"];
    hash = "sha256-z8d0m5b2O9McPEK1xHG/dWgUBT6EfBDz6wA0F7xSPTA=";
  };
  lz4License = fetchurl {
    urls = ["https://raw.githubusercontent.com/lz4/lz4-java/${version}/src/lz4/LICENSE"];
    hash = "sha256-zWgJU8LQkzBphAhGOBuQTvLALkz+bkDonEQXh28QstI=";
  };
  xxhashLicense = fetchurl {
    urls = ["https://raw.githubusercontent.com/lz4/lz4-java/${version}/src/xxhash/LICENSE"];
    hash = "sha256-huxpU3lFA5QrcPzU81tWXUT2P3A7cDfORNrZZcSqrpE=";
  };
in
  assert isX86 || isArm;
    mkDerivation {
      pname = "bazel-lz4-java";
      inherit version;
      src = fetchurl {
        urls = ["https://repo.maven.apache.org/maven2/org/lz4/lz4-java/${version}/lz4-java-${version}-sources.jar"];
        hash = "sha256-8jnE3LkHeB3VxNTOdJff1ifa3MZTJ3rhtMNpTES21hs=";
      };

      buildDeps = [buildJdk buildPackages.python3];
      runtimeDeps = [];

      phases = [
        {
          name = "unpack";
          script = ''
            python3 - "$src" <<'PY'
            from pathlib import Path, PurePosixPath
            from zipfile import ZipFile
            import stat
            import sys

            compiled_suffixes = {
                ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
                ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
            }
            compiled_signatures = tuple(bytes.fromhex(value) for value in (
                "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
                "feedface", "cefaedfe", "feedfacf", "cffaedfe",
                "4d5a", "504b0304", "504b0506",
            ))

            with ZipFile(sys.argv[1]) as archive:
                for member in archive.infolist():
                    path = PurePosixPath(member.filename)
                    kind = stat.S_IFMT(member.external_attr >> 16)
                    if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                        raise SystemExit(f"Unsafe LZ4 Java source: {path}")
                    if member.is_dir():
                        continue

                    data = archive.read(member)
                    if path.suffix.lower() in compiled_suffixes or data.startswith(compiled_signatures):
                        raise SystemExit(f"Compiled LZ4 Java source: {path}")

                    destination = Path("source") / str(path)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)

            sources = sorted(Path("source").rglob("*.java"))
            if len(sources) != 39:
                raise SystemExit(f"Expected 39 LZ4 Java sources, found {len(sources)}")
            Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
            PY

            ${stageNativeFiles}
            python3 - <<'PY'
            from pathlib import Path

            for path in Path("native").rglob("*"):
                if path.is_file():
                    path.read_text(encoding="utf-8")
            PY
          '';
        }
        {
          name = "build";
          script = ''
            mkdir -p classes headers objects
            ${buildJdk}/bin/javac -source 8 -target 8 -proc:none \
              -encoding UTF-8 -h headers -d classes @java-sources

            includes="-Iheaders -Inative/lz4 -Inative/xxhash"
            includes="$includes -I${buildJdk}/include -I${buildJdk}/include/linux"
            for source in \
              native/jni/net_jpountz_lz4_LZ4JNI.c \
              native/jni/net_jpountz_xxhash_XXHashJNI.c \
              native/lz4/lz4.c native/lz4/lz4hc.c \
              native/xxhash/xxhash.c; do
              object="objects/$(basename "$source").o"
              cc -O2 -fPIC $includes -c "$source" -o "$object"
            done
            cc -shared -Wl,-soname,liblz4-java.so \
              -o liblz4-java.so objects/*.o

            nativeResource="classes/net/jpountz/util/linux/${javaArch}"
            mkdir -p "$nativeResource"
            cp liblz4-java.so "$nativeResource/liblz4-java.so"
          '';
        }
        {
          name = "check";
          script = ''
            ${
              if stdenv.hostPlatform.system == stdenv.buildPlatform.system
              then ''
                cat > Lz4JavaSmoke.java <<'JAVA'
                import java.util.Arrays;
                import net.jpountz.lz4.LZ4Factory;
                import net.jpountz.xxhash.XXHashFactory;

                final class Lz4JavaSmoke {
                    public static void main(String[] args) {
                        byte[] input = "source-built LZ4 JNI".getBytes();
                        byte[] compressed = new byte[64];
                        byte[] restored = new byte[input.length];
                        int compressedLength = LZ4Factory.nativeInstance()
                                .fastCompressor().compress(input, 0, input.length,
                                        compressed, 0, compressed.length);
                        LZ4Factory.nativeInstance().fastDecompressor()
                                .decompress(compressed, 0, restored, 0, restored.length);
                        if (!Arrays.equals(input, restored) || compressedLength <= 0) {
                            throw new AssertionError("Native LZ4 roundtrip failed");
                        }
                        XXHashFactory.nativeInstance().hash32()
                                .hash(input, 0, input.length, 0);
                    }
                }
                JAVA

                ${buildJdk}/bin/javac --release 8 -proc:none \
                  -cp classes Lz4JavaSmoke.java
                ${buildJdk}/bin/java -cp classes:. Lz4JavaSmoke
              ''
              else ""
            }
          '';
        }
        {
          name = "install";
          script = ''
            destination="$out/maven/org/lz4/lz4-java/${version}"
            mkdir -p "$destination" "$out/share/licenses/lz4-java" \
              "$out/share/source"
            ${buildJdk}/bin/jar --create \
              --file "$destination/lz4-java-${version}.jar" \
              --no-manifest --date=1980-01-01T00:00:02Z -C classes .
            cp ${apacheLicense} "$out/share/licenses/lz4-java/LICENSE"
            cp ${lz4License} "$out/share/licenses/lz4-java/LZ4-LICENSE"
            cp ${xxhashLicense} "$out/share/licenses/lz4-java/XXHASH-LICENSE"
            cp -R source native "$out/share/source/"
          '';
        }
      ];
    }
