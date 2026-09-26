##! Snappy Java and JNI rebuilt from pinned source files without bundled native binaries.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  snappy,
  stdenv,
}: let
  version = "1.1.7.1";
  buildJdk = buildPackages.openjdk-21;
  isX86 = stdenv.hostPlatform.system == "x86_64-linux";
  isArm = stdenv.hostPlatform.system == "aarch64-linux";
  javaArch =
    if isX86
    then "x86_64"
    else "aarch64";

  javaFiles = [
    {
      path = "org/xerial/snappy/BitShuffle.java";
      hash = "sha256-vl5pWsXbhA6ZrmggaLAe9HhrTAArtNZrJXV+6eIyjLs=";
    }
    {
      path = "org/xerial/snappy/BitShuffleNative.cpp";
      hash = "sha256-v9FyntkaPlnq8d2VFAbDZSYP7WGYCu1wuQHW+uYUlZs=";
    }
    {
      path = "org/xerial/snappy/BitShuffleNative.h";
      hash = "sha256-wKpMdMXAe7LCcOedhArmw5GznUXZ5WFY1iCme2N8/pE=";
    }
    {
      path = "org/xerial/snappy/BitShuffleNative.java";
      hash = "sha256-4RVN0yUq7CzjSsR6siS1SdhP53g9sc2a1pDbHNyO8WE=";
    }
    {
      path = "org/xerial/snappy/BitShuffleType.java";
      hash = "sha256-a2A1I5aHmvmdEUrl86m7FNa08qI6N4gX2h1Nf54qTtw=";
    }
    {
      path = "org/xerial/snappy/OSInfo.java";
      hash = "sha256-7YFAtv1JJhGM1wUkq8JrMD7Y0GgARYHFbRJLQltxTt0=";
    }
    {
      path = "org/xerial/snappy/PureJavaCrc32C.java";
      hash = "sha256-tAu0WDecZFu//dw5RX7rvYCyMuI0pC69oGoKQV3G0j8=";
    }
    {
      path = "org/xerial/snappy/Snappy.java";
      hash = "sha256-G1yCEesVy8C0iztuFl1oOYwXOR8+ViGDneniAB9L++Q=";
    }
    {
      path = "org/xerial/snappy/SnappyBundleActivator.java";
      hash = "sha256-kGTgfnyMiFOkZ9HKkYnm4iONl4ybdiMo9w/z3p3aevo=";
    }
    {
      path = "org/xerial/snappy/SnappyCodec.java";
      hash = "sha256-FkOtC1iICFt0TaWGYWqtO2dm5zoGXSJasiGT69aciDw=";
    }
    {
      path = "org/xerial/snappy/SnappyError.java";
      hash = "sha256-/6ySIFBolSUZrcAKH4cXDT1wo80cKknyWsjRY/Ic2Ek=";
    }
    {
      path = "org/xerial/snappy/SnappyErrorCode.java";
      hash = "sha256-NFlY8XV+UfcGwR6ZG4NsU8LfNDo6D2Dd2ir/El6N15s=";
    }
    {
      path = "org/xerial/snappy/SnappyException.java";
      hash = "sha256-RfmgTKOaFr0VXrdVJh9VFlxQcuUX7D+tsMRG7TFfyZc=";
    }
    {
      path = "org/xerial/snappy/SnappyFramed.java";
      hash = "sha256-ED3OibsxCO3+ha1kYv4CnvsOT/1lRtawOr+Ta0JTtu0=";
    }
    {
      path = "org/xerial/snappy/SnappyFramedInputStream.java";
      hash = "sha256-MdvFV0aara6KGK+MFwevN/YAH6PgLUzK4Uo1BVpoYDw=";
    }
    {
      path = "org/xerial/snappy/SnappyFramedOutputStream.java";
      hash = "sha256-BV914uaqZ9Zr5biO/ti+WHwoawogNyG8XEgqYqTOB2c=";
    }
    {
      path = "org/xerial/snappy/SnappyHadoopCompatibleOutputStream.java";
      hash = "sha256-HegXo4SarxG2OD1dFOYwvRNVkT/me7XqgdWeKa6uD4g=";
    }
    {
      path = "org/xerial/snappy/SnappyIOException.java";
      hash = "sha256-K/4DiQuqUMK9QL5T8Zu0QoJHS5iUCByX/RNqyhXwNo0=";
    }
    {
      path = "org/xerial/snappy/SnappyInputStream.java";
      hash = "sha256-CY5G+eUAx4auDvEpQVMWN8kXL0wgkhe5pMLVbwaxx9Y=";
    }
    {
      path = "org/xerial/snappy/SnappyLoader.java";
      hash = "sha256-owuvjfGyD/P21gLYSkGvMShmg+bUcHM8fBtQavOiOr4=";
    }
    {
      path = "org/xerial/snappy/SnappyNative.cpp";
      hash = "sha256-KQLJCzh1kM828LhEjKjZYCyytThGIpD/0KOoaj7i+CA=";
    }
    {
      path = "org/xerial/snappy/SnappyNative.h";
      hash = "sha256-uJENAxXJzPBTOver24ckCTf52dOPeYlXlGy1JmyIvJg=";
    }
    {
      path = "org/xerial/snappy/SnappyNative.java";
      hash = "sha256-9EO1Z+F/SSkAwK+dCnneOzuQH1DnLkpt7TV+Hbsp0Yo=";
    }
    {
      path = "org/xerial/snappy/SnappyOutputStream.java";
      hash = "sha256-LAcLizBGPvNq0x8f/wTRQN6THQrbOV4G74dANyOAVO4=";
    }
    {
      path = "org/xerial/snappy/buffer/BufferAllocator.java";
      hash = "sha256-BK4hhtfqJLZ9E1PJeZCxYAscBvoAf1a9/B0YoomMn38=";
    }
    {
      path = "org/xerial/snappy/buffer/BufferAllocatorFactory.java";
      hash = "sha256-2o3Pr5PiVe+86K9bVCJuEMbQJKWcEybkohucFJDaEAI=";
    }
    {
      path = "org/xerial/snappy/buffer/CachedBufferAllocator.java";
      hash = "sha256-+vqKv0EWtQH06n6+KgMSTWSme/EoRxyGs5p+TjwTd8s=";
    }
    {
      path = "org/xerial/snappy/buffer/DefaultBufferAllocator.java";
      hash = "sha256-pPi6RB62zPUz9zvjyVETVyLLt+LJh9iPMlhwlmpQ33U=";
    }
    {
      path = "org/xerial/snappy/package-info.java";
      hash = "sha256-pPAn2Lk6nXzPTaFVAMqz5riwqWjO5Tckwtkja1N0As8=";
    }
  ];
  bitshuffleFiles = [
    {
      path = "src/bitshuffle.h";
      hash = "sha256-Cp5XOTig1+xOcNk/GxBMBhKSbh6ItszZjjJh/q/ppPY=";
    }
    {
      path = "src/bitshuffle_core.c";
      hash = "sha256-xhFaqLX90JCbyTUENO+Ax5pztOvUBuAioHFZwPCt87A=";
    }
    {
      path = "src/bitshuffle_core.h";
      hash = "sha256-vXQmLWLNqM2xsqk9H7Wfd/hafKrYm4po/xx+cHiMSsQ=";
    }
    {
      path = "src/bitshuffle_internals.h";
      hash = "sha256-3Yro9w8q8++B9NrLAhDKCfGJHk1Y+FSt9Ikh96Uk9aA=";
    }
    {
      path = "src/iochain.c";
      hash = "sha256-hzxKfpx1i3w++9vus7hkwfAHtW5JogpYP5noToJIJnw=";
    }
    {
      path = "src/iochain.h";
      hash = "sha256-pkSKkCN+EsLw06q2O3ccWdmy/SN3aLl6V+JQ7NyO0Fk=";
    }
    {
      path = "LICENSE";
      hash = "sha256-7zV8IGHPZ9spj58VZVcu4imtkmNYKp+dDr/1CU9dEKw=";
    }
  ];

  stageFiles = root: repositoryPath: files:
    builtins.concatStringsSep "\n" (builtins.map (file: let
        source = fetchurl {
          urls = ["https://raw.githubusercontent.com/${repositoryPath}/${file.path}"];
          inherit (file) hash;
        };
      in ''
        mkdir -p ${root}/${builtins.dirOf file.path}
        cp ${source} ${root}/${file.path}
      '')
      files);

  snappyLicense = fetchurl {
    urls = ["https://raw.githubusercontent.com/xerial/snappy-java/${version}/LICENSE"];
    hash = "sha256-Pd+b5cKP4n2tFDpdx27qJSIq0d1ok0oEcGTlbtL6QMU=";
  };
  snappyVersion = fetchurl {
    urls = ["https://raw.githubusercontent.com/xerial/snappy-java/${version}/src/main/resources/org/xerial/snappy/VERSION"];
    hash = "sha256-kCyQ4uHnv6Xt+0KONidpmlT+ceBrnjjFaloTQu4Y1cI=";
  };
  osgiJar = "${bazelMavenBootstrap}/maven/org/osgi/org.osgi.core/4.3.1/org.osgi.core-4.3.1.jar";
in
  assert isX86 || isArm;
    mkDerivation {
      pname = "bazel-snappy-java";
      inherit version;
      src = snappyLicense;

      buildDeps = [buildJdk buildPackages.python3 bazelMavenBootstrap];
      runtimeDeps = [snappy];

      phases = [
        {
          name = "unpack";
          script = ''
            ${stageFiles "java" "xerial/snappy-java/${version}/src/main/java" javaFiles}
            ${stageFiles "bitshuffle" "kiyo-masui/bitshuffle/0.3.2" bitshuffleFiles}
            cp ${snappyVersion} java/VERSION

            python3 - <<'PY'
            from pathlib import Path

            for root in (Path("java"), Path("bitshuffle")):
                for path in root.rglob("*"):
                    if path.is_file():
                        path.read_text(encoding="utf-8")

            sources = sorted(Path("java").rglob("*.java"))
            if len(sources) != 25:
                raise SystemExit(f"Expected 25 Snappy Java sources, found {len(sources)}")
            Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
            PY
          '';
        }
        {
          name = "build";
          script = ''
            mkdir -p classes objects
            ${buildJdk}/bin/javac -source 8 -target 8 -proc:none \
              -encoding UTF-8 -cp ${osgiJar} -d classes @java-sources

            includes="-Ijava/org/xerial/snappy -Ibitshuffle/src"
            includes="$includes -I${snappy}/include"
            includes="$includes -I${buildJdk}/include -I${buildJdk}/include/linux"
            cc -O2 -fPIC -U__AVX2__ $includes \
              -c bitshuffle/src/bitshuffle_core.c -o objects/bitshuffle_core.o
            cc -O2 -fPIC -U__AVX2__ $includes \
              -c bitshuffle/src/iochain.c -o objects/iochain.o
            c++ -O2 -fPIC $includes \
              -c java/org/xerial/snappy/SnappyNative.cpp -o objects/SnappyNative.o
            c++ -O2 -fPIC $includes \
              -c java/org/xerial/snappy/BitShuffleNative.cpp -o objects/BitShuffleNative.o
            c++ -shared -Wl,-soname,libsnappyjava.so \
              -Wl,-rpath,${snappy}/lib \
              -o libsnappyjava.so objects/*.o -L${snappy}/lib -lsnappy

            nativeResource="classes/org/xerial/snappy/native/Linux/${javaArch}"
            mkdir -p "$nativeResource"
            cp libsnappyjava.so "$nativeResource/libsnappyjava.so"
            cp java/VERSION classes/org/xerial/snappy/VERSION
          '';
        }
        {
          name = "check";
          script = ''
            ${
              if stdenv.hostPlatform.system == stdenv.buildPlatform.system
              then ''
                cat > SnappyJavaSmoke.java <<'JAVA'
                import java.util.Arrays;
                import org.xerial.snappy.BitShuffle;
                import org.xerial.snappy.Snappy;

                final class SnappyJavaSmoke {
                    public static void main(String[] args) throws Exception {
                        byte[] input = "source-built Snappy JNI".getBytes();
                        byte[] restored = Snappy.uncompress(Snappy.compress(input));
                        if (!Arrays.equals(input, restored)) {
                            throw new AssertionError("Native Snappy roundtrip failed");
                        }

                        int[] values = {1, 2, 3, 4};
                        int[] unshuffled = BitShuffle.unshuffleIntArray(BitShuffle.shuffle(values));
                        if (!Arrays.equals(values, unshuffled)) {
                            throw new AssertionError("Native BitShuffle roundtrip failed");
                        }
                    }
                }
                JAVA

                ${buildJdk}/bin/javac --release 8 -proc:none \
                  -cp classes SnappyJavaSmoke.java
                ${buildJdk}/bin/java -cp classes:. SnappyJavaSmoke
              ''
              else ""
            }
          '';
        }
        {
          name = "install";
          script = ''
            destination="$out/maven/org/xerial/snappy/snappy-java/${version}"
            mkdir -p "$destination" "$out/share/licenses/snappy-java" \
              "$out/share/source" "$out/nix-support"
            ${buildJdk}/bin/jar --create \
              --file "$destination/snappy-java-${version}.jar" \
              --no-manifest --date=1980-01-01T00:00:02Z -C classes .
            cp ${snappyLicense} "$out/share/licenses/snappy-java/LICENSE"
            cp bitshuffle/LICENSE "$out/share/licenses/snappy-java/BITSHUFFLE-LICENSE"
            cp -R java bitshuffle "$out/share/source/"

            # Nix cannot scan the JNI library's RPATH inside a compressed JAR.
            # Keep the shared Snappy library in the published runtime closure.
            printf '%s\n' '${snappy}' > "$out/nix-support/snappy-runtime"
          '';
        }
      ];
    }
