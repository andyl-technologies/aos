##! Kafka clients rebuilt from the Apache source classifier with native codecs retained.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelLz4Java,
  bazelSnappyJava,
  stdenv,
}: let
  version = "1.1.1";
  sourceCommit = "4dae083af486eaedd27c69c973c74605bffd416b";
  buildJdk = buildPackages.openjdk-21;
  slf4jJar = "${bazelMavenBootstrap}/maven/org/slf4j/slf4j-api/1.7.30/slf4j-api-1.7.30.jar";
  lz4Jar = "${bazelLz4Java}/maven/org/lz4/lz4-java/1.4.1/lz4-java-1.4.1.jar";
  snappyJar = "${bazelSnappyJava}/maven/org/xerial/snappy/snappy-java/1.1.7.1/snappy-java-1.1.7.1.jar";
  runtimeClasspath = builtins.concatStringsSep ":" [slf4jJar lz4Jar snappyJar];
in
  mkDerivation {
    pname = "bazel-kafka-clients";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/org/apache/kafka/kafka-clients/${version}/kafka-clients-${version}-sources.jar"];
      hash = "sha256-y35JH8/UHyvJgGvY9YPzcP5LHvbE7DeJV+RVdIgb6a4=";
    };

    buildDeps = [buildJdk buildPackages.python3 bazelMavenBootstrap];
    runtimeDeps = [bazelLz4Java bazelSnappyJava bazelMavenBootstrap];

    phases = [
      {
        name = "unpack";
        script = ''
          python3 - "$src" <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          allowed_resources = {"META-INF/MANIFEST.MF", "LICENSE", "NOTICE"}
          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe", "4d5a",
          ))

          with ZipFile(sys.argv[1]) as archive:
              for member in archive.infolist():
                  path = PurePosixPath(member.filename)
                  kind = stat.S_IFMT(member.external_attr >> 16)
                  if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                      raise SystemExit(f"Unsafe Kafka source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix != ".java" and str(path) not in allowed_resources:
                      raise SystemExit(f"Unexpected Kafka source member: {path}")

                  data = archive.read(member)
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Kafka source: {path}")
                  data.decode("utf-8")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 566:
              raise SystemExit(f"Expected 566 Kafka Java sources, found {len(sources)}")
          Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes/META-INF classes/kafka
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -cp ${runtimeClasspath} \
            -d classes @java-sources

          cp source/LICENSE source/NOTICE classes/META-INF/
          printf 'version=${version}\ncommitId=${sourceCommit}\n' \
            > classes/kafka/kafka-version.properties
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > KafkaClientsSmoke.java <<'JAVA'
              import java.io.ByteArrayOutputStream;
              import java.io.InputStream;
              import java.io.OutputStream;
              import java.nio.ByteBuffer;
              import java.util.Arrays;
              import org.apache.kafka.common.record.BufferSupplier;
              import org.apache.kafka.common.record.CompressionType;
              import org.apache.kafka.common.record.RecordBatch;
              import org.apache.kafka.common.utils.AppInfoParser;
              import org.apache.kafka.common.utils.ByteBufferOutputStream;

              final class KafkaClientsSmoke {
                  public static void main(String[] args) throws Exception {
                      if (!"${version}".equals(AppInfoParser.getVersion()) ||
                              !"${sourceCommit}".equals(AppInfoParser.getCommitId())) {
                          throw new AssertionError("Kafka version metadata is missing");
                      }

                      byte[] input = new byte[1024];
                      Arrays.fill(input, (byte) 0x45);
                      for (CompressionType codec : new CompressionType[] {
                              CompressionType.LZ4, CompressionType.SNAPPY}) {
                          ByteBufferOutputStream buffer = new ByteBufferOutputStream(128);
                          try (OutputStream encoded = codec.wrapForOutput(
                                  buffer, RecordBatch.MAGIC_VALUE_V2)) {
                              encoded.write(input);
                          }

                          ByteBuffer compressed = buffer.buffer().duplicate();
                          compressed.flip();
                          ByteArrayOutputStream restored = new ByteArrayOutputStream();
                          try (InputStream decoded = codec.wrapForInput(
                                  compressed, RecordBatch.MAGIC_VALUE_V2,
                                  BufferSupplier.NO_CACHING)) {
                              int value;
                              while ((value = decoded.read()) != -1) {
                                  restored.write(value);
                              }
                          }

                          if (!Arrays.equals(input, restored.toByteArray())) {
                              throw new AssertionError(codec + " roundtrip failed");
                          }
                      }
                  }
              }
              JAVA

              checkClasspath="classes:${runtimeClasspath}"
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$checkClasspath" KafkaClientsSmoke.java
              ${buildJdk}/bin/java -cp "$checkClasspath:." KafkaClientsSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/org/apache/kafka/kafka-clients/${version}"
          mkdir -p "$destination" "$out/share/licenses/kafka-clients" \
            "$out/share/source" "$out/nix-support"
          ${buildJdk}/bin/jar --create \
            --file "$destination/kafka-clients-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/LICENSE source/NOTICE "$out/share/licenses/kafka-clients/"
          cp -R source "$out/share/source/kafka-clients"

          # Dependency JARs are loaded by Java, so retain them explicitly.
          printf '%s\n' '${bazelLz4Java}' '${bazelSnappyJava}' \
            '${bazelMavenBootstrap}' > "$out/nix-support/java-runtime"
        '';
      }
    ];
  }
