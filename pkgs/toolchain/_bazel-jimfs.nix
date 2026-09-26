##! Jimfs 1.2 built from Java source with its Unicode runtime dependency.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
}: let
  version = "1.2";
  buildJdk = buildPackages.openjdk-17;
  icu4j = buildPackages.icu4j;
  icu4jJar = "${icu4j}/share/java/icu4j-${icu4j.version}.jar";

  license = fetchurl {
    urls = ["https://raw.githubusercontent.com/google/jimfs/v${version}/LICENSE"];
    hash = "sha256-WNHhf/5RCaeuKWyq/K39vmp9F28LxKsB4SpomwSZ2L0=";
  };
in
  mkDerivation {
    pname = "bazel-jimfs";
    inherit version;

    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/com/google/jimfs/jimfs/${version}/jimfs-${version}-sources.jar"];
      hash = "sha256-HxsyCcuF1s7K3A7TaDG6F1VXpL1meYvS8SzS7j05Ep4=";
    };

    buildDeps = [
      buildJdk
      buildPackages.python3
      buildPackages.findutils
      bazelMavenBootstrap
      icu4j
    ];
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
                      raise SystemExit(f"Unsafe Jimfs source member: {path}")
                  if member.is_dir():
                      continue

                  data = archive.read(member)
                  if path.suffix.lower() in compiled_suffixes or data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Jimfs source member: {path}")

                  destination = Path(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("com/google/common/jimfs").rglob("*.java"))
          provider = Path("com/google/common/jimfs/SystemJimfsFileSystemProvider.java")
          if not sources or "@AutoService(FileSystemProvider.class)" not in provider.read_text():
              raise SystemExit("Jimfs service provider source is missing")
          Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mavenClasspath=$(find ${bazelMavenBootstrap}/maven -type f -name '*.jar' -print | sort | paste -sd:)
          classpath="$mavenClasspath:${icu4jJar}"
          printf '%s\n' "$classpath" > build-classpath

          mkdir -p classes/META-INF/services
          ${buildJdk}/bin/javac --release 17 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d classes @java-sources

          # Upstream's AutoService annotation declares this JDK provider.
          # Recreate its descriptor without executing an annotation processor.
          printf '%s\n' com.google.common.jimfs.SystemJimfsFileSystemProvider \
            > classes/META-INF/services/java.nio.file.spi.FileSystemProvider
        '';
      }
      {
        name = "check";
        script = ''
          cat > JimfsSourceSmoke.java <<'JAVA'
          import com.google.common.jimfs.Configuration;
          import com.google.common.jimfs.Jimfs;
          import com.google.common.jimfs.PathNormalization;
          import java.nio.file.FileSystem;
          import java.nio.file.Files;
          import java.nio.file.Path;
          import java.nio.file.Paths;

          final class JimfsSourceSmoke {
              public static void main(String[] args) throws Exception {
                  Configuration config = Configuration.unix().toBuilder()
                      .setNameCanonicalNormalization(PathNormalization.CASE_FOLD_UNICODE)
                      .build();
                  try (FileSystem fs = Jimfs.newFileSystem(config)) {
                      Path path = fs.getPath("/Stra\u00dfe");
                      Files.writeString(path, "source");
                      if (!Files.exists(fs.getPath("/STRASSE"))) {
                          throw new AssertionError("Unicode case folding failed");
                      }
                      if (!Paths.get(path.toUri()).equals(path)) {
                          throw new AssertionError("Jimfs URI provider was not registered");
                      }
                  }
              }
          }
          JAVA

          classpath="classes:$(cat build-classpath)"
          ${buildJdk}/bin/javac --release 17 -encoding UTF-8 \
            -cp "$classpath" -d classes JimfsSourceSmoke.java
          ${buildJdk}/bin/java -cp "$classpath" JimfsSourceSmoke
          rm classes/JimfsSourceSmoke.class
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/com/google/jimfs/jimfs/${version}"
          mkdir -p "$destination" "$out/maven/com/ibm/icu/icu4j/${icu4j.version}"
          ${buildJdk}/bin/jar --create \
            --file "$destination/jimfs-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp ${icu4jJar} \
            "$out/maven/com/ibm/icu/icu4j/${icu4j.version}/icu4j-${icu4j.version}.jar"

          mkdir -p "$out/share/licenses/jimfs"
          cp ${license} "$out/share/licenses/jimfs/LICENSE"
        '';
      }
    ];
  }
