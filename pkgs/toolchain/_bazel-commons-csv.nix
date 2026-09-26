##! Apache Commons CSV rebuilt from Java source for Log4j's CSV layout.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "1.9.0";
  buildJdk = buildPackages.openjdk-21;
in
  mkDerivation {
    pname = "bazel-commons-csv";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/org/apache/commons/commons-csv/${version}/commons-csv-${version}-sources.jar"];
      hash = "sha256-w3wfPB+nzlz/Jx1ZlTOVLSYjDOyClwEcnueiTTxsmcw=";
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

          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe", "4d5a",
          ))
          with ZipFile(sys.argv[1]) as archive:
              for member in archive.infolist():
                  path = PurePosixPath(member.filename)
                  kind = stat.S_IFMT(member.external_attr >> 16)
                  if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                      raise SystemExit(f"Unsafe Commons CSV source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix not in {".java", ".txt", ".xml", ".properties"} and str(path) != "META-INF/MANIFEST.MF":
                      raise SystemExit(f"Unexpected Commons CSV source: {path}")

                  data = archive.read(member)
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Commons CSV source: {path}")
                  data.decode("utf-8")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 11:
              raise SystemExit(f"Expected 11 Commons CSV sources, found {len(sources)}")
          Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes/META-INF
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -d classes @java-sources
          cp source/META-INF/LICENSE.txt source/META-INF/NOTICE.txt classes/META-INF/
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > CommonsCsvSmoke.java <<'JAVA'
              import java.io.StringReader;
              import java.io.StringWriter;
              import org.apache.commons.csv.CSVFormat;
              import org.apache.commons.csv.CSVParser;
              import org.apache.commons.csv.CSVPrinter;

              final class CommonsCsvSmoke {
                  public static void main(String[] args) throws Exception {
                      StringWriter output = new StringWriter();
                      try (CSVPrinter printer = new CSVPrinter(output, CSVFormat.DEFAULT)) {
                          printer.printRecord("release", "andyl,testing");
                      }
                      try (CSVParser parser = CSVFormat.DEFAULT.parse(new StringReader(output.toString()))) {
                          if (!"andyl,testing".equals(parser.getRecords().get(0).get(1))) {
                              throw new AssertionError("Commons CSV roundtrip failed");
                          }
                      }
                  }
              }
              JAVA

              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp classes CommonsCsvSmoke.java
              ${buildJdk}/bin/java -cp classes:. CommonsCsvSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/org/apache/commons/commons-csv/${version}"
          mkdir -p "$destination" "$out/share/licenses/commons-csv" \
            "$out/share/source"
          ${buildJdk}/bin/jar --create \
            --file "$destination/commons-csv-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/META-INF/LICENSE.txt source/META-INF/NOTICE.txt \
            "$out/share/licenses/commons-csv/"
          cp -R source "$out/share/source/commons-csv"
        '';
      }
    ];
  }
