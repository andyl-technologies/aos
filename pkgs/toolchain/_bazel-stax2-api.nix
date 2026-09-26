##! StAX2 API rebuilt from its source classifier for Jackson XML and Woodstox.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "4.2.1";
  buildJdk = buildPackages.openjdk-21;
in
  mkDerivation {
    pname = "bazel-stax2-api";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/org/codehaus/woodstox/stax2-api/${version}/stax2-api-${version}-sources.jar"];
      hash = "sha256-8SFY7Z80ri6VkWvfbkJ3cZ41SyUiwOZyCykBInP2xu0=";
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
                      raise SystemExit(f"Unsafe StAX2 source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix not in {".java", ".html"} and path.parts[0] != "META-INF":
                      raise SystemExit(f"Unexpected StAX2 source: {path}")

                  data = archive.read(member)
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled StAX2 source: {path}")
                  data.decode("utf-8")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 93:
              raise SystemExit(f"Expected 93 StAX2 Java sources, found {len(sources)}")
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
          cp source/META-INF/LICENSE classes/META-INF/LICENSE
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > Stax2Smoke.java <<'JAVA'
              import java.io.StringReader;
              import javax.xml.stream.XMLInputFactory;
              import javax.xml.stream.XMLStreamReader;
              import org.codehaus.stax2.XMLStreamReader2;
              import org.codehaus.stax2.ri.Stax2ReaderAdapter;

              final class Stax2Smoke {
                  public static void main(String[] args) throws Exception {
                      XMLStreamReader source = XMLInputFactory.newInstance()
                              .createXMLStreamReader(new StringReader("<release>1</release>"));
                      XMLStreamReader2 reader = Stax2ReaderAdapter.wrapIfNecessary(source);
                      reader.nextTag();
                      if (!"release".equals(reader.getLocalName()) ||
                              !"1".equals(reader.getElementText())) {
                          throw new AssertionError("StAX2 adapter failed to read XML");
                      }
                      reader.close();
                  }
              }
              JAVA

              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp classes Stax2Smoke.java
              ${buildJdk}/bin/java -cp classes:. Stax2Smoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/org/codehaus/woodstox/stax2-api/${version}"
          mkdir -p "$destination" "$out/share/licenses/stax2-api" \
            "$out/share/source"
          ${buildJdk}/bin/jar --create \
            --file "$destination/stax2-api-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/META-INF/LICENSE "$out/share/licenses/stax2-api/LICENSE"
          cp -R source "$out/share/source/stax2-api"
        '';
      }
    ];
  }
