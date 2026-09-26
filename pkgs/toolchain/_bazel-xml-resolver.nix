##! Apache XML Resolver rebuilt from source for the legacy MSV catalog path.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "1.2";
  buildJdk = buildPackages.openjdk-21;
in
  mkDerivation {
    pname = "bazel-xml-resolver";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/xml-resolver/xml-resolver/${version}/xml-resolver-${version}-sources.jar"];
      hash = "sha256-U5FfPFGB7HEtGP3n8TqQxT2UobL2nyC2BEJNuyvlsic=";
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
                      raise SystemExit(f"Unsafe XML Resolver source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix not in {".java", ".html", ".txt", ".xml", ".src"} and str(path) != "META-INF/MANIFEST.MF":
                      raise SystemExit(f"Unexpected XML Resolver source: {path}")

                  data = archive.read(member)
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled XML Resolver source: {path}")
                  data.decode("utf-8")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          production_sources = [path for path in sources if "tests" not in path.parts]
          if len(sources) != 31 or len(production_sources) != 30:
              raise SystemExit("Expected 30 XML Resolver sources and one JUnit test source")
          Path("java-sources").write_text("".join(f"{path}\n" for path in production_sources))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes/META-INF
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -d classes @java-sources
          cp source/org/apache/xml/resolver/LICENSE.resolver.txt \
            classes/META-INF/LICENSE
          cp source/org/apache/xml/resolver/NOTICE-resolver.txt \
            classes/META-INF/NOTICE
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > XmlResolverSmoke.java <<'JAVA'
              import java.io.File;
              import java.nio.charset.StandardCharsets;
              import java.nio.file.Files;
              import org.apache.xml.resolver.tools.CatalogResolver;

              final class XmlResolverSmoke {
                  public static void main(String[] args) throws Exception {
                      File catalogFile = new File("catalog.xml");
                      String catalog = "<?xml version=\"1.0\"?>"
                              + "<catalog xmlns=\"urn:oasis:names:tc:entity:xmlns:xml:catalog\">"
                              + "<system systemId=\"urn:aos:test\" uri=\"file:/tmp/aos-test.dtd\"/>"
                              + "</catalog>";
                      Files.write(catalogFile.toPath(), catalog.getBytes(StandardCharsets.UTF_8));

                      System.setProperty("xml.catalog.ignoreMissing", "yes");
                      CatalogResolver resolver = new CatalogResolver(true);
                      resolver.getCatalog().parseCatalog(catalogFile.getAbsolutePath());
                      String resolved = resolver.getResolvedEntity(null, "urn:aos:test");
                      if (!"file:/tmp/aos-test.dtd".equals(resolved)) {
                          throw new AssertionError("XML catalog resolution failed: " + resolved);
                      }
                  }
              }
              JAVA

              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp classes XmlResolverSmoke.java
              ${buildJdk}/bin/java -cp classes:. XmlResolverSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/xml-resolver/xml-resolver/${version}"
          mkdir -p "$destination" "$out/share/licenses/xml-resolver" \
            "$out/share/source"
          ${buildJdk}/bin/jar --create \
            --file "$destination/xml-resolver-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/org/apache/xml/resolver/LICENSE.resolver.txt \
            "$out/share/licenses/xml-resolver/LICENSE"
          cp source/org/apache/xml/resolver/NOTICE-resolver.txt \
            "$out/share/licenses/xml-resolver/NOTICE"
          cp -R source "$out/share/source/xml-resolver"
        '';
      }
    ];
  }
