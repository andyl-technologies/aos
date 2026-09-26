##! RELAX NG, ISO RELAX, XSDLib, and MSV rebuilt from their Java sources.
{
  mkDerivation,
  fetchurl,
  fetchgit,
  buildPackages,
  stdenv,
  xmlResolver,
}: let
  buildJdk = buildPackages.openjdk-21;
  msvVersion = "2013.6.1";

  # The published MSV source classifier also contains GIF and VSD files.
  # Fetch only source text from the release commit instead.
  msvSource = fetchgit {
    url = "https://github.com/xmlark/msv.git";
    rev = "83df89e6ad3be5fd1ffeb31a5b556b48c3f518c5";
    name = "msv-${msvVersion}-source-only";
    hash = "sha256-/3dGUVOd2j7kTactbZ3+KuTlLAiCEo+iZNsriy77fB4=";
    deepClone = true;
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/msv/src/main/java/"
      "/msv/src/main/resources/"
      "/xsdlib/src/main/java/"
      "/xsdlib/src/main/resources/"
      "/msv/doc/license.txt"
      "/xsdlib/doc/license.txt"
      "!*.gif"
      "!*.vsd"
    ];
  };

  relaxngSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/relaxngDatatype/relaxngDatatype/20020414/relaxngDatatype-20020414-sources.jar"];
    hash = "sha256-AraIEMzltWBFZhqzBkbxfpk/CmXhwaQOC+OOEvLhA2U=";
  };
  isorelaxSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/sun/xml/bind/jaxb/isorelax/20090621/isorelax-20090621-sources.jar"];
    hash = "sha256-CZtgUhUay2ojDqeYmgFmo4lAW6VqrgdclRi4K3zNZcs=";
  };
  isorelaxPom = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/sun/xml/bind/jaxb/isorelax/20090621/isorelax-20090621.pom"];
    hash = "sha256-zaZFHQIxqXM1K1kv+VDjkiS6a6Gi817qtmURtcIl3/E=";
  };
in
  mkDerivation {
    pname = "bazel-msv-chain";
    version = msvVersion;
    src = msvSource;

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [xmlResolver];

    phases = [
      {
        name = "unpack";
        script = ''
          python3 - "$src" "${relaxngSource}" "${isorelaxSource}" <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import shutil
          import stat
          import sys

          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe", "4d5a",
          ))

          def unpack_java_sources(archive_path, name, allowed_suffixes):
              root = Path("source") / name
              with ZipFile(archive_path) as archive:
                  for member in archive.infolist():
                      path = PurePosixPath(member.filename)
                      kind = stat.S_IFMT(member.external_attr >> 16)
                      if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                          raise SystemExit(f"Unsafe {name} source: {path}")
                      if member.is_dir():
                          continue
                      if path.suffix not in allowed_suffixes and str(path) != "META-INF/MANIFEST.MF":
                          raise SystemExit(f"Unexpected {name} source: {path}")

                      data = archive.read(member)
                      if data.startswith(compiled_signatures):
                          raise SystemExit(f"Compiled {name} source: {path}")
                      data.decode("utf-8")

                      destination = root / str(path)
                      destination.parent.mkdir(parents=True, exist_ok=True)
                      destination.write_bytes(data)

              return root

          relaxng = unpack_java_sources(sys.argv[2], "relaxng", {".java"})
          isorelax = unpack_java_sources(
              sys.argv[3], "isorelax", {".java", ".dtd", ".rxm", ".mod"})
          if len(list(relaxng.rglob("*.java"))) != 10:
              raise SystemExit("Expected 10 RELAX NG datatype sources")
          if len(list(isorelax.rglob("*.java"))) != 42:
              raise SystemExit("Expected 42 ISO RELAX sources")

          upstream = Path(sys.argv[1])
          for project in ("xsdlib", "msv"):
              root = Path("source") / project
              for relative in ("src/main/java", "src/main/resources", "doc/license.txt"):
                  source = upstream / project / relative
                  destination = root / relative
                  if source.is_dir():
                      shutil.copytree(source, destination)
                  else:
                      destination.parent.mkdir(parents=True, exist_ok=True)
                      shutil.copy2(source, destination)

              for path in root.rglob("*"):
                  if not path.is_file():
                      continue
                  if path.suffix not in {".java", ".html", ".properties", ".xsd", ".rlx", ".rng", ".txt"} and path.name != ".cvsignore":
                      raise SystemExit(f"Unexpected {project} source: {path}")
                  data = path.read_bytes()
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled {project} source: {path}")
                  data.decode("utf-8")

          xsdlib_sources = sorted(Path("source/xsdlib/src/main/java").rglob("*.java"))
          msv_sources = sorted(Path("source/msv/src/main/java").rglob("*.java"))
          if len(xsdlib_sources) != 116 or len(msv_sources) != 371:
              raise SystemExit("Unexpected XSDLib or MSV source count")

          # JDK 9 removed this internal alias. The independent Apache library
          # implements the same CatalogResolver constructor and catalog API.
          driver = Path("source/msv/src/main/java/com/sun/msv/driver/textui/Driver.java")
          original = "com.sun.org.apache.xml.internal.resolver.tools.CatalogResolver"
          replacement = "org.apache.xml.resolver.tools.CatalogResolver"
          driver_text = driver.read_text(encoding="utf-8")
          if driver_text.count(original) != 1:
              raise SystemExit("Expected one obsolete JDK catalog resolver import")
          driver.chmod(0o644)
          driver.write_text(driver_text.replace(original, replacement), encoding="utf-8")

          for name, sources in (
              ("relaxng", sorted(relaxng.rglob("*.java"))),
              ("isorelax", sorted(isorelax.rglob("*.java"))),
              ("xsdlib", xsdlib_sources),
              ("msv", msv_sources),
          ):
              Path(f"{name}-sources").write_text(
                  "".join(f"{path}\n" for path in sources), encoding="utf-8")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes/relaxng classes/isorelax classes/xsdlib classes/msv
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -d classes/relaxng @relaxng-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -d classes/isorelax @isorelax-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp classes/relaxng -encoding UTF-8 -d classes/xsdlib @xsdlib-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp "classes/relaxng:classes/isorelax:classes/xsdlib:${xmlResolver}/maven/xml-resolver/xml-resolver/1.2/xml-resolver-1.2.jar" \
            -encoding UTF-8 -d classes/msv @msv-sources

          cp -R source/isorelax/jp/gr/xml/relax/lib classes/isorelax/jp/gr/xml/relax/
          cp -R source/xsdlib/src/main/resources/. classes/xsdlib/
          cp -R source/msv/src/main/resources/. classes/msv/
          cp source/msv/src/main/java/com/sun/msv/reader/relax/core/relaxCore.rlx \
            classes/msv/com/sun/msv/reader/relax/core/
          cp source/msv/src/main/java/com/sun/msv/reader/trex/ng/relaxng.rng \
            classes/msv/com/sun/msv/reader/trex/ng/
          cp source/msv/src/main/java/com/sun/msv/reader/xmlschema/xml.xsd \
            source/msv/src/main/java/com/sun/msv/reader/xmlschema/xmlschema.xsd \
            classes/msv/com/sun/msv/reader/xmlschema/

          mkdir -p classes/xsdlib/META-INF/services classes/msv/META-INF/services
          printf '%s\n' com.sun.msv.datatype.xsd.ngimpl.DataTypeLibraryImpl \
            > classes/xsdlib/META-INF/services/org.relaxng.datatype.DatatypeLibraryFactory
          printf '%s\n' com.sun.msv.verifier.jarv.FactoryLoaderImpl \
            > classes/msv/META-INF/services/org.iso_relax.verifier.VerifierFactoryLoader
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > MsvSmoke.java <<'JAVA'
              import java.io.StringReader;
              import org.xml.sax.InputSource;
              import com.sun.msv.reader.util.GrammarLoader;

              final class MsvSmoke {
                  public static void main(String[] args) throws Exception {
                      String schema = "<element xmlns='http://relaxng.org/ns/structure/1.0' name='release'>"
                              + "<text/></element>";
                      InputSource input = new InputSource(new StringReader(schema));
                      if (GrammarLoader.loadSchema(input) == null) {
                          throw new AssertionError("MSV did not load a RELAX NG schema");
                      }
                  }
              }
              JAVA

              classpath="classes/relaxng:classes/isorelax:classes/xsdlib:classes/msv:${xmlResolver}/maven/xml-resolver/xml-resolver/1.2/xml-resolver-1.2.jar"
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$classpath" MsvSmoke.java
              ${buildJdk}/bin/java -cp "$classpath:." MsvSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          install_jar() {
            component="$1"
            coordinates="$2"
            filename="$3"
            destination="$out/maven/$coordinates"
            mkdir -p "$destination"
            ${buildJdk}/bin/jar --create \
              --file "$destination/$filename" \
              --no-manifest --date=1980-01-01T00:00:02Z \
              -C "classes/$component" .
          }

          install_jar relaxng relaxngDatatype/relaxngDatatype/20020414 relaxngDatatype-20020414.jar
          install_jar isorelax com/sun/xml/bind/jaxb/isorelax/20090621 isorelax-20090621.jar
          install_jar xsdlib org/glassfish/jaxb/xsdlib/${msvVersion} xsdlib-${msvVersion}.jar
          install_jar msv org/glassfish/jaxb/msv-core/${msvVersion} msv-core-${msvVersion}.jar

          mkdir -p "$out/share/source" "$out/share/licenses/msv" "$out/share/licenses/xsdlib"
          cp -R source/. "$out/share/source/"
          cp "${isorelaxPom}" "$out/share/source/isorelax/pom.xml"
          cp source/msv/doc/license.txt "$out/share/licenses/msv/LICENSE"
          cp source/xsdlib/doc/license.txt "$out/share/licenses/xsdlib/LICENSE"
        '';
      }
    ];
  }
