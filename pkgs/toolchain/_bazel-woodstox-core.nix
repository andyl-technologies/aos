##! Woodstox XML implementation rebuilt with its validation and OSGi features.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  bazelStax2Api,
  bazelMsvChain,
  bazelBndAnnotation,
  bazelMavenBootstrap,
}: let
  version = "6.3.1";
  buildJdk = buildPackages.openjdk-21;
  classpath = builtins.concatStringsSep ":" [
    "${bazelStax2Api}/maven/org/codehaus/woodstox/stax2-api/4.2.1/stax2-api-4.2.1.jar"
    "${bazelMsvChain}/maven/relaxngDatatype/relaxngDatatype/20020414/relaxngDatatype-20020414.jar"
    "${bazelMsvChain}/maven/com/sun/xml/bind/jaxb/isorelax/20090621/isorelax-20090621.jar"
    "${bazelMsvChain}/maven/org/glassfish/jaxb/xsdlib/2013.6.1/xsdlib-2013.6.1.jar"
    "${bazelMsvChain}/maven/org/glassfish/jaxb/msv-core/2013.6.1/msv-core-2013.6.1.jar"
    "${bazelBndAnnotation}/maven/biz/aQute/bnd/biz.aQute.bnd.annotation/6.3.1/biz.aQute.bnd.annotation-6.3.1.jar"
    "${bazelBndAnnotation}/maven/org/osgi/osgi.annotation/8.1.0/osgi.annotation-8.1.0.jar"
    "${bazelBndAnnotation}/maven/org/osgi/org.osgi.dto/1.0.0/org.osgi.dto-1.0.0.jar"
    "${bazelBndAnnotation}/maven/org/osgi/org.osgi.resource/1.0.0/org.osgi.resource-1.0.0.jar"
    "${bazelBndAnnotation}/maven/org/osgi/org.osgi.namespace.extender/1.0.1/org.osgi.namespace.extender-1.0.1.jar"
    "${bazelBndAnnotation}/maven/org/osgi/org.osgi.namespace.service/1.0.0/org.osgi.namespace.service-1.0.0.jar"
    "${bazelBndAnnotation}/maven/org/osgi/org.osgi.service.serviceloader/1.0.0/org.osgi.service.serviceloader-1.0.0.jar"
    "${bazelMavenBootstrap}/maven/org/osgi/org.osgi.core/4.3.1/org.osgi.core-4.3.1.jar"
  ];
in
  mkDerivation {
    pname = "bazel-woodstox-core";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/com/fasterxml/woodstox/woodstox-core/${version}/woodstox-core-${version}-sources.jar"];
      hash = "sha256-2idUkC5lGuezOAd8u3HJ2Iut+FCFjPH1PrsgFNqKo2Y=";
    };

    buildDeps = [
      buildJdk
      buildPackages.python3
      bazelStax2Api
      bazelMsvChain
      bazelBndAnnotation
      bazelMavenBootstrap
    ];
    runtimeDeps = [bazelStax2Api bazelMsvChain bazelBndAnnotation bazelMavenBootstrap];

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
                      raise SystemExit(f"Unsafe Woodstox source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix not in {".java", ".html", ".xml", ".properties"} and path.name not in {
                      "LICENSE", "MANIFEST.MF", "org.codehaus.stax2.validation.XMLValidationSchemaFactory.w3c",
                      "org.codehaus.stax2.validation.XMLValidationSchemaFactory.relaxng",
                      "org.codehaus.stax2.validation.XMLValidationSchemaFactory.dtd",
                      "org.codehaus.stax2.validation.XMLValidationSchemaFactory",
                      "javax.xml.stream.XMLEventFactory", "javax.xml.stream.XMLInputFactory",
                      "javax.xml.stream.XMLOutputFactory",
                  }:
                      raise SystemExit(f"Unexpected Woodstox source: {path}")

                  data = archive.read(member)
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Woodstox source: {path}")
                  data.decode("utf-8")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 178:
              raise SystemExit(f"Expected 178 Woodstox Java sources, found {len(sources)}")
          Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes/META-INF
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -cp '${classpath}' -encoding UTF-8 -d classes @java-sources
          cp -R source/META-INF/services classes/META-INF/
          cp source/META-INF/LICENSE classes/META-INF/LICENSE
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > WoodstoxSmoke.java <<'JAVA'
              import java.io.StringReader;
              import javax.xml.stream.XMLInputFactory;
              import org.codehaus.stax2.XMLStreamReader2;
              import org.codehaus.stax2.validation.XMLValidationSchema;
              import org.codehaus.stax2.validation.XMLValidationSchemaFactory;

              final class WoodstoxSmoke {
                  public static void main(String[] args) throws Exception {
                      XMLInputFactory factory = XMLInputFactory.newFactory();
                      if (!factory.getClass().getName().equals("com.ctc.wstx.stax.WstxInputFactory")) {
                          throw new AssertionError("Woodstox service provider was not loaded");
                      }

                      String schema = "<element xmlns='http://relaxng.org/ns/structure/1.0' name='release'>"
                              + "<text/></element>";
                      XMLValidationSchemaFactory validationFactory = XMLValidationSchemaFactory
                              .newInstance(XMLValidationSchema.SCHEMA_ID_RELAXNG);
                      XMLValidationSchema validation = validationFactory.createSchema(new StringReader(schema));
                      XMLStreamReader2 reader = (XMLStreamReader2) factory
                              .createXMLStreamReader(new StringReader("<release>testing</release>"));
                      reader.validateAgainst(validation);
                      while (reader.hasNext()) {
                          reader.next();
                      }
                      reader.close();
                  }
              }
              JAVA

              classpath="classes:${classpath}"
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$classpath" WoodstoxSmoke.java
              ${buildJdk}/bin/java -cp "$classpath:." WoodstoxSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/com/fasterxml/woodstox/woodstox-core/${version}"
          mkdir -p "$destination" "$out/share/licenses/woodstox" "$out/share/source"
          ${buildJdk}/bin/jar --create \
            --file "$destination/woodstox-core-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/META-INF/LICENSE "$out/share/licenses/woodstox/LICENSE"
          cp -R source "$out/share/source/woodstox-core"
        '';
      }
    ];
  }
