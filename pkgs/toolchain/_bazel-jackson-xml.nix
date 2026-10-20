##! Jackson XML rebuilt from source with the complete source-built Woodstox stack.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  bazelJacksonBase,
  bazelStax2Api,
  bazelWoodstoxCore,
}: let
  version = "2.13.4";
  buildJdk = buildPackages.openjdk-21;
  classpath = builtins.concatStringsSep ":" [
    "${bazelJacksonBase}/maven/com/fasterxml/jackson/core/jackson-annotations/${version}/jackson-annotations-${version}.jar"
    "${bazelJacksonBase}/maven/com/fasterxml/jackson/core/jackson-core/${version}/jackson-core-${version}.jar"
    "${bazelJacksonBase}/maven/com/fasterxml/jackson/core/jackson-databind/${version}/jackson-databind-${version}.jar"
    "${bazelStax2Api}/maven/org/codehaus/woodstox/stax2-api/4.2.1/stax2-api-4.2.1.jar"
    "${bazelWoodstoxCore}/maven/com/fasterxml/woodstox/woodstox-core/6.3.1/woodstox-core-6.3.1.jar"
  ];
in
  mkDerivation {
    pname = "bazel-jackson-xml";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/com/fasterxml/jackson/dataformat/jackson-dataformat-xml/${version}/jackson-dataformat-xml-${version}-sources.jar"];
      hash = "sha256-3U6NbC2glWBWxbdqvsZkcTHs9gb3SBG3JVTUmIv7ac0=";
    };

    buildDeps = [buildJdk buildPackages.python3 bazelJacksonBase bazelStax2Api bazelWoodstoxCore];
    runtimeDeps = [bazelJacksonBase bazelStax2Api bazelWoodstoxCore];

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
                      raise SystemExit(f"Unsafe Jackson XML source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix not in {".java", ".in", ".xml", ".properties"} and path.parts[0] != "META-INF":
                      raise SystemExit(f"Unexpected Jackson XML source: {path}")

                  data = archive.read(member)
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Jackson XML source: {path}")
                  data.decode("utf-8")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 40:
              raise SystemExit(f"Expected 40 Jackson XML sources, found {len(sources)}")
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
          cp source/META-INF/LICENSE source/META-INF/NOTICE classes/META-INF/
          cp -R source/META-INF/services classes/META-INF/
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > JacksonXmlSmoke.java <<'JAVA'
              import com.fasterxml.jackson.dataformat.xml.XmlFactory;
              import com.fasterxml.jackson.dataformat.xml.XmlMapper;

              final class JacksonXmlSmoke {
                  public static final class Payload {
                      public int release;

                      public Payload() {}
                  }

                  public static void main(String[] args) throws Exception {
                      XmlMapper mapper = new XmlMapper();
                      Payload input = new Payload();
                      input.release = 1;
                      String encoded = mapper.writeValueAsString(input);
                      Payload decoded = mapper.readValue(encoded, Payload.class);
                      if (decoded.release != 1) {
                          throw new AssertionError("Jackson XML roundtrip failed");
                      }
                      if (!"${version}".equals(new XmlFactory().version().toString())) {
                          throw new AssertionError("Jackson XML version metadata is missing");
                      }
                  }
              }
              JAVA

              check_classpath="classes:${classpath}"
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$check_classpath" JacksonXmlSmoke.java
              ${buildJdk}/bin/java -cp "$check_classpath:." JacksonXmlSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/com/fasterxml/jackson/dataformat/jackson-dataformat-xml/${version}"
          mkdir -p "$destination" "$out/share/licenses/jackson-xml" \
            "$out/share/source" "$out/nix-support"
          ${buildJdk}/bin/jar --create \
            --file "$destination/jackson-dataformat-xml-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/META-INF/LICENSE source/META-INF/NOTICE \
            "$out/share/licenses/jackson-xml/"
          cp -R source "$out/share/source/jackson-xml"

          # Java loads these classes from JARs that Nix cannot inspect.
          printf '%s\n' '${bazelJacksonBase}' '${bazelStax2Api}' '${bazelWoodstoxCore}' \
            > "$out/nix-support/java-runtime"
        '';
      }
    ];
  }
