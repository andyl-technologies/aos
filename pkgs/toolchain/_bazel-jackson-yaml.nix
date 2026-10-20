##! Jackson YAML rebuilt from its source classifier and source-built dependencies.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelJacksonBase,
  bazelMavenBootstrap,
  stdenv,
}: let
  version = "2.13.4";
  buildJdk = buildPackages.openjdk-21;
  jacksonClasspath = builtins.concatStringsSep ":" [
    "${bazelJacksonBase}/maven/com/fasterxml/jackson/core/jackson-annotations/${version}/jackson-annotations-${version}.jar"
    "${bazelJacksonBase}/maven/com/fasterxml/jackson/core/jackson-core/${version}/jackson-core-${version}.jar"
    "${bazelJacksonBase}/maven/com/fasterxml/jackson/core/jackson-databind/${version}/jackson-databind-${version}.jar"
  ];
  snakeYamlJar = "${bazelMavenBootstrap}/maven/org/yaml/snakeyaml/1.28/snakeyaml-1.28.jar";
  runtimeClasspath = "${jacksonClasspath}:${snakeYamlJar}";
in
  mkDerivation {
    pname = "bazel-jackson-yaml";
    inherit version;
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/com/fasterxml/jackson/dataformat/jackson-dataformat-yaml/${version}/jackson-dataformat-yaml-${version}-sources.jar"];
      hash = "sha256-PeBZrLGq+fqoFawaJish/qBgG4A9VYFypS++1eI3n5Y=";
    };

    buildDeps = [buildJdk buildPackages.python3 bazelJacksonBase bazelMavenBootstrap];
    runtimeDeps = [bazelJacksonBase bazelMavenBootstrap];

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
                      raise SystemExit(f"Unsafe Jackson YAML source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix not in {".java", ".in"} and path.parts[0] != "META-INF":
                      raise SystemExit(f"Unexpected Jackson YAML source: {path}")

                  data = archive.read(member)
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Jackson YAML source: {path}")
                  data.decode("utf-8")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 16:
              raise SystemExit(f"Expected 16 Jackson YAML sources, found {len(sources)}")
          Path("java-sources").write_text("".join(f"{path}\n" for path in sources))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes/META-INF
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -cp ${runtimeClasspath} \
            -d classes @java-sources

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
              cat > JacksonYamlSmoke.java <<'JAVA'
              import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
              import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
              import java.util.Collections;
              import java.util.Map;

              final class JacksonYamlSmoke {
                  public static void main(String[] args) throws Exception {
                      YAMLMapper mapper = new YAMLMapper();
                      String encoded = mapper.writeValueAsString(Collections.singletonMap("release", 1));
                      Map<?, ?> decoded = mapper.readValue(encoded, Map.class);
                      if (!Integer.valueOf(1).equals(decoded.get("release"))) {
                          throw new AssertionError("Jackson YAML roundtrip failed");
                      }
                      if (!"${version}".equals(new YAMLFactory().version().toString())) {
                          throw new AssertionError("Jackson YAML version metadata is missing");
                      }
                  }
              }
              JAVA

              checkClasspath="classes:${runtimeClasspath}"
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$checkClasspath" JacksonYamlSmoke.java
              ${buildJdk}/bin/java -cp "$checkClasspath:." JacksonYamlSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/com/fasterxml/jackson/dataformat/jackson-dataformat-yaml/${version}"
          mkdir -p "$destination" "$out/share/licenses/jackson-yaml" \
            "$out/share/source" "$out/nix-support"
          ${buildJdk}/bin/jar --create \
            --file "$destination/jackson-dataformat-yaml-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/META-INF/LICENSE source/META-INF/NOTICE \
            "$out/share/licenses/jackson-yaml/"
          cp -R source "$out/share/source/jackson-yaml"

          # Java loads these classes from JARs that Nix cannot inspect.
          printf '%s\n' '${bazelJacksonBase}' '${bazelMavenBootstrap}' \
            > "$out/nix-support/java-runtime"
        '';
      }
    ];
  }
