##! Jackson annotations, core, and databind rebuilt from source classifiers.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
}: let
  version = "2.13.4";
  buildJdk = buildPackages.openjdk-21;

  annotationsSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/jackson-annotations/${version}/jackson-annotations-${version}-sources.jar"];
    hash = "sha256-95V81GniyA8qMT1XgWyYNBNaUhjgLqpNcNGoH7ScpDc=";
  };
  coreSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/jackson-core/${version}/jackson-core-${version}-sources.jar"];
    hash = "sha256-ar0JyBFuEfwrUbV3FhII5jZLCq9FS8eyAEvZgeMrSGg=";
  };
  databindSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/jackson-databind/${version}/jackson-databind-${version}-sources.jar"];
    hash = "sha256-wauSY8uZ+D8lzG98WhrgjNkAaUZJOwLkV0zctNp5PO8=";
  };
in
  mkDerivation {
    pname = "bazel-jackson-base";
    inherit version;
    src = annotationsSource;

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          python3 - '${annotationsSource}' '${coreSource}' '${databindSource}' <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          inputs = (
              ("annotations", Path(sys.argv[1]), 46),
              ("core", Path(sys.argv[2]), 120),
              ("databind", Path(sys.argv[3]), 455),
          )
          compiled_suffixes = {".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o", ".wasm", ".exe"}
          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe", "4d5a",
          ))

          for name, archive_path, expected_count in inputs:
              with ZipFile(archive_path) as archive:
                  for member in archive.infolist():
                      path = PurePosixPath(member.filename)
                      kind = stat.S_IFMT(member.external_attr >> 16)
                      if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                          raise SystemExit(f"Unsafe Jackson {name} source: {path}")
                      if member.is_dir():
                          continue
                      if path.suffix in compiled_suffixes:
                          raise SystemExit(f"Compiled Jackson {name} source: {path}")

                      data = archive.read(member)
                      if data.startswith(compiled_signatures):
                          raise SystemExit(f"Compiled Jackson {name} source: {path}")
                      data.decode("utf-8")

                      destination = Path("source") / name / str(path)
                      destination.parent.mkdir(parents=True, exist_ok=True)
                      destination.write_bytes(data)

              sources = sorted((Path("source") / name).rglob("*.java"))
              if len(sources) != expected_count:
                  raise SystemExit(f"Expected {expected_count} Jackson {name} sources, found {len(sources)}")
              Path(f"{name}-sources").write_text("".join(f"{path}\n" for path in sources))
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes-annotations classes-core classes-databind

          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -d classes-annotations @annotations-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -cp classes-annotations \
            -d classes-core @core-sources
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -cp classes-annotations:classes-core \
            -d classes-databind @databind-sources

          for name in annotations core databind; do
            mkdir -p "classes-$name/META-INF"
            cp "source/$name/META-INF/LICENSE" "classes-$name/META-INF/LICENSE"
            if [ -f "source/$name/META-INF/NOTICE" ]; then
              cp "source/$name/META-INF/NOTICE" "classes-$name/META-INF/NOTICE"
            fi
            if [ -d "source/$name/META-INF/services" ]; then
              cp -R "source/$name/META-INF/services" "classes-$name/META-INF/"
            fi
          done
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > JacksonBaseSmoke.java <<'JAVA'
              import com.fasterxml.jackson.core.JsonFactory;
              import com.fasterxml.jackson.databind.ObjectMapper;

              final class JacksonBaseSmoke {
                  public static void main(String[] args) throws Exception {
                      ObjectMapper mapper = new ObjectMapper();
                      String encoded = mapper.writeValueAsString(new int[] {1, 2, 3});
                      int[] decoded = mapper.readValue(encoded, int[].class);
                      if (decoded.length != 3 || decoded[1] != 2) {
                          throw new AssertionError("Jackson JSON roundtrip failed");
                      }
                      if (!"${version}".equals(new JsonFactory().version().toString())) {
                          throw new AssertionError("Jackson version metadata is missing");
                      }
                  }
              }
              JAVA

              classpath=classes-annotations:classes-core:classes-databind
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$classpath" JacksonBaseSmoke.java
              ${buildJdk}/bin/java -cp "$classpath:." JacksonBaseSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/source" "$out/share/licenses/jackson-base"
          for name in annotations core databind; do
            artifact="jackson-$name"
            destination="$out/maven/com/fasterxml/jackson/core/$artifact/${version}"
            mkdir -p "$destination" "$out/share/licenses/jackson-base/$artifact"
            ${buildJdk}/bin/jar --create \
              --file "$destination/$artifact-${version}.jar" \
              --no-manifest --date=1980-01-01T00:00:02Z \
              -C "classes-$name" .
            cp "source/$name/META-INF/LICENSE" \
              "$out/share/licenses/jackson-base/$artifact/LICENSE"
            if [ -f "source/$name/META-INF/NOTICE" ]; then
              cp "source/$name/META-INF/NOTICE" \
                "$out/share/licenses/jackson-base/$artifact/NOTICE"
            fi
          done
          cp -R source "$out/share/source/jackson-base"
        '';
      }
    ];
  }
