##! JavaMail API and SMTP classes built from the pinned upstream sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
}: let
  version = "1.6.3";
  buildJdk = buildPackages.openjdk-17;
  activationJar = "${bazelMavenBootstrap}/maven/javax/activation/javax.activation-api/1.2.0/javax.activation-api-1.2.0.jar";
in
  mkDerivation {
    pname = "bazel-mail-api";
    inherit version;
    src = fetchurl {
      urls = ["https://codeload.github.com/jakartaee/mail-api/tar.gz/refs/tags/${version}"];
      hash = "sha256-thWlwMj/HjUYKOri+mZDWKllP7o1EOCoYSr5+xG6lbU=";
    };

    buildDeps = [buildJdk buildPackages.python3 bazelMavenBootstrap];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd mail-api-${version}

          python3 - <<'PY'
          from pathlib import Path

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"),
          )
          for path in Path(".").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled payload in JavaMail source: {path}")
              if path.read_bytes()[:8].startswith(compiled_signatures):
                  raise SystemExit(f"Compiled payload in JavaMail source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p generated/javax/mail classes
          cp mail/src/main/resources/javax/mail/Version.java \
            generated/javax/mail/Version.java
          sed -i 's|version = .*;|version = "${version}";|' \
            generated/javax/mail/Version.java

          find mail/src/main/java smtp/src/main/java generated \
            -name '*.java' ! -name module-info.java -print > java-sources
          javac --release 8 -proc:none -encoding UTF-8 \
            -cp "${activationJar}" -d classes @java-sources
        '';
      }
      {
        name = "install";
        script = ''
          cp -R mail/src/main/resources/. classes/
          cp -R smtp/src/main/resources/. classes/
          rm classes/javax/mail/Version.java

          mkdir -p "$out/share/java" "$out/share/licenses/mail-api"
          jar --create --file "$out/share/java/javax.mail-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp LICENSE.md "$out/share/licenses/mail-api/LICENSE.md"
          cp NOTICE.md "$out/share/licenses/mail-api/NOTICE.md"
        '';
      }
    ];
  }
