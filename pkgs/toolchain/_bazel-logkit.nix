##! Complete historical LogKit source release for Bazel's logging adapters.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
}: let
  version = "1.0.1";
  buildJdk = buildPackages.openjdk-17;
  servletJar = "${bazelMavenBootstrap}/maven/javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar";
  jmsJar = "${bazelMavenBootstrap}/maven/javax/jms/javax.jms-api/2.0.1/javax.jms-api-2.0.1.jar";
in
  mkDerivation {
    pname = "bazel-logkit";
    inherit version;
    src = fetchurl {
      urls = ["https://archive.apache.org/dist/avalon/logkit/v${version}/LogKit-${version}-src.tar.gz"];
      hash = "sha256-u0LkBxNPrL0GdTKzTs/Shfs4FuYJUaqDZCN+t6q/Y68=";
    };

    buildDeps = [buildJdk buildPackages.python3 bazelMavenBootstrap];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd LogKit-${version}

          python3 - <<'PY'
          from pathlib import Path

          compiled_suffixes = {
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip",
          }
          compiled_signatures = (
              bytes.fromhex("cafebabe"), bytes.fromhex("7f454c46"),
              bytes.fromhex("0061736d"), bytes.fromhex("213c617263683e0a"),
              bytes.fromhex("4d5a"), bytes.fromhex("504b0304"),
          )
          for path in Path(".").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix.lower() in compiled_suffixes:
                  raise SystemExit(f"Compiled payload in LogKit source: {path}")
              if path.read_bytes()[:8].startswith(compiled_signatures):
                  raise SystemExit(f"Compiled payload in LogKit source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

                    # LogKit 1.0 predates JDBC's logger and wrapper methods.
                    # Add their standard behavior for modern Java toolchains.
          python3 - <<'PY'
          from pathlib import Path

          path = Path("src/java/org/apache/log/output/db/DefaultDataSource.java")
          source = path.read_text(encoding="ISO-8859-1")
          marker = "\n}"
          assert source.endswith(marker + "\n")
          method = (
              "\n    public java.util.logging.Logger getParentLogger()\n"
              "        throws java.sql.SQLFeatureNotSupportedException\n"
              "    {\n"
              "        throw new java.sql.SQLFeatureNotSupportedException();\n"
                        "    }\n\n"
                        "    public <T> T unwrap(Class<T> iface) throws java.sql.SQLException\n"
                        "    {\n"
                        "        if (iface.isInstance(this)) return iface.cast(this);\n"
                        "        throw new java.sql.SQLException(\"Not a wrapper for \" + iface.getName());\n"
                        "    }\n\n"
                        "    public boolean isWrapperFor(Class<?> iface) throws java.sql.SQLException\n"
                        "    {\n"
                        "        return iface.isInstance(this);\n"
                        "    }"
          )
          path.write_text(source[:-2] + method + marker + "\n", encoding="ISO-8859-1")
          PY

          mkdir -p classes
          # The Avalon formatter needs the framework API, which itself uses
          # LogKit. Compile that bridge after the framework in its derivation.
          find src/java src/compat -name '*.java' \
            ! -path '*/format/AvalonFormatter.java' -print > java-sources
          javac --release 8 -proc:none -encoding ISO-8859-1 \
            -cp "${servletJar}:${jmsJar}" -d classes @java-sources
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/maven/logkit/logkit/${version}" \
            "$out/share/licenses/logkit" "$out/share/sources/logkit"
          jar --create --file "$out/maven/logkit/logkit/${version}/logkit-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp LICENSE "$out/share/licenses/logkit/LICENSE"
          cp src/compat/org/apache/log/format/AvalonFormatter.java \
            "$out/share/sources/logkit/AvalonFormatter.java"
        '';
      }
    ];
  }
