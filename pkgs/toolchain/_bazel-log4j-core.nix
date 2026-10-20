##! Log4j Core rebuilt with every optional implementation from Java source.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  stdenv,
  bazelMavenBootstrap,
  bazelMailApi,
  bazelJacksonBase,
  bazelJacksonYaml,
  bazelJacksonXml,
  bazelStax2Api,
  bazelWoodstoxCore,
  bazelKafkaClients,
  bazelJeroMq,
  bazelJansi,
  bazelCommonsCsv,
}: let
  version = "2.19.0";
  buildJdk = buildPackages.openjdk-21;
  classpath = builtins.concatStringsSep ":" [
    "${bazelMavenBootstrap}/maven/org/apache/logging/log4j/log4j-api/${version}/log4j-api-${version}.jar"
    "${bazelMavenBootstrap}/maven/org/apache/commons/commons-compress/1.26.1/commons-compress-1.26.1.jar"
    "${bazelMavenBootstrap}/maven/javax/jms/javax.jms-api/2.0.1/javax.jms-api-2.0.1.jar"
    "${bazelMavenBootstrap}/maven/javax/activation/javax.activation-api/1.2.0/javax.activation-api-1.2.0.jar"
    "${bazelMavenBootstrap}/maven/org/osgi/org.osgi.core/4.3.1/org.osgi.core-4.3.1.jar"
    "${bazelMavenBootstrap}/maven/com/lmax/disruptor/3.4.4/disruptor-3.4.4.jar"
    "${bazelMavenBootstrap}/maven/com/conversantmedia/disruptor/1.2.15/disruptor-1.2.15.jar"
    "${bazelMavenBootstrap}/maven/org/jctools/jctools-core/3.3.0/jctools-core-3.3.0.jar"
    "${bazelMavenBootstrap}/maven/org/yaml/snakeyaml/1.28/snakeyaml-1.28.jar"
    "${bazelMailApi}/share/java/javax.mail-1.6.3.jar"
    "${bazelJacksonBase}/maven/com/fasterxml/jackson/core/jackson-annotations/2.13.4/jackson-annotations-2.13.4.jar"
    "${bazelJacksonBase}/maven/com/fasterxml/jackson/core/jackson-core/2.13.4/jackson-core-2.13.4.jar"
    "${bazelJacksonBase}/maven/com/fasterxml/jackson/core/jackson-databind/2.13.4/jackson-databind-2.13.4.jar"
    "${bazelJacksonYaml}/maven/com/fasterxml/jackson/dataformat/jackson-dataformat-yaml/2.13.4/jackson-dataformat-yaml-2.13.4.jar"
    "${bazelJacksonXml}/maven/com/fasterxml/jackson/dataformat/jackson-dataformat-xml/2.13.4/jackson-dataformat-xml-2.13.4.jar"
    "${bazelStax2Api}/maven/org/codehaus/woodstox/stax2-api/4.2.1/stax2-api-4.2.1.jar"
    "${bazelWoodstoxCore}/maven/com/fasterxml/woodstox/woodstox-core/6.3.1/woodstox-core-6.3.1.jar"
    "${bazelKafkaClients}/maven/org/apache/kafka/kafka-clients/1.1.1/kafka-clients-1.1.1.jar"
    "${bazelJeroMq}/maven/org/zeromq/jeromq/0.5.2/jeromq-0.5.2.jar"
    "${bazelJeroMq}/maven/eu/neilalexander/jnacl/1.0.0/jnacl-1.0.0.jar"
    "${bazelJansi}/maven/org/fusesource/jansi/jansi/2.4.0/jansi-2.4.0.jar"
    "${bazelCommonsCsv}/maven/org/apache/commons/commons-csv/1.9.0/commons-csv-1.9.0.jar"
  ];
in
  mkDerivation {
    pname = "bazel-log4j-core";
    inherit version;
    passthru.sourceTargets = ["org/apache/logging/log4j/log4j-core/${version}/log4j-core-${version}.jar"];
    src = fetchurl {
      urls = ["https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-core/${version}/log4j-core-${version}-sources.jar"];
      hash = "sha256-fywGuBy/f7pvxeT2B8e0fL2JPDFc0sI32mW5QcqLEng=";
    };

    buildDeps = [
      buildJdk
      buildPackages.python3
      bazelMavenBootstrap
      bazelMailApi
      bazelJacksonBase
      bazelJacksonYaml
      bazelJacksonXml
      bazelStax2Api
      bazelWoodstoxCore
      bazelKafkaClients
      bazelJeroMq
      bazelJansi
      bazelCommonsCsv
    ];
    runtimeDeps = [
      bazelMavenBootstrap
      bazelMailApi
      bazelJacksonBase
      bazelJacksonYaml
      bazelJacksonXml
      bazelStax2Api
      bazelWoodstoxCore
      bazelKafkaClients
      bazelJeroMq
      bazelJansi
      bazelCommonsCsv
    ];

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
                      raise SystemExit(f"Unsafe Log4j Core source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix not in {".java", ".xsd", ".dtd", ".xml", ".properties"} and path.parts[0] != "META-INF":
                      raise SystemExit(f"Unexpected Log4j Core source: {path}")

                  data = archive.read(member)
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Log4j Core source: {path}")
                  data.decode("utf-8")

                  destination = Path("source") / str(path)
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          sources = sorted(Path("source").rglob("*.java"))
          if len(sources) != 708:
              raise SystemExit(f"Expected 708 Log4j Core sources, found {len(sources)}")
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

          # Compile the in-tree processor first, then emit the plugin index
          # required by XML configuration and every optional appender.
          ${buildJdk}/bin/javac --release 8 -proc:only \
            -processor org.apache.logging.log4j.core.config.plugins.processor.PluginProcessor \
            -processorpath 'classes:${classpath}' \
            -cp 'classes:${classpath}' \
            -encoding UTF-8 -d classes @java-sources
          test -s classes/META-INF/org/apache/logging/log4j/core/config/plugins/Log4j2Plugins.dat

          cp source/META-INF/LICENSE source/META-INF/NOTICE \
            source/META-INF/DEPENDENCIES classes/META-INF/
          cp -R source/META-INF/services classes/META-INF/
          cp source/Log4j-config.xsd source/Log4j-events.dtd \
            source/Log4j-events.xsd source/Log4j-levels.xsd classes/
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > Log4jCoreSmoke.java <<'JAVA'
              import org.apache.logging.log4j.LogManager;
              import org.apache.logging.log4j.Logger;
              import org.apache.logging.log4j.core.config.plugins.util.PluginManager;

              final class Log4jCoreSmoke {
                  public static void main(String[] args) {
                      PluginManager manager = new PluginManager("Core");
                      manager.collectPlugins();
                      if (!manager.getPlugins().containsKey("console")) {
                          throw new AssertionError("Log4j plugin index is missing Console");
                      }
                      Logger logger = LogManager.getLogger(Log4jCoreSmoke.class);
                      if (logger == null) {
                          throw new AssertionError("Log4j Core logger was not created");
                      }
                  }
              }
              JAVA

              check_classpath="classes:${classpath}"
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$check_classpath" Log4jCoreSmoke.java
              ${buildJdk}/bin/java -cp "$check_classpath:." Log4jCoreSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/org/apache/logging/log4j/log4j-core/${version}"
          mkdir -p "$destination" "$out/share/licenses/log4j-core" \
            "$out/share/source" "$out/nix-support"
          ${buildJdk}/bin/jar --create \
            --file "$destination/log4j-core-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp source/META-INF/LICENSE source/META-INF/NOTICE \
            source/META-INF/DEPENDENCIES "$out/share/licenses/log4j-core/"
          cp -R source "$out/share/source/log4j-core"

          # Java loads these classes from JARs that Nix cannot inspect.
          printf '%s\n' \
            '${bazelMavenBootstrap}' '${bazelMailApi}' \
            '${bazelJacksonBase}' '${bazelJacksonYaml}' '${bazelJacksonXml}' \
            '${bazelStax2Api}' '${bazelWoodstoxCore}' \
            '${bazelKafkaClients}' '${bazelJeroMq}' \
            '${bazelJansi}' '${bazelCommonsCsv}' \
            > "$out/nix-support/java-runtime"
        '';
      }
    ];
  }
