##! BlockHound and its optional RxJava integration built from Java sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelByteBuddy,
  bazelMavenBootstrap,
}: let
  version = "1.0.6.RELEASE";
  buildJdk = buildPackages.openjdk-17;
  blockhoundSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/projectreactor/tools/blockhound/${version}/blockhound-${version}-sources.jar"];
    hash = "sha256-K8lx6jXyQ5dGVVAVinIOW06Z4Lf6WjmSCyc3U4Zjwhk=";
  };
  rxjavaSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/reactivex/rxjava2/rxjava/2.2.21/rxjava-2.2.21-sources.jar"];
    hash = "sha256-s5xi9LGGCpYqVfsp7szTMvNDTMOoIk7FG29r8P0XrG8=";
  };
  reactorSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/projectreactor/reactor-core/3.4.7/reactor-core-3.4.7-sources.jar"];
    hash = "sha256-Uk1BOMrjBqDKKaSCo/BJV4OQoKhZn0xSFibQu32svTQ=";
  };
in
  mkDerivation {
    pname = "bazel-blockhound";
    inherit version;
    src = blockhoundSource;

    buildDeps = [
      buildJdk
      bazelByteBuddy
      bazelMavenBootstrap
      buildPackages.findutils
      buildPackages.python3
      buildPackages.unzip
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - ${blockhoundSource} ${rxjavaSource} ${reactorSource} <<'PY'
          import sys
          from zipfile import ZipFile

          compiled_suffixes = (
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          )
          for source_path in sys.argv[1:]:
              with ZipFile(source_path) as source:
                  for member in source.infolist():
                      if member.is_dir():
                          continue
                      if member.filename.lower().endswith(compiled_suffixes):
                          raise SystemExit(f"Compiled payload in {source_path}: {member.filename}")
                      if b"\0" in source.read(member):
                          raise SystemExit(f"Opaque payload in {source_path}: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p blockhound-source rxjava-source reactor-source
          mkdir -p blockhound-classes rxjava-classes reactor-api-classes
          unzip -q ${blockhoundSource} -d blockhound-source
          unzip -q ${rxjavaSource} -d rxjava-source
          unzip -q ${reactorSource} -d reactor-source

          reactiveStreams="${bazelMavenBootstrap}/maven/org/reactivestreams/reactive-streams/1.0.3/reactive-streams-1.0.3.jar"
          find rxjava-source/io -name '*.java' -print > rxjava-sources
          javac --release 8 -proc:none -encoding UTF-8 \
            -cp "$reactiveStreams" -d rxjava-classes @rxjava-sources

          # Reactor is an optional runtime integration. Compile its genuine
          # source interface as an API input without bundling a partial core.
          javac --release 8 -proc:none -encoding UTF-8 \
            -d reactor-api-classes \
            reactor-source/reactor/core/scheduler/NonBlocking.java

          byteBuddy="${bazelByteBuddy}/share/java"
          classpath="$byteBuddy/byte-buddy-dep-1.10.22.jar:$byteBuddy/byte-buddy-agent-1.10.22.jar"
          classpath="$classpath:$byteBuddy/byte-buddy-shaded-asm-1.10.22.jar"
          classpath="$classpath:${bazelMavenBootstrap}/maven/com/google/auto/service/auto-service-annotations/1.0.1/auto-service-annotations-1.0.1.jar"
          classpath="$classpath:rxjava-classes:reactor-api-classes"
          find blockhound-source/reactor -name '*.java' -print > blockhound-sources
          javac --release 8 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d blockhound-classes @blockhound-sources

          mkdir -p blockhound-classes/META-INF/services
          cat > blockhound-classes/META-INF/services/reactor.blockhound.integration.BlockHoundIntegration <<'EOF'
          reactor.blockhound.integration.LoggingIntegration
          reactor.blockhound.integration.ReactorIntegration
          reactor.blockhound.integration.RxJava2Integration
          reactor.blockhound.integration.StandardOutputIntegration
          EOF
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/java"
          mkdir -p rxjava-classes/META-INF/proguard
          cp rxjava-source/META-INF/proguard/rxjava2.pro \
            rxjava-classes/META-INF/proguard/
          jar --create --file "$out/share/java/rxjava-2.2.21.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C rxjava-classes .
          jar --create --file "$out/share/java/blockhound-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C blockhound-classes .
        '';
      }
    ];
  }
