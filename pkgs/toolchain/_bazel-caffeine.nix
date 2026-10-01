##! Complete Caffeine runtime, including upstream's generated cache and node classes.
{
  mkDerivation,
  fetchgit,
  buildPackages,
  bazelMavenBootstrap,
  bazelGoogleJavaFormat,
}: let
  version = "3.1.8";
  buildJdk = buildPackages.openjdk-21;
  source = (import ./_bazel-module-source.nix {inherit fetchgit buildPackages;}) {
    name = "caffeine";
    inherit version;
    url = "https://github.com/ben-manes/caffeine.git";
    ref = "v${version}";
    rev = "b0723da5976ebb52069f6b0cccfcf44186c3fdf3";
    sparseDirectories = ["caffeine/src/main" "caffeine/src/javaPoet"];
    hash = "sha256-1AT58pvqqySZIqk2dZmdEEO9WuOiLh3Z7kPjDDlN5Ic=";
  };
in
  mkDerivation {
    pname = "bazel-caffeine";
    inherit version;
    src = source;

    buildDeps = [
      buildJdk
      bazelMavenBootstrap
      bazelGoogleJavaFormat
      buildPackages.python3
      buildPackages.findutils
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - "$src" <<'PY'
          from pathlib import Path
          import sys

          suffixes = {".jar", ".class", ".so", ".dylib", ".dll", ".a", ".o", ".wasm", ".exe", ".bin"}
          signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a", "4d5a", "504b0304",
          ))
          for path in Path(sys.argv[1]).rglob("*"):
              if path.is_file() and (path.suffix.lower() in suffixes
                      or path.read_bytes()[:8].startswith(signatures)):
                  raise SystemExit(f"Compiled payload in Caffeine source: {path}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"
          classpath=$(find ${bazelMavenBootstrap}/maven ${bazelGoogleJavaFormat}/maven \
            -type f -name '*.jar' -print | sort | paste -sd:)
          module_exports=""
          for package in api code file parser tree util; do
            module_exports="$module_exports --add-exports=jdk.compiler/com.sun.tools.javac.$package=ALL-UNNAMED"
          done

          mkdir generator-classes classes generated-local generated-nodes
          find "$src/caffeine/src/javaPoet/java" -name '*.java' -print > generator-sources
          javac --enable-preview -source 21 -target 21 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d generator-classes @generator-sources
          cp "$src/caffeine/src/javaPoet/resources/license.txt" generator-classes/

          # Both generators are required: cache factories choose their subclasses
          # by reflection, so compiling the handwritten classes alone succeeds
          # but produces a runtime that cannot instantiate bounded caches.
          for generator in LocalCacheFactoryGenerator NodeFactoryGenerator; do
            case "$generator" in
              LocalCacheFactoryGenerator) destination=generated-local ;;
              NodeFactoryGenerator) destination=generated-nodes ;;
            esac
            java --enable-preview $module_exports -cp "generator-classes:$classpath" \
              "com.github.benmanes.caffeine.cache.$generator" "$destination"
          done

          find "$src/caffeine/src/main/java" generated-local generated-nodes \
            -name '*.java' ! -name module-info.java -print > runtime-sources
          javac --release 17 -proc:none -encoding UTF-8 \
            -cp "$classpath" -d classes @runtime-sources
          jar --create --file caffeine-${version}.jar --no-manifest \
            --date=1980-01-01T00:00:02Z -C classes .
        '';
      }
      {
        name = "check";
        script = ''
          cat > CaffeineCheck.java <<'JAVA'
          import com.github.benmanes.caffeine.cache.Caffeine;
          import java.time.Duration;

          public final class CaffeineCheck {
              public static void main(String[] args) {
                  var expiring = Caffeine.newBuilder()
                      .expireAfterAccess(Duration.ofMinutes(1)).build();
                  expiring.put("key", "value");
                  if (!"value".equals(expiring.getIfPresent("key"))) {
                      throw new AssertionError("Access-expiring cache lost its entry");
                  }

                  var weighted = Caffeine.newBuilder().maximumWeight(10)
                      .weigher((Object key, Object value) -> 1).recordStats()
                      .expireAfterWrite(Duration.ofMinutes(1))
                      .refreshAfterWrite(Duration.ofSeconds(1)).build(key -> "loaded");
                  if (!"loaded".equals(weighted.get("key"))) {
                      throw new AssertionError("Weighted loading cache did not load");
                  }

                  Object key = new Object();
                  Object value = new Object();
                  var references = Caffeine.newBuilder().weakKeys().softValues()
                      .maximumSize(10).removalListener((k, v, cause) -> {}).build();
                  references.put(key, value);
                  if (references.getIfPresent(key) != value) {
                      throw new AssertionError("Reference cache lost a live entry");
                  }

                  var asynchronous = Caffeine.newBuilder().maximumSize(10)
                      .expireAfterAccess(Duration.ofMinutes(1)).buildAsync(k -> "async");
                  if (!"async".equals(asynchronous.get("key").join())) {
                      throw new AssertionError("Asynchronous cache did not load");
                  }
              }
          }
          JAVA
          ${buildJdk}/bin/javac --release 17 -cp caffeine-${version}.jar CaffeineCheck.java
          ${buildJdk}/bin/java -cp caffeine-${version}.jar:. CaffeineCheck
        '';
      }
      {
        name = "install";
        script = ''
          install -Dm644 caffeine-${version}.jar \
            "$out/maven/com/github/ben-manes/caffeine/caffeine/${version}/caffeine-${version}.jar"
        '';
      }
    ];
  }
