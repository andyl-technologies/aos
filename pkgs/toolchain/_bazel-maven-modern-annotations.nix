##! Updated annotation and small utility Maven libraries built from Java sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  includeBazel9 ? false,
}: let
  buildJdk = buildPackages.openjdk-17;
  archives =
    (
      if includeBazel9
      then [
        {
          group = "com/google/errorprone";
          name = "error_prone_annotations";
          version = "2.41.0";
          hash = "sha256-iIW8y0J31N54XajlzZuGEMwS+zdAd2dBVVY5r7kuyEk=";
        }
        {
          group = "com/google/j2objc";
          name = "j2objc-annotations";
          version = "3.1";
          hash = "sha256-KVk4MH9AFrPxKPc0cQGyNq2hOUgIEEUZyek81htkYCs=";
        }
      ]
      else []
    )
    ++ [
      {
        group = "com/google/errorprone";
        name = "error_prone_type_annotations";
        version = "2.32.0";
        hash = "sha256-vri5GTMvfsR+CQVrl2FL+eATBQ912r2IvL9l9f9kitQ=";
      }
      {
        group = "com/google/guava";
        name = "failureaccess";
        version = "1.0.3";
        hash = "sha256-b+9N/S65+WFlXyo8Tqh8AjYY2fy/trEEwXhi5a/ma5c=";
      }
      {
        group = "com/google/j2objc";
        name = "j2objc-annotations";
        version = "3.0.0";
        hash = "sha256-vWABmgQjw6Al72qyT+B2H19F/7SKjMp0oBtnjeEQXTg=";
      }
      {
        group = "org/checkerframework";
        name = "checker-qual";
        version = "3.42.0";
        hash = "sha256-77ZetHn2H1PG3K+9Qu1Z2tCbCg1af0S3vGjfJcLc+P0=";
      }
      {
        group = "org/codehaus/mojo";
        name = "animal-sniffer-annotations";
        version = "1.24";
        hash = "sha256-QnDOVTHtDxLkI04I8kDvO0XuPO6xbijUSrxhwSz1Iso=";
      }
      {
        group = "io/perfmark";
        name = "perfmark-api";
        version = "0.27.0";
        hash = "sha256-MRVRqynPUeWoq+5qAZ6I3uR9Hqcd65/NNknbnFGyN7w=";
      }
    ]
    ++ (
      if includeBazel9
      then [
        {
          group = "com/github/ben-manes/caffeine";
          name = "caffeine";
          version = "3.1.8";
          hash = "sha256-fII39djyNlTnCRBWMWo3MGNreg8ub85FDivVIgkNa38=";
          javaRelease = 17;
        }
      ]
      else []
    );
  sources = builtins.map (archive:
    archive
    // {
      src = fetchurl {
        urls = ["https://repo.maven.apache.org/maven2/${archive.group}/${archive.name}/${archive.version}/${archive.name}-${archive.version}-sources.jar"];
        inherit (archive) hash;
      };
      target = "${archive.group}/${archive.name}/${archive.version}/${archive.name}-${archive.version}.jar";
    })
  archives;
  sourcePaths = builtins.concatStringsSep " " (builtins.map (source: toString source.src) sources);
  buildSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      mkdir -p source-${source.name}-${source.version} classes-${source.name}-${source.version}
      unzip -q ${source.src} -d source-${source.name}-${source.version}
      find source-${source.name}-${source.version} -name '*.java' ! -name module-info.java \
        -print > sources-${source.name}-${source.version}
      javac --release ${toString (source.javaRelease or 8)} -proc:none -encoding UTF-8 \
        -cp "classes-checker-qual-3.42.0:${bazelMavenBootstrap}/maven/com/google/errorprone/error_prone_annotations/2.36.0/error_prone_annotations-2.36.0.jar" \
        -d classes-${source.name}-${source.version} @sources-${source.name}-${source.version}

      find source-${source.name}-${source.version} -type f ! -name '*.java' \
        ! -path '*/META-INF/MANIFEST.MF' -print | while IFS= read -r resource; do
          destination="classes-${source.name}-${source.version}/''${resource#source-${source.name}-${source.version}/}"
          mkdir -p "$(dirname "$destination")"
          cp "$resource" "$destination"
        done

      jar --create --file ${source.name}-${source.version}.jar --no-manifest \
        --date=1980-01-01T00:00:02Z -C classes-${source.name}-${source.version} .
    '')
    sources);
  installSources = builtins.concatStringsSep "\n" (builtins.map (source: ''
      install -Dm644 ${source.name}-${source.version}.jar "$out/maven/${source.target}"
    '')
    sources);
in
  mkDerivation {
    pname = "bazel-maven-modern-annotations";
    version = "1";
    src = (builtins.head sources).src;

    passthru.sourceTargets = builtins.map (source: source.target) sources;

    buildDeps = [
      buildJdk
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
          python3 - ${sourcePaths} <<'PY'
          import sys
          from zipfile import ZipFile

          compiled_suffixes = (
              ".class", ".jar", ".so", ".dylib", ".dll", ".a", ".o",
              ".wasm", ".exe", ".bin", ".zip", ".tar", ".gz", ".xz",
          )
          for source_path in sys.argv[1:]:
              with ZipFile(source_path) as archive:
                  for member in archive.infolist():
                      if member.is_dir():
                          continue
                      if member.filename.lower().endswith(compiled_suffixes):
                          raise SystemExit(f"Compiled payload in {source_path}: {member.filename}")
                      if b"\0" in archive.read(member):
                          raise SystemExit(f"Opaque payload in {source_path}: {member.filename}")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          ${buildSources}
        '';
      }
      {
        name = "check";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"
          classpath=$(find . -maxdepth 1 -name '*.jar' -print | sort | paste -sd:)

          cat > AnnotationCheck.java <<'JAVA'
          public final class AnnotationCheck {
              public static void main(String[] args) throws Exception {
                  String[] names = {
                      "com.google.errorprone.annotations.ImmutableTypeParameter",
                      "com.google.common.util.concurrent.internal.InternalFutureFailureAccess",
                      "com.google.j2objc.annotations.ObjectiveCName",
                      "org.checkerframework.checker.nullness.qual.NonNull",
                      "org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement",
                      "io.perfmark.PerfMark",
                  };
                  for (String name : names) {
                      Class.forName(name);
                  }
              }
          }
          JAVA

          javac --release 8 -cp "$classpath" AnnotationCheck.java
          java -cp "$classpath:." AnnotationCheck
        '';
      }
      {
        name = "install";
        script = installSources;
      }
    ];
  }
