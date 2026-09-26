##! Tomcat 6 annotations compiled from the selected upstream Java sources.
{
  mkDerivation,
  buildPackages,
}: let
  version = "6.0.53";
  source = ./sources/tomcat-annotations-6.0.53;
  target = "org/apache/tomcat/tomcat-annotations-api/${version}/tomcat-annotations-api-${version}.jar";
  buildJdk = buildPackages.openjdk-17;
in
  mkDerivation {
    pname = "bazel-tomcat-annotations-api";
    inherit version;
    src = source;

    passthru.sourceTargets = [target];

    buildDeps = [buildJdk buildPackages.findutils buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "audit-source";
        script = ''
          python3 - "$src" <<'PY'
          from pathlib import Path
          import sys

          root = Path(sys.argv[1])
          files = [path for path in root.rglob("*") if path.is_file()]
          java = [path for path in files if path.suffix == ".java"]
          allowed = {"LICENSE", "NOTICE", "SOURCE.md"}
          if len(java) != 10:
              raise SystemExit(f"Expected ten Tomcat annotation sources, found {len(java)}")
          for path in files:
              relative = path.relative_to(root).as_posix()
              if relative not in allowed and not (
                  relative.startswith("java/javax/annotation/") and path.suffix == ".java"
              ):
                  raise SystemExit(f"Unexpected Tomcat source file: {relative}")
              data = path.read_bytes()
              if b"\0" in data:
                  raise SystemExit(f"Opaque Tomcat source file: {relative}")
              data.decode("utf-8")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          export JAVA_HOME=${buildJdk}
          export PATH="$JAVA_HOME/bin:$PATH"

          mkdir -p classes
          find "$src/java" -name '*.java' -print > java-sources
          javac --release 8 -proc:none -encoding UTF-8 \
            -d classes @java-sources
        '';
      }
      {
        name = "check";
        script = ''
          cat > TomcatAnnotationsCheck.java <<'JAVA'
          import java.lang.annotation.Retention;
          import java.lang.annotation.RetentionPolicy;
          import javax.annotation.Resource;

          public final class TomcatAnnotationsCheck {
              public static void main(String[] args) {
                  Retention retention = Resource.class.getAnnotation(Retention.class);
                  if (retention == null || retention.value() != RetentionPolicy.RUNTIME) {
                      throw new AssertionError("Resource annotation retention is unavailable");
                  }
              }
          }
          JAVA

          javac --release 8 -cp classes TomcatAnnotationsCheck.java
          java -cp classes:. TomcatAnnotationsCheck
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/maven/$(dirname '${target}')" "$out/share/licenses/tomcat"
          jar --create --file "$out/maven/${target}" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp "$src/LICENSE" "$src/NOTICE" "$out/share/licenses/tomcat/"
        '';
      }
    ];
  }
