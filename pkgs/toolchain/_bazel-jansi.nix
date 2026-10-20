##! Jansi Java and JNI rebuilt from a sparse source-only release checkout.
{
  mkDerivation,
  fetchgit,
  buildPackages,
  stdenv,
}: let
  version = "2.4.0";
  buildJdk = buildPackages.openjdk-21;
  nativeTarget =
    if stdenv.hostPlatform.system == "x86_64-linux"
    then "Linux/x86_64"
    else if stdenv.hostPlatform.system == "aarch64-linux"
    then "Linux/arm64"
    else if stdenv.hostPlatform.system == "x86_64-darwin"
    then "Mac/x86_64"
    else if stdenv.hostPlatform.system == "aarch64-darwin"
    then "Mac/arm64"
    else throw "Jansi ${version} has no native target for ${stdenv.hostPlatform.system}";
  nativeLibrary =
    if stdenv.hostPlatform.isDarwin
    then "libjansi.jnilib"
    else "libjansi.so";
  nativeLinkFlag =
    if stdenv.hostPlatform.isDarwin
    then "-dynamiclib"
    else "-shared";
in
  mkDerivation {
    pname = "bazel-jansi";
    inherit version;
    src = fetchgit {
      url = "https://github.com/fusesource/jansi.git";
      rev = "165d4e0617362fe9d05f626d2b4b290cbaa65c63";
      name = "jansi-${version}-source-only";
      hash = "sha256-Y8KzF0PAO7BoTJGyJSzeyGKDIpnJoHOYdtVOUeiaD50=";
      deepClone = true;
      git = buildPackages.git-minimal;
      caCertificates = buildPackages.ca-certificates;
      coreutils = buildPackages.coreutils;
      sparsePatterns = [
        "/src/main/java/"
        "/src/main/native/"
        "/src/main/resources/META-INF/native-image/"
        "/src/main/resources/org/fusesource/jansi/jansi.properties"
        "/src/main/resources/org/fusesource/jansi/jansi.txt"
        "/license.txt"
      ];
    };

    buildDeps = [buildJdk buildPackages.python3];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source
          cp -R "$src"/. source/

          python3 - <<'PY'
          from pathlib import Path

          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe", "4d5a",
          ))
          root = Path("source")
          for path in root.rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix not in {".java", ".c", ".h", ".txt", ".properties", ".json"}:
                  raise SystemExit(f"Unexpected Jansi source: {path}")
              data = path.read_bytes()
              if data.startswith(compiled_signatures):
                  raise SystemExit(f"Compiled Jansi source: {path}")
              data.decode("utf-8")

          java_sources = sorted(root.glob("src/main/java/**/*.java"))
          native_sources = sorted(root.glob("src/main/native/*.c"))
          if len(java_sources) != 19 or len(native_sources) != 4:
              raise SystemExit("Expected 19 Jansi Java sources and four JNI C sources")
          Path("java-sources").write_text(
              "".join(f"{path}\n" for path in java_sources), encoding="utf-8")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          mkdir -p classes/org/fusesource/jansi/internal/native/${nativeTarget}
          ${buildJdk}/bin/javac --release 8 -proc:none \
            -encoding UTF-8 -d classes @java-sources

          cc -O2 -fPIC ${nativeLinkFlag} \
            -Isource/src/main/native \
            source/src/main/native/jansi.c \
            source/src/main/native/jansi_isatty.c \
            source/src/main/native/jansi_structs.c \
            source/src/main/native/jansi_ttyname.c \
            -o classes/org/fusesource/jansi/internal/native/${nativeTarget}/${nativeLibrary}

          cp -R source/src/main/resources/. classes/
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > JansiSmoke.java <<'JAVA'
              import org.fusesource.jansi.AnsiRenderer;
              import org.fusesource.jansi.internal.CLibrary;

              final class JansiSmoke {
                  public static void main(String[] args) {
                      if (!CLibrary.LOADED || !CLibrary.HAVE_ISATTY) {
                          throw new AssertionError("Source-built Jansi JNI was not loaded");
                      }
                      int terminal = CLibrary.isatty(CLibrary.STDOUT_FILENO);
                      if (terminal != 0 && terminal != 1) {
                          throw new AssertionError("Jansi JNI returned an invalid terminal status");
                      }
                      if (!AnsiRenderer.render("@|red release|@").contains("release")) {
                          throw new AssertionError("Jansi ANSI renderer failed");
                      }
                  }
              }
              JAVA

              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp classes JansiSmoke.java
              ${buildJdk}/bin/java -cp classes:. JansiSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/org/fusesource/jansi/jansi/${version}"
          mkdir -p "$destination" "$out/lib" "$out/share/licenses/jansi" \
            "$out/share/source"
          ${buildJdk}/bin/jar --create \
            --file "$destination/jansi-${version}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C classes .
          cp "classes/org/fusesource/jansi/internal/native/${nativeTarget}/${nativeLibrary}" \
            "$out/lib/${nativeLibrary}"
          cp source/license.txt "$out/share/licenses/jansi/LICENSE"
          cp -R source "$out/share/source/jansi"
        '';
      }
    ];
  }
