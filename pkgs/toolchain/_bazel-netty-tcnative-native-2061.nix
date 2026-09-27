##! Netty TCNative BoringSSL JNI rebuilt from release C source.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  stdenv,
  apr,
  bazelNettyBoringssl2061,
  bazelNettyTcnativeClasses2061,
}: let
  version = "2.0.61.Final";
  buildJdk = buildPackages.openjdk-21;
  nativeTarget =
    if stdenv.hostPlatform.system == "x86_64-linux"
    then "linux_x86_64"
    else if stdenv.hostPlatform.system == "aarch64-linux"
    then "linux_aarch_64"
    else if stdenv.hostPlatform.system == "x86_64-darwin"
    then "osx_x86_64"
    else if stdenv.hostPlatform.system == "aarch64-darwin"
    then "osx_aarch_64"
    else throw "Netty TCNative has no source build for ${stdenv.hostPlatform.system}";
  classifier = builtins.replaceStrings ["linux_" "osx_"] ["linux-" "osx-"] nativeTarget;
  nativeLibrary =
    "libnetty_tcnative_${nativeTarget}."
    + (
      if stdenv.hostPlatform.isDarwin
      then "jnilib"
      else "so"
    );
  linkFlags =
    if stdenv.hostPlatform.isDarwin
    then "-dynamiclib -Wl,-undefined,dynamic_lookup"
    else "-shared -ldl -pthread";
  jniUtilSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/netty/netty-jni-util/0.0.6.Final/netty-jni-util-0.0.6.Final-sources.jar"];
    hash = "sha256-CbvbrDHP2QIubN18npILENi0ui+CZD24wzoDvC8qGJM=";
  };
in
  mkDerivation {
    pname = "bazel-netty-tcnative-native";
    inherit version;

    src = fetchgit {
      url = "https://github.com/netty/netty-tcnative.git";
      rev = "ea87032e1dd058f7d3d5a8c5d1852e690a5142a3";
      name = "netty-tcnative-${version}-native-source-only";
      hash = "sha256-pxJ2Q//Z/ByQcNZhhxcV2octR9zdKH34pr6vf/bWxxc=";
      deepClone = true;
      git = buildPackages.git-minimal;
      caCertificates = buildPackages.ca-certificates;
      coreutils = buildPackages.coreutils;
      sparsePatterns = [
        "/openssl-dynamic/src/main/c/"
        "/LICENSE.txt"
        "/NOTICE.txt"
      ];
    };

    buildDeps = [
      buildJdk
      buildPackages.python3
      bazelNettyTcnativeClasses2061
    ];
    runtimeDeps = [apr bazelNettyBoringssl2061 bazelNettyTcnativeClasses2061];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir source
          cp -R "$src"/. source/

          python3 - "${jniUtilSource}" <<'PY'
          from pathlib import Path, PurePosixPath
          from zipfile import ZipFile
          import stat
          import sys

          files = [path for path in Path("source").rglob("*") if path.is_file()]
          if len(files) != 28:
            raise SystemExit(f"Unexpected Netty TCNative C source inventory: {len(files)}")
          for path in files:
              if path.suffix not in {".c", ".cpp", ".h", ".txt"}:
                  raise SystemExit(f"Unexpected Netty TCNative source: {path}")
              path.read_text(encoding="utf-8")

          with ZipFile(sys.argv[1]) as archive:
              for member in archive.infolist():
                  path = PurePosixPath(member.filename)
                  kind = stat.S_IFMT(member.external_attr >> 16)
                  if path.is_absolute() or ".." in path.parts or kind == stat.S_IFLNK:
                      raise SystemExit(f"Unsafe Netty JNI utility source: {path}")
                  if member.is_dir():
                      continue
                  if path.suffix not in {".c", ".h", ".java", ".xml", ".properties"} and str(path) != "META-INF/MANIFEST.MF":
                      raise SystemExit(f"Unexpected Netty JNI utility source: {path}")
                  data = archive.read(member)
                  data.decode("utf-8")
                  if path.name not in {"netty_jni_util.c", "netty_jni_util.h"}:
                      continue
                  destination = Path("source/jni-util") / path.name
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)
          PY
        '';
      }
      {
        name = "build";
        script = ''
          native=source/openssl-dynamic/src/main/c
          mkdir -p objects native-jar/META-INF/native
          for input in "$native"/*.c "$native"/*.cpp source/jni-util/netty_jni_util.c; do
            object="objects/$(basename "''${input%.*}").o"
            case "$input" in
              *.cpp) compiler=c++ ;;
              *) compiler=cc ;;
            esac
            "$compiler" -O2 -fPIC -fvisibility=hidden -DHAVE_OPENSSL \
              -I${buildJdk}/include -I${buildJdk}/include/linux \
              -I${apr}/include/apr-1 -I${bazelNettyBoringssl2061}/include \
              -I"$native" -Isource/jni-util \
              -c "$input" -o "$object"
          done

          c++ ${linkFlags} objects/*.o \
            ${bazelNettyBoringssl2061}/lib/libssl.a \
            ${bazelNettyBoringssl2061}/lib/libcrypto.a \
            ${apr}/lib/libapr-1.a \
            -o "native-jar/META-INF/native/${nativeLibrary}"
        '';
      }
      {
        name = "check";
        script = ''
          nm -g "native-jar/META-INF/native/${nativeLibrary}" \
            | grep -E ' (_)?JNI_OnLoad$' > jni-exports
          test -s jni-exports
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > NettyTlsSmoke.java <<'JAVA'
              import io.netty.internal.tcnative.Library;

              final class NettyTlsSmoke {
                  public static void main(String[] args) throws Exception {
                      System.load(args[0]);
                      if (!Library.initialize()) {
                          throw new AssertionError("Source-built Netty TLS JNI did not initialize");
                      }
                  }
              }
              JAVA
              classes=${bazelNettyTcnativeClasses2061}/share/java/netty-tcnative-classes-${version}.jar
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$classes" NettyTlsSmoke.java
              ${buildJdk}/bin/java -cp "$classes:." NettyTlsSmoke \
                "$PWD/native-jar/META-INF/native/${nativeLibrary}"
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/io/netty/netty-tcnative-boringssl-static/${version}"
          mkdir -p "$destination" "$out/lib" "$out/share/licenses/netty-tcnative" \
            "$out/share/source" "$out/nix-support"
          ${buildJdk}/bin/jar --create \
            --file "$destination/netty-tcnative-boringssl-static-${version}-${classifier}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C native-jar .
          cp "native-jar/META-INF/native/${nativeLibrary}" "$out/lib/"
          cp source/LICENSE.txt source/NOTICE.txt \
            "$out/share/licenses/netty-tcnative/"
          cp -R source "$out/share/source/netty-tcnative"

          printf '%s\n' '${apr}' '${bazelNettyBoringssl2061}' \
            '${bazelNettyTcnativeClasses2061}' > "$out/nix-support/java-runtime"
        '';
      }
    ];
  }
