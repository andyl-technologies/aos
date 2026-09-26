##! Netty Unix JNI static library rebuilt from its C source tree.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  stdenv,
  bazelNettyTransportExtras,
}: let
  version = "4.1.93.Final";
  buildJdk = buildPackages.openjdk-21;
  classifier =
    if stdenv.hostPlatform.system == "x86_64-linux"
    then "linux-x86_64"
    else if stdenv.hostPlatform.system == "aarch64-linux"
    then "linux-aarch_64"
    else if stdenv.hostPlatform.system == "x86_64-darwin"
    then "osx-x86_64"
    else if stdenv.hostPlatform.system == "aarch64-darwin"
    then "osx-aarch_64"
    else throw "Netty Unix JNI source build has no target for ${stdenv.hostPlatform.system}";
  source = fetchgit {
    url = "https://github.com/netty/netty.git";
    rev = "69270b102a6339ef3279e3f0755526db001850ef";
    name = "netty-4.1.93-native-source-only";
    hash = "sha256-i3v2q6KPv8Llei3qweCwum0IjLvqfIz4U8gAiK9fgKc=";
    deepClone = true;
    git = buildPackages.git-minimal;
    caCertificates = buildPackages.ca-certificates;
    coreutils = buildPackages.coreutils;
    sparsePatterns = [
      "/transport-native-unix-common/src/main/c/"
      "/transport-native-epoll/src/main/c/"
      "/transport-native-kqueue/src/main/c/"
      "/LICENSE.txt"
      "/NOTICE.txt"
    ];
  };
  jniUtilSource = fetchurl {
    urls = ["https://repo.maven.apache.org/maven2/io/netty/netty-jni-util/0.0.6.Final/netty-jni-util-0.0.6.Final-sources.jar"];
    hash = "sha256-CbvbrDHP2QIubN18npILENi0ui+CZD24wzoDvC8qGJM=";
  };
in
  mkDerivation {
    pname = "bazel-netty-native-unix";
    inherit version;
    src = source;

    buildDeps = [buildJdk buildPackages.python3 buildPackages.unzip bazelNettyTransportExtras];
    runtimeDeps = [bazelNettyTransportExtras];

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

          compiled_signatures = tuple(bytes.fromhex(value) for value in (
              "cafebabe", "7f454c46", "0061736d", "213c617263683e0a",
              "feedface", "cefaedfe", "feedfacf", "cffaedfe", "4d5a",
          ))
          for path in Path("source").rglob("*"):
              if not path.is_file():
                  continue
              if path.suffix not in {".c", ".h", ".txt"}:
                  raise SystemExit(f"Unexpected Netty source: {path}")
              data = path.read_bytes()
              if data.startswith(compiled_signatures):
                  raise SystemExit(f"Compiled Netty source: {path}")
              data.decode("utf-8")

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
                  if data.startswith(compiled_signatures):
                      raise SystemExit(f"Compiled Netty JNI utility source: {path}")
                  data.decode("utf-8")
                  if path.name not in {"netty_jni_util.c", "netty_jni_util.h"}:
                      continue
                  destination = Path("source/jni-util") / path.name
                  destination.parent.mkdir(parents=True, exist_ok=True)
                  destination.write_bytes(data)

          native = Path("source/transport-native-unix-common/src/main/c")
          if len(list(native.glob("*.c"))) != 7:
              raise SystemExit("Expected seven Netty Unix JNI C sources")
          PY
        '';
      }
      {
        name = "build";
        script = ''
          native=source/transport-native-unix-common/src/main/c
          mkdir -p objects native-jar/META-INF/native/lib \
            native-jar/META-INF/native/include
          for input in "$native"/*.c source/jni-util/*.c; do
            object="objects/$(basename "''${input%.c}").o"
            cc -O2 -fPIC -fno-omit-frame-pointer -fvisibility=hidden \
              -I${buildJdk}/include -I${buildJdk}/include/linux \
              -I"$native" -Isource/jni-util \
              -c "$input" -o "$object"
          done
          # The archive is embedded in a JAR, beyond Nix's raw-file scrub.
          ar rcsD native-jar/META-INF/native/lib/libnetty-unix-common.a objects/*.o

          ${buildPackages.unzip}/bin/unzip -q \
            ${bazelNettyTransportExtras}/share/java/netty-transport-native-unix-common-${version}.jar \
            -d native-jar
          cp "$native"/*.h source/jni-util/*.h \
            native-jar/META-INF/native/include/
        '';
      }
      {
        name = "check";
        script = ''
          ar t native-jar/META-INF/native/lib/libnetty-unix-common.a \
            > archive-members
          python3 - <<'PY'
          from pathlib import Path

          members = Path("archive-members").read_text().splitlines()
          if len(members) != 8 or "netty_jni_util.o" not in members:
              raise SystemExit(f"Unexpected Netty Unix native archive members: {members}")
          PY
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/io/netty/netty-transport-native-unix-common/${version}"
          mkdir -p "$destination" "$out/lib" "$out/share/licenses/netty-native" \
            "$out/share/source" "$out/nix-support"
          ${buildJdk}/bin/jar --create \
            --file "$destination/netty-transport-native-unix-common-${version}-${classifier}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C native-jar .
          cp native-jar/META-INF/native/lib/libnetty-unix-common.a "$out/lib/"
          cp source/LICENSE.txt source/NOTICE.txt "$out/share/licenses/netty-native/"
          cp -R source "$out/share/source/netty-native"

          printf '%s\n' '${bazelNettyTransportExtras}' \
            > "$out/nix-support/java-runtime"
        '';
      }
    ];
  }
