##! Netty epoll JNI rebuilt from C source and the source-built Unix archive.
{
  mkDerivation,
  buildPackages,
  stdenv,
  bazelNettyNativeUnix,
  bazelNettyTransportExtras,
  bazelNettyCommon,
  bazelNettyBase,
  version ? "4.1.93.Final",
}: let
  buildJdk = buildPackages.openjdk-21;
  architecture =
    if stdenv.hostPlatform.system == "x86_64-linux"
    then "x86_64"
    else if stdenv.hostPlatform.system == "aarch64-linux"
    then "aarch_64"
    else throw "Netty epoll JNI source build needs a Linux target: ${stdenv.hostPlatform.system}";
  classifier = "linux-${architecture}";
  nativeLibrary = "libnetty_transport_native_epoll_${architecture}.so";
  classpath = builtins.concatStringsSep ":" [
    "${bazelNettyCommon}/share/java/netty-common-${version}.jar"
    "${bazelNettyBase}/share/java/netty-buffer-${version}.jar"
    "${bazelNettyBase}/share/java/netty-resolver-${version}.jar"
    "${bazelNettyBase}/share/java/netty-transport-${version}.jar"
    "${bazelNettyTransportExtras}/share/java/netty-transport-native-unix-common-${version}.jar"
    "${bazelNettyTransportExtras}/share/java/netty-transport-classes-epoll-${version}.jar"
  ];
in
  mkDerivation {
    pname = "bazel-netty-native-epoll";
    inherit version;
    src = bazelNettyNativeUnix;

    buildDeps = [
      buildJdk
      bazelNettyTransportExtras
      bazelNettyCommon
      bazelNettyBase
    ];
    runtimeDeps = [bazelNettyNativeUnix bazelNettyTransportExtras bazelNettyCommon bazelNettyBase];

    phases = [
      {
        name = "build";
        script = ''
          upstream="$src/share/source/netty-native"
          epoll="$upstream/transport-native-epoll/src/main/c"
          unix="$upstream/transport-native-unix-common/src/main/c"
          utility="$upstream/jni-util"
          mkdir -p native-jar/META-INF/native

          cc -O2 -fPIC -shared -fno-omit-frame-pointer \
            -fvisibility=hidden \
            -I${buildJdk}/include -I${buildJdk}/include/linux \
            -I"$epoll" -I"$unix" -I"$utility" \
            "$epoll/netty_epoll_linuxsocket.c" \
            "$epoll/netty_epoll_native.c" \
            -Wl,--whole-archive "$src/lib/libnetty-unix-common.a" \
            -Wl,--no-whole-archive -ldl \
            -o "native-jar/META-INF/native/${nativeLibrary}"
        '';
      }
      {
        name = "check";
        script = ''
          ${
            if stdenv.hostPlatform.system == stdenv.buildPlatform.system
            then ''
              cat > NettyEpollSmoke.java <<'JAVA'
              import io.netty.channel.epoll.Epoll;

              final class NettyEpollSmoke {
                  public static void main(String[] args) {
                      if (!Epoll.isAvailable()) {
                          throw new AssertionError("Source-built Netty epoll JNI did not load", Epoll.unavailabilityCause());
                      }
                  }
              }
              JAVA

              classpath="native-jar:${classpath}"
              ${buildJdk}/bin/javac --release 8 -proc:none \
                -cp "$classpath" NettyEpollSmoke.java
              ${buildJdk}/bin/java -cp "$classpath:." NettyEpollSmoke
            ''
            else ""
          }
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/io/netty/netty-transport-native-epoll/${version}"
          mkdir -p "$destination" "$out/lib" "$out/share/licenses/netty-native" \
            "$out/nix-support"
          ${buildJdk}/bin/jar --create \
            --file "$destination/netty-transport-native-epoll-${version}-${classifier}.jar" \
            --no-manifest --date=1980-01-01T00:00:02Z -C native-jar .
          cp "native-jar/META-INF/native/${nativeLibrary}" "$out/lib/"
          cp "$src/share/licenses/netty-native/LICENSE.txt" \
            "$src/share/licenses/netty-native/NOTICE.txt" \
            "$out/share/licenses/netty-native/"

          printf '%s\n' '${bazelNettyNativeUnix}' '${bazelNettyTransportExtras}' \
            '${bazelNettyCommon}' '${bazelNettyBase}' \
            > "$out/nix-support/java-runtime"
        '';
      }
    ];
  }
