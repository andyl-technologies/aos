##! Netty kqueue JNI rebuilt for Darwin from C source and the Unix archive.
{
  mkDerivation,
  buildPackages,
  stdenv,
  bazelNettyNativeUnix,
  bazelNettyTransportExtras,
  bazelNettyCommon,
  bazelNettyBase,
}: let
  version = "4.1.93.Final";
  buildJdk = buildPackages.openjdk-21;
  architecture =
    if stdenv.hostPlatform.system == "x86_64-darwin"
    then "x86_64"
    else if stdenv.hostPlatform.system == "aarch64-darwin"
    then "aarch_64"
    else throw "Netty kqueue JNI source build needs a Darwin target: ${stdenv.hostPlatform.system}";
  classifier = "osx-${architecture}";
  nativeLibrary = "libnetty_transport_native_kqueue_${architecture}.jnilib";
in
  mkDerivation {
    pname = "bazel-netty-native-kqueue";
    inherit version;
    src = bazelNettyNativeUnix;

    buildDeps = [
      buildJdk
      bazelNettyNativeUnix
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
          kqueue="$upstream/transport-native-kqueue/src/main/c"
          unix="$upstream/transport-native-unix-common/src/main/c"
          utility="$upstream/jni-util"
          mkdir -p native-jar/META-INF/native patched
          cp "$kqueue"/*.c patched/
          # Upstream includes a BSD malloc header, but uses stdlib malloc.
          sed -i '/^#include <sys\/malloc.h>$/d' patched/netty_kqueue_bsdsocket.c

          cc -O2 -fPIC -dynamiclib -fno-omit-frame-pointer \
            -fvisibility=hidden -Wl,-undefined,dynamic_lookup \
            -I${buildJdk}/include -I${buildJdk}/include/linux \
            -I"$kqueue" -I"$unix" -I"$utility" \
            patched/netty_kqueue_bsdsocket.c \
            patched/netty_kqueue_eventarray.c \
            patched/netty_kqueue_native.c \
            -Wl,-force_load,"$src/lib/libnetty-unix-common.a" \
            -o "native-jar/META-INF/native/${nativeLibrary}"
        '';
      }
      {
        name = "check";
        script = ''
          nm -g "native-jar/META-INF/native/${nativeLibrary}" \
            | grep 'JNI_OnLoad$' > jni-exports
          test -s jni-exports
        '';
      }
      {
        name = "install";
        script = ''
          destination="$out/maven/io/netty/netty-transport-native-kqueue/${version}"
          mkdir -p "$destination" "$out/lib" "$out/share/licenses/netty-native" \
            "$out/nix-support"
          ${buildJdk}/bin/jar --create \
            --file "$destination/netty-transport-native-kqueue-${version}-${classifier}.jar" \
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
