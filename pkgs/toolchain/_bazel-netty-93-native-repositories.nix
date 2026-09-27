##! Bazel 7's Linux Netty JNI Maven repositories from rebuilt native code.
{
  mkDerivation,
  bazelNettyNativeUnix,
  bazelNettyNativeEpoll,
  bazelNettyTcnativeNative,
}: let
  nettyVersion = "4.1.93.Final";
  tcnativeVersion = "2.0.56.Final";
  classifier = "linux-x86_64";

  repository = artifact: version: sourcePackage:
    mkDerivation {
      pname = "bazel-maven-${artifact}-source";
      inherit version;
      src = sourcePackage;

      buildDeps = [];
      runtimeDeps = [sourcePackage];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/file"
            printf 'workspace(name = "bazel_maven_netty_native")\n' > "$out/WORKSPACE"
            cp ${sourcePackage}/maven/io/netty/${artifact}/${version}/${artifact}-${version}-${classifier}.jar \
              "$out/file/artifact.jar"
            cat > "$out/file/BUILD.bazel" <<'BUILD'
            package(default_visibility = ["//visibility:public"])
            filegroup(name = "file", srcs = ["artifact.jar"])
            BUILD
          '';
        }
      ];
    };
in {
  "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_linux_x86_64_4_1_93_Final" =
    repository "netty-transport-native-unix-common" nettyVersion bazelNettyNativeUnix;
  "rules_jvm_external++maven+io_netty_netty_transport_native_epoll_jar_linux_x86_64_4_1_93_Final" =
    repository "netty-transport-native-epoll" nettyVersion bazelNettyNativeEpoll;
  "rules_jvm_external++maven+io_netty_netty_tcnative_boringssl_static_jar_linux_x86_64_2_0_56_Final" =
    repository "netty-tcnative-boringssl-static" tcnativeVersion bazelNettyTcnativeNative;
}
