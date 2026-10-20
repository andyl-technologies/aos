##! Bazel 7's Linux and Darwin Netty JNI Maven repositories from source.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  bazelNettyTransportExtras,
  bazelNettyCommon,
  bazelNettyBase,
  bazelNettyTcnativeClasses,
  bazelNettyNativeUnix,
  bazelNettyNativeEpoll,
  bazelNettyTcnativeNative,
}: let
  nettyVersion = "4.1.93.Final";
  tcnativeVersion = "2.0.56.Final";
  linuxArmPackages = import ../../default.nix {crossSystem = "aarch64-linux";};
  darwinX64Packages = import ../../default.nix {crossSystem = "x86_64-darwin";};
  darwinArmPackages = import ../../default.nix {crossSystem = "aarch64-darwin";};

  nativeUnixFor = target:
    import ./_bazel-netty-native-unix.nix {
      inherit fetchgit fetchurl buildPackages bazelNettyTransportExtras;
      inherit (target.pkgs) mkDerivation;
      inherit (target) stdenv;
    };

  nativeTransportFor = name: target: unix:
    import (./. + "/_bazel-netty-native-${name}.nix") {
      inherit buildPackages bazelNettyTransportExtras bazelNettyCommon bazelNettyBase;
      inherit (target.pkgs) mkDerivation;
      inherit (target) stdenv;
      bazelNettyNativeUnix = unix;
    };

  nativeTcnativeFor = target:
    import ./_bazel-netty-tcnative-native.nix {
      inherit fetchgit fetchurl buildPackages bazelNettyTcnativeClasses;
      inherit (target.pkgs) mkDerivation apache-portable-runtime;
      inherit (target) stdenv;
      bazelNettyBoringssl = import ./_bazel-netty-boringssl.nix {
        inherit fetchgit buildPackages;
        inherit (target.pkgs) mkDerivation;
        inherit (target) stdenv;
      };
    };

  unixLinuxArm = nativeUnixFor linuxArmPackages;
  unixDarwinX64 = nativeUnixFor darwinX64Packages;
  unixDarwinArm = nativeUnixFor darwinArmPackages;
  epollLinuxArm = nativeTransportFor "epoll" linuxArmPackages unixLinuxArm;
  kqueueDarwinX64 = nativeTransportFor "kqueue" darwinX64Packages unixDarwinX64;
  kqueueDarwinArm = nativeTransportFor "kqueue" darwinArmPackages unixDarwinArm;
  tcnativeLinuxArm = nativeTcnativeFor linuxArmPackages;
  tcnativeDarwinX64 = nativeTcnativeFor darwinX64Packages;
  tcnativeDarwinArm = nativeTcnativeFor darwinArmPackages;

  repository = artifact: version: classifier: sourcePackage:
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
    repository "netty-transport-native-unix-common" nettyVersion "linux-x86_64" bazelNettyNativeUnix;
  "rules_jvm_external++maven+io_netty_netty_transport_native_epoll_jar_linux_x86_64_4_1_93_Final" =
    repository "netty-transport-native-epoll" nettyVersion "linux-x86_64" bazelNettyNativeEpoll;
  "rules_jvm_external++maven+io_netty_netty_tcnative_boringssl_static_jar_linux_x86_64_2_0_56_Final" =
    repository "netty-tcnative-boringssl-static" tcnativeVersion "linux-x86_64" bazelNettyTcnativeNative;
  "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_linux_aarch_64_4_1_93_Final" =
    repository "netty-transport-native-unix-common" nettyVersion "linux-aarch_64" unixLinuxArm;
  "rules_jvm_external++maven+io_netty_netty_transport_native_epoll_jar_linux_aarch_64_4_1_93_Final" =
    repository "netty-transport-native-epoll" nettyVersion "linux-aarch_64" epollLinuxArm;
  "rules_jvm_external++maven+io_netty_netty_tcnative_boringssl_static_jar_linux_aarch_64_2_0_56_Final" =
    repository "netty-tcnative-boringssl-static" tcnativeVersion "linux-aarch_64" tcnativeLinuxArm;
  "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_osx_x86_64_4_1_93_Final" =
    repository "netty-transport-native-unix-common" nettyVersion "osx-x86_64" unixDarwinX64;
  "rules_jvm_external++maven+io_netty_netty_transport_native_kqueue_jar_osx_x86_64_4_1_93_Final" =
    repository "netty-transport-native-kqueue" nettyVersion "osx-x86_64" kqueueDarwinX64;
  "rules_jvm_external++maven+io_netty_netty_tcnative_boringssl_static_jar_osx_x86_64_2_0_56_Final" =
    repository "netty-tcnative-boringssl-static" tcnativeVersion "osx-x86_64" tcnativeDarwinX64;
  "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_osx_aarch_64_4_1_93_Final" =
    repository "netty-transport-native-unix-common" nettyVersion "osx-aarch_64" unixDarwinArm;
  "rules_jvm_external++maven+io_netty_netty_transport_native_kqueue_jar_osx_aarch_64_4_1_93_Final" =
    repository "netty-transport-native-kqueue" nettyVersion "osx-aarch_64" kqueueDarwinArm;
  "rules_jvm_external++maven+io_netty_netty_tcnative_boringssl_static_jar_osx_aarch_64_2_0_56_Final" =
    repository "netty-tcnative-boringssl-static" tcnativeVersion "osx-aarch_64" tcnativeDarwinArm;
}
