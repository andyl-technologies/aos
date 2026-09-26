##! Source-built Netty 4.1.119 Unix JNI classifiers for Bazel's Maven graph.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  stdenv,
  bazelNetty119,
}: let
  version = "4.1.119.Final";
  linuxArmPackages = import ../../default.nix {crossSystem = "aarch64-linux";};
  darwinX64Packages = import ../../default.nix {crossSystem = "x86_64-darwin";};
  darwinArmPackages = import ../../default.nix {crossSystem = "aarch64-darwin";};

  nativeUnix = targetMkDerivation: targetStdenv:
    import ./_bazel-netty-native-unix.nix {
      mkDerivation = targetMkDerivation;
      stdenv = targetStdenv;
      inherit fetchgit fetchurl buildPackages version;
      bazelNettyTransportExtras = bazelNetty119.transportExtras;
      sourceRev = "fb7c786f2df57867bcfe049b13a42e764606f0d5";
      sourceHash = "sha256-DZWpmBu7aPOR2rmD0brS4XxVKDI3Wbn4+7hva+ZTnX4=";
      jniUtilVersion = "0.0.9.Final";
      jniUtilHash = "sha256-2rFdDCsIBz1q5Uv+039Xv2wzdDF4uqRO6YUzElwesL0=";
    };

  nativeUnixLinuxX64 = nativeUnix mkDerivation stdenv;
  nativeUnixLinuxArm = nativeUnix linuxArmPackages.pkgs.mkDerivation linuxArmPackages.stdenv;
  nativeUnixDarwinX64 = nativeUnix darwinX64Packages.pkgs.mkDerivation darwinX64Packages.stdenv;
  nativeUnixDarwinArm = nativeUnix darwinArmPackages.pkgs.mkDerivation darwinArmPackages.stdenv;

  nativeTransport = name: targetMkDerivation: targetStdenv: nativeUnixPackage:
    import (./. + "/_bazel-netty-native-${name}.nix") {
      mkDerivation = targetMkDerivation;
      stdenv = targetStdenv;
      inherit buildPackages version;
      bazelNettyNativeUnix = nativeUnixPackage;
      bazelNettyTransportExtras = bazelNetty119.transportExtras;
      bazelNettyCommon = bazelNetty119.common;
      bazelNettyBase = bazelNetty119.base;
    };

  nativeEpollLinuxX64 = nativeTransport "epoll" mkDerivation stdenv nativeUnixLinuxX64;
  nativeEpollLinuxArm = nativeTransport "epoll" linuxArmPackages.pkgs.mkDerivation linuxArmPackages.stdenv nativeUnixLinuxArm;
  nativeKqueueDarwinX64 = nativeTransport "kqueue" darwinX64Packages.pkgs.mkDerivation darwinX64Packages.stdenv nativeUnixDarwinX64;
  nativeKqueueDarwinArm = nativeTransport "kqueue" darwinArmPackages.pkgs.mkDerivation darwinArmPackages.stdenv nativeUnixDarwinArm;

  mavenRepository = artifact: classifier: nativePackage:
    mkDerivation {
      pname = "bazel-maven-${artifact}-source";
      inherit version;
      src = nativePackage;

      buildDeps = [];
      runtimeDeps = [nativePackage];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/file"
            printf 'workspace(name = "bazel_maven_netty_native_unix")\n' > "$out/WORKSPACE"
            cp ${nativePackage}/maven/io/netty/${artifact}/${version}/${artifact}-${version}-${classifier}.jar \
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
  inherit nativeUnixLinuxX64 nativeUnixLinuxArm nativeUnixDarwinX64 nativeUnixDarwinArm;
  inherit nativeEpollLinuxX64 nativeEpollLinuxArm nativeKqueueDarwinX64 nativeKqueueDarwinArm;
  repositories = {
    "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_linux_x86_64_4_1_119_Final" =
      mavenRepository "netty-transport-native-unix-common" "linux-x86_64" nativeUnixLinuxX64;
    "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_linux_aarch_64_4_1_119_Final" =
      mavenRepository "netty-transport-native-unix-common" "linux-aarch_64" nativeUnixLinuxArm;
    "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_osx_x86_64_4_1_119_Final" =
      mavenRepository "netty-transport-native-unix-common" "osx-x86_64" nativeUnixDarwinX64;
    "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_osx_aarch_64_4_1_119_Final" =
      mavenRepository "netty-transport-native-unix-common" "osx-aarch_64" nativeUnixDarwinArm;
    "rules_jvm_external++maven+io_netty_netty_transport_native_epoll_jar_linux_x86_64_4_1_119_Final" =
      mavenRepository "netty-transport-native-epoll" "linux-x86_64" nativeEpollLinuxX64;
    "rules_jvm_external++maven+io_netty_netty_transport_native_epoll_jar_linux_aarch_64_4_1_119_Final" =
      mavenRepository "netty-transport-native-epoll" "linux-aarch_64" nativeEpollLinuxArm;
    "rules_jvm_external++maven+io_netty_netty_transport_native_kqueue_jar_osx_x86_64_4_1_119_Final" =
      mavenRepository "netty-transport-native-kqueue" "osx-x86_64" nativeKqueueDarwinX64;
    "rules_jvm_external++maven+io_netty_netty_transport_native_kqueue_jar_osx_aarch_64_4_1_119_Final" =
      mavenRepository "netty-transport-native-kqueue" "osx-aarch_64" nativeKqueueDarwinArm;
  };
}
