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

  mavenRepository = classifier: nativePackage:
    mkDerivation {
      pname = "bazel-maven-netty-native-unix-source";
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
            cp ${nativePackage}/maven/io/netty/netty-transport-native-unix-common/${version}/netty-transport-native-unix-common-${version}-${classifier}.jar \
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
  repositories = {
    "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_linux_x86_64_4_1_119_Final" =
      mavenRepository "linux-x86_64" nativeUnixLinuxX64;
    "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_linux_aarch_64_4_1_119_Final" =
      mavenRepository "linux-aarch_64" nativeUnixLinuxArm;
    "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_osx_x86_64_4_1_119_Final" =
      mavenRepository "osx-x86_64" nativeUnixDarwinX64;
    "rules_jvm_external++maven+io_netty_netty_transport_native_unix_common_jar_osx_aarch_64_4_1_119_Final" =
      mavenRepository "osx-aarch_64" nativeUnixDarwinArm;
  };
}
