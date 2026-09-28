##! Source-built Netty TCNative 2.0.61 classifiers for Bazel's Maven graph.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  stdenv,
  apr,
  bazelNettyTcnativeClasses2061,
  version ? "2.0.61.Final",
}: let
  repositoryVersion = builtins.replaceStrings ["."] ["_"] version;
  linuxArmPackages = import ../../default.nix {crossSystem = "aarch64-linux";};
  darwinX64Packages = import ../../default.nix {crossSystem = "x86_64-darwin";};
  darwinArmPackages = import ../../default.nix {crossSystem = "aarch64-darwin";};

  boringsslFor = targetMkDerivation: targetStdenv:
    import ./_bazel-netty-boringssl-2061.nix {
      mkDerivation = targetMkDerivation;
      stdenv = targetStdenv;
      inherit fetchgit buildPackages;
      version =
        if version == "2.0.70.Final"
        then "2024-10-26"
        else "2022-12-08";
    };

  nativeFor = targetMkDerivation: targetStdenv: targetApr:
    import ./_bazel-netty-tcnative-native-2061.nix {
      mkDerivation = targetMkDerivation;
      stdenv = targetStdenv;
      apr = targetApr;
      inherit fetchgit fetchurl buildPackages bazelNettyTcnativeClasses2061 version;
      bazelNettyBoringssl2061 = boringsslFor targetMkDerivation targetStdenv;
    };

  nativeLinuxX64 = nativeFor mkDerivation stdenv apr;
  nativeLinuxArm = nativeFor linuxArmPackages.pkgs.mkDerivation linuxArmPackages.stdenv linuxArmPackages.pkgs.apr;
  nativeDarwinX64 = nativeFor darwinX64Packages.pkgs.mkDerivation darwinX64Packages.stdenv darwinX64Packages.pkgs.apr;
  nativeDarwinArm = nativeFor darwinArmPackages.pkgs.mkDerivation darwinArmPackages.stdenv darwinArmPackages.pkgs.apr;

  mavenRepository = classifier: nativePackage:
    mkDerivation {
      pname = "bazel-maven-netty-tcnative-source";
      inherit version;
      src = nativePackage;

      buildDeps = [];
      runtimeDeps = [nativePackage];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/file"
            printf 'workspace(name = "bazel_maven_netty_tcnative")\n' > "$out/WORKSPACE"
            cp ${nativePackage}/maven/io/netty/netty-tcnative-boringssl-static/${version}/netty-tcnative-boringssl-static-${version}-${classifier}.jar \
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
  inherit nativeLinuxX64 nativeLinuxArm nativeDarwinX64 nativeDarwinArm;
  repositories = {
    "rules_jvm_external++maven+io_netty_netty_tcnative_boringssl_static_jar_linux_x86_64_${repositoryVersion}" =
      mavenRepository "linux-x86_64" nativeLinuxX64;
    "rules_jvm_external++maven+io_netty_netty_tcnative_boringssl_static_jar_linux_aarch_64_${repositoryVersion}" =
      mavenRepository "linux-aarch_64" nativeLinuxArm;
    "rules_jvm_external++maven+io_netty_netty_tcnative_boringssl_static_jar_osx_x86_64_${repositoryVersion}" =
      mavenRepository "osx-x86_64" nativeDarwinX64;
    "rules_jvm_external++maven+io_netty_netty_tcnative_boringssl_static_jar_osx_aarch_64_${repositoryVersion}" =
      mavenRepository "osx-aarch_64" nativeDarwinArm;
  };
}
