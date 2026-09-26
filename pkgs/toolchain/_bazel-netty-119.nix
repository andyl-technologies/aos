##! Source-built Netty 4.1.119 modules for Bazel 8's Maven graph.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  bazelMavenBootstrap,
  bazelJbossModules,
  bazelLog4j,
  bazelLegacyJavaHttp,
  bazelBlockHound,
  bazelByteBuddy,
  bazelBndAnnotation,
  bazelProtobufJava,
  bazelZstdJni155,
}: let
  commonInputs = {
    inherit
      mkDerivation
      fetchurl
      buildPackages
      bazelMavenBootstrap
      bazelLog4j
      bazelLegacyJavaHttp
      bazelBlockHound
      bazelByteBuddy
      ;
  };

  common = import ./_bazel-netty-common.nix (commonInputs
    // {
      version = "4.1.119.Final";
      sourceHash = "sha256-YkarAnNV2den2WTbGRcrtCbZ+olX6aru8/txuenQ5e0=";
      osgiAnnotations = bazelBndAnnotation;
    });

  base = import ./_bazel-netty-base.nix (commonInputs
    // {
      bazelNettyCommon = common;
      version = "4.1.119.Final";
      archiveHashes = {
        buffer = "sha256-NrpeV5OcdFLCFDbwcdPsKfY+/+kpONc8bmQcTPoH4xU=";
        resolver = "sha256-JtMnim9G8LiWnK4IxiAbHECHqVcJuu7EaRSdEw0wdeo=";
        transport = "sha256-ppeSW1LnMjRkh54xuFahTWvvcCVYd9wbC4joLxLarWg=";
      };
    });

  codecJavaDeps = import ./_bazel-netty-codec-java-deps.nix {
    inherit mkDerivation fetchurl buildPackages bazelJbossModules bazelMavenBootstrap;
    bazelNettyCommon = common;
    bazelNettyBase = base;
    version = "4.1.119.Final";
    brotliVersion = "1.16.0";
    brotliServiceHash = "sha256-/pbOjE0Yi5ieO1W31a+5MCyDztq3yf7SiMUSbhOCGlQ=";
    brotliHash = "sha256-m53F3CRrJIEc39DLJUU/VfXX6CaYeMb0Ymjm9/9OLqA=";
  };

  codec = import ./_bazel-netty-codec.nix {
    inherit
      mkDerivation
      fetchurl
      buildPackages
      bazelMavenBootstrap
      bazelProtobufJava
      bazelZstdJni155
      ;
    bazelNettyCommon = common;
    bazelNettyBase = base;
    bazelNettyCodecJavaDeps = codecJavaDeps;
    version = "4.1.119.Final";
    sourceHash = "sha256-Av26kRsc6t2GB8j3ZP/Hf5VzQxtK+/xbfE7On/yfA20=";
  };

  mavenRepository = name: sourcePackage:
    mkDerivation {
      pname = "bazel-maven-netty-${name}-source";
      version = "4.1.119.Final";
      src = sourcePackage;

      buildDeps = [];
      runtimeDeps = [sourcePackage];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/file"
            printf 'workspace(name = "bazel_maven_netty_${name}")\n' > "$out/WORKSPACE"
            cp ${sourcePackage}/share/java/netty-${name}-4.1.119.Final.jar \
              "$out/file/artifact.jar"
            cat > "$out/file/BUILD.bazel" <<'BUILD'
            package(default_visibility = ["//visibility:public"])
            filegroup(name = "file", srcs = ["artifact.jar"])
            BUILD
          '';
        }
      ];
    };

  repositories = {
    "rules_jvm_external++maven+io_netty_netty_common_4_1_119_Final" = mavenRepository "common" common;
    "rules_jvm_external++maven+io_netty_netty_buffer_4_1_119_Final" = mavenRepository "buffer" base;
    "rules_jvm_external++maven+io_netty_netty_resolver_4_1_119_Final" = mavenRepository "resolver" base;
    "rules_jvm_external++maven+io_netty_netty_transport_4_1_119_Final" = mavenRepository "transport" base;
    "rules_jvm_external++maven+io_netty_netty_codec_4_1_119_Final" = mavenRepository "codec" codec;
  };
in {
  inherit common base codec repositories;
}
