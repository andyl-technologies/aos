##! Bazel 7's Netty 4.1.93 Maven repositories from source-built modules.
{
  mkDerivation,
  bazelNettyCommon,
  bazelNettyBase,
  bazelNettyCodec,
  bazelNettyCodecHttp,
  bazelNettyTransportExtras,
  bazelNettyHandler,
  bazelNettyDns,
  bazelNettyHttp2Proxy,
}: let
  version = "4.1.93.Final";
  modules = {
    common = bazelNettyCommon;
    buffer = bazelNettyBase;
    resolver = bazelNettyBase;
    transport = bazelNettyBase;
    codec = bazelNettyCodec;
    codec-http = bazelNettyCodecHttp;
    codec-socks = bazelNettyTransportExtras;
    transport-native-unix-common = bazelNettyTransportExtras;
    transport-classes-epoll = bazelNettyTransportExtras;
    transport-classes-kqueue = bazelNettyTransportExtras;
    handler = bazelNettyHandler;
    codec-dns = bazelNettyDns;
    resolver-dns = bazelNettyDns;
    handler-proxy = bazelNettyHttp2Proxy;
    codec-http2 = bazelNettyHttp2Proxy;
  };
  repository = name: sourcePackage:
    mkDerivation {
      pname = "bazel-maven-netty-${name}-source";
      inherit version;
      src = sourcePackage;

      buildDeps = [];
      runtimeDeps = [sourcePackage];

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/file"
            printf 'workspace(name = "bazel_maven_netty_${name}")\n' > "$out/WORKSPACE"
            cp ${sourcePackage}/share/java/netty-${name}-${version}.jar \
              "$out/file/artifact.jar"
            cat > "$out/file/BUILD.bazel" <<'BUILD'
            package(default_visibility = ["//visibility:public"])
            filegroup(name = "file", srcs = ["artifact.jar"])
            BUILD
          '';
        }
      ];
    };
in
  builtins.listToAttrs (builtins.map (name: {
      name = "rules_jvm_external++maven+io_netty_netty_${builtins.replaceStrings ["-"] ["_"] name}_4_1_93_Final";
      value = repository name modules.${name};
    })
    (builtins.attrNames modules))
