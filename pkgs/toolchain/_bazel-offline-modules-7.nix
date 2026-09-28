##! Bazel 7's pinned protocol module and extension source dependencies.
{
  buildPackages,
  fetchgit,
  bazelSource,
  sharedModules,
}: let
  moduleSource = import ./_bazel-module-source.nix {inherit buildPackages fetchgit;};
  prepareModule = import ./_bazel-module-prepared.nix {inherit buildPackages;};
  registryRevision = "18e405773f40bfe226ef2e2ea7bc0f1a71d39fd9";
  registryPatch = module: version: patch:
    buildPackages.fetchurl {
      urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/${module}/${version}/patches/${patch.name}"];
      inherit (patch) hash;
    };
  upbSource = moduleSource {
    name = "upb";
    version = "0.0.0-20220923-a547704";
    url = "https://github.com/protocolbuffers/upb.git";
    rev = "a5477045acaa34586420942098f5fecd3570f577";
    fetchCommit = true;
    hash = "sha256-F/fBSUOZkjlPwM48yhdxdN05+SksZ7W9us1HZ6qEO/s=";
  };
  rulesProtoSource = moduleSource {
    name = "rules_proto";
    version = "6.0.0";
    url = "https://github.com/bazelbuild/rules_proto.git";
    ref = "6.0.0";
    rev = "d205d37866925569d99b4d6cdcba172326ecf812";
    hash = "sha256-9DcA00GmdhOmybHQHbhNHqQgdWi1qWkGBYVP+D/al0Q=";
  };
  protobufSource = moduleSource {
    name = "protobuf";
    version = "21.7";
    url = "https://github.com/protocolbuffers/protobuf.git";
    ref = "v21.7";
    rev = "54489e95e01882407f356f83c9074415e561db00";
    hash = "sha256-Lx74bDPbt2lw42Ju5i7SVmyDOt8aimeu5lwB+V99Eno=";
  };
  grpcSource = moduleSource {
    name = "grpc";
    version = "1.48.1";
    url = "https://github.com/grpc/grpc.git";
    ref = "v1.48.1";
    rev = "d52ed193d11dee797c0d51dc8db06032998b33f4";
    hash = "sha256-LTyKVX7SEPOGhY1bB7H15RDosT04yQPrDfqSJ7IkX2k=";
  };
  grpcEnvoySource = moduleSource {
    name = "grpc-envoy-api";
    version = "9c42588c";
    url = "https://github.com/envoyproxy/data-plane-api.git";
    rev = "9c42588c956220b48eb3099d186487c2f04d32ec";
    fetchCommit = true;
    hash = "sha256-1ALZZTCGZeex0vas4t6FCnM+R/g2hJfZYClIyYikznE=";
  };
in
  sharedModules
  // {
    grpc-envoy-api = prepareModule {
      pname = "bazel-grpc-envoy-api-source";
      version = "9c42588c";
      source = grpcEnvoySource;
      patches = [];
      # The upstream archive repository supplies its root marker separately.
      overlays."WORKSPACE" = builtins.toFile "grpc-envoy-api-WORKSPACE" "";
    };
    grpc-udpa = prepareModule {
      pname = "bazel-grpc-udpa-source";
      version = "cb28da34";
      source = moduleSource {
        name = "grpc-udpa";
        version = "cb28da34";
        url = "https://github.com/cncf/xds.git";
        rev = "cb28da3451f158a947dfc45090fe92b07b243bc1";
        fetchCommit = true;
        hash = "sha256-zQkFrXlpv5NrFB51EZfUXLOJImiwt1eDL5ieze6GYtQ=";
      };
      patches = [];
      overlays."WORKSPACE" = builtins.toFile "grpc-udpa-WORKSPACE" "";
    };
    grpc-googleapis = moduleSource {
      name = "grpc-googleapis";
      version = "2f9af297";
      url = "https://github.com/googleapis/googleapis.git";
      rev = "2f9af297c84c55c8b871ba4495e01ade42476c92";
      fetchCommit = true;
      hash = "sha256-2FGy1ZjWULIS6ZFRyLEiJxSXdVUAIj0B/Y3k4ObeFNU=";
    };
    upb = prepareModule {
      pname = "bazel-upb-source";
      version = "0.0.0-20220923-a547704";
      source = upbSource;
      patchStrip = 0;
      patches = [
        (registryPatch "upb" "0.0.0-20220923-a547704" {
          name = "module_dot_bazel.patch";
          hash = "sha256-wH4mNS6ZYy+8uC0HoAft/c7SDsq2Kxf+J8dUakXhaB0=";
        })
      ];
    };
    rules_cc = moduleSource {
      name = "rules_cc";
      version = "0.0.11";
      url = "https://github.com/bazelbuild/rules_cc.git";
      ref = "0.0.11";
      rev = "be5e15fc2783b11573a9f82d8d89f0c940728fe1";
      hash = "sha256-a+1+ubbnx27sEGPCqAQrSy71x8mk56BTleHoVQh7R5I=";
    };
    rules_proto = prepareModule {
      pname = "bazel-rules-proto-source";
      version = "6.0.0";
      source = rulesProtoSource;
      patches = [
        (registryPatch "rules_proto" "6.0.0" {
          name = "module_dot_bazel_version.patch";
          hash = "sha256-fjQjxMdkMeumhvx9JdFSYeHH+Ex4TaTXNFMi554NF8E=";
        })
      ];
    };
    googleapis = bazelSource + "/third_party/googleapis";
    rules_java = moduleSource {
      name = "rules_java";
      version = "7.6.5";
      url = "https://github.com/bazelbuild/rules_java.git";
      ref = "7.6.5";
      rev = "628fc4a0f376a6066f8bcb3221f1044764f270e1";
      hash = "sha256-npz1Ne4h8l5GofKKvmg3HKqvBA/E1IMRIFPXdSaGSIw=";
    };
    protobuf = prepareModule {
      pname = "bazel-protobuf-source";
      version = "21.7";
      source = protobufSource;
      # The Git checkout already contains all five conformance files that
      # the registry restores to the release archive with add_missing_files.patch.
      patches = map (registryPatch "protobuf" "21.7") [
        {
          name = "add_module_dot_bazel.patch";
          hash = "sha256-q3V2+eq0v2XF0z8z+V+QF4cynD6JvHI1y3kI/+rzl5s=";
        }
        {
          name = "add_module_dot_bazel_for_examples.patch";
          hash = "sha256-O7YP6s3lo/1opUiO0jqXYORNHdZ/2q3hjz1QGy8QdIU=";
        }
        {
          name = "relative_repo_names.patch";
          hash = "sha256-RK9RjW8T5UJNG7flIrnFiNE9vKwWB+8uWWtJqXYT0w4=";
        }
      ];
    };
    grpc = prepareModule {
      pname = "bazel-grpc-source";
      version = "1.48.1.bcr.1";
      source = grpcSource;
      patches = [
        (registryPatch "grpc" "1.48.1.bcr.1" {
          name = "adopt_bzlmod.patch";
          hash = "sha256-iMrebRKNKLNqVtRX+4eRZ63QcBr2t8Zo/ZvBPjVnyw8=";
        })
        (bazelSource + "/third_party/grpc/00_disable_layering_check.patch")
      ];
    };
  }
