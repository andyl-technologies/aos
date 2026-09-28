##! Bazel 7's pinned protocol dependencies and in-tree Google API source.
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
in
  sharedModules
  // {
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
      # The Git checkout already contains all five conformance source files that
      # the registry restores to its release archive with add_missing_files.patch.
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
