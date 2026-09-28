##! Pinned source modules for Bazel 9's download-disabled dependency graph.
{
  buildPackages,
  fetchgit,
  bazelSource,
  rulesGraalvmBase,
  rulesKotlin,
  zstdJniBase,
}: let
  moduleSource = import ./_bazel-module-source.nix {
    inherit buildPackages fetchgit;
  };
  prepareModule = import ./_bazel-module-prepared.nix {inherit buildPackages;};
  rulesAppleSource = moduleSource {
    name = "rules_apple";
    version = "4.3.1";
    url = "https://github.com/bazelbuild/rules_apple.git";
    ref = "4.3.1";
    rev = "7ffad20eb1c7816bb7e7ab64f19a001ee3887e00";
    hash = "sha256-WL2rcpmOVkmpu27UPy8JkOaytpz5FYz6mS8BRincF2o=";
  };
  googleapisSource = moduleSource {
    name = "googleapis";
    version = "0.0.0-20250604-de157ca3";
    url = "https://github.com/googleapis/googleapis.git";
    rev = "de157ca34fa487ce248eb9130293d630b501e4ad";
    fetchCommit = true;
    hash = "sha256-biJrNhGmm6bNWp63T7qSX+pjO3G0t2E5sFsptg7H5VE=";
  };
  googleapisRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/googleapis/0.0.0-20250604-de157ca3";
  googleapisRegistrySource = prepareModule {
    pname = "bazel-googleapis-registry-source";
    version = "0.0.0-20250604-de157ca3";
    source = googleapisSource;
    patchStrip = 0;
    # The module creation patch overlaps the registry's complete MODULE file.
    # Apply it to the source first, then retain the pinned final definition.
    overlaysAfterPatches = true;
    overlays = builtins.mapAttrs (name: hash:
      buildPackages.fetchurl {
        urls = ["${googleapisRegistryRoot}/overlay/${name}"];
        inherit hash;
      }) {
      "MODULE.bazel" = "sha256-3mBEvw7fePH1G4AKBjPcfdMFqvbuh4EWdX+YzRoFR30=";
      "extensions.bzl" = "sha256-18dc+oJEnOppNXZCBWCZQgRi1lIlOooLjhV0FP2ry8c=";
      "tests/bcr/.bazelrc" = "sha256-hFZT+gits3VtXcUkKuh3NCEC9FgBNGuNxaOVCuOiFPk=";
      "tests/bcr/BUILD.bazel" = "sha256-KZzDURLUNDOiMsurUHrnuWYogHPFs7W+Ar9ZrilPLuE=";
      "tests/bcr/MODULE.bazel" = "sha256-4zmBG1uAn7W3ExjUMQChBcrJVSNCE6K8PhIs9SfKy1U=";
      "tests/bcr/failure_test.bzl" = "sha256-pKImfWiY7m3EB1w0n4C66/LABDBwTYr/2nqxoC+gvBc=";
    };
    patches = map (patch:
      buildPackages.fetchurl {
        urls = ["${googleapisRegistryRoot}/patches/${patch.name}"];
        inherit (patch) hash;
      }) [
      {
        name = "module_dot_bazel.patch";
        hash = "sha256-Qemq+hByZrQXIY7ElAswlzMJ+I6muXiCFW5LJ/c9rZk=";
      }
      {
        name = "remove_upb_c_rules.patch";
        hash = "sha256-MmXB+YzXhG05hDbVgw5S/VZRgu4b2qjQl0OHVEEtP7Y=";
      }
    ];
  };
  zlibSource = moduleSource {
    name = "zlib";
    version = "1.3.1";
    url = "https://github.com/madler/zlib.git";
    ref = "v1.3.1";
    rev = "51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf";
    hash = "sha256-TkPLWSN5QcPlL9D0kc/yhH0/puE9bFND24aj5NVDKYs=";
  };
  grpcJavaSource = moduleSource {
    name = "grpc-java";
    version = "1.71.0";
    url = "https://github.com/grpc/grpc-java.git";
    ref = "v1.71.0";
    rev = "865c4432569dfdf738b3cf07bcdb6d6e3285f761";
    hash = "sha256-90h/WXRDHwNPuwruaPzeDMv2kahswbXFaQXjTHdUbr0=";
  };
  rulesSwiftSource = moduleSource {
    name = "rules_swift";
    version = "3.3.0";
    url = "https://github.com/bazelbuild/rules_swift.git";
    ref = "3.3.0";
    rev = "df2e46cc4cea180cb563813e16872ac6b37958ad";
    hash = "sha256-GHbg1fk+EROsUTrIbO2vrfU2DH1C76Pxqz0RGp4bDD0=";
  };
  blake3Source = moduleSource {
    name = "blake3";
    version = "1.8.2";
    url = "https://github.com/BLAKE3-team/BLAKE3.git";
    ref = "1.8.2";
    rev = "df610ddc3b93841ffc59a87e3da659a15910eb46";
    hash = "sha256-IABVErXWYQFXZcwsFKfQhm3ox7UZUcW5uzVrGwsSp94=";
  };
  rulesProtoSource = moduleSource {
    name = "rules_proto";
    version = "7.1.0";
    url = "https://github.com/bazelbuild/rules_proto.git";
    ref = "7.1.0";
    rev = "4904e1ca79182d5a3779ecbd23273285ccd70e5c";
    hash = "sha256-jWGvbaV+mbat8ZY+VHE+N1ccieMgIlUkyphp9FFBH7k=";
  };
  rulesPerlSource = moduleSource {
    name = "rules_perl";
    version = "0.2.4";
    url = "https://github.com/bazel-contrib/rules_perl.git";
    ref = "0.2.4";
    rev = "e8d828565046868d5b4d3f9b6544878a24665cd0";
    hash = "sha256-QZ+CfMLuH1tItSHbZM48Ox5NvP8rVAI1ROmum8edRpM=";
  };
  protobufSource = moduleSource {
    name = "protobuf";
    version = "33.4";
    url = "https://github.com/protocolbuffers/protobuf.git";
    ref = "v33.4";
    rev = "edaa823d8b36a8656d7b2b9241b7d0bfe50af878";
    hash = "sha256-qn/bKcRml8b45On9gFBVLa+q8ay55NAJff1KDxfz9zM=";
  };
  registryRevision = "18e405773f40bfe226ef2e2ea7bc0f1a71d39fd9";
  grpcRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/grpc/1.76.0.bcr.1";
  grpcSource = moduleSource {
    name = "grpc";
    version = "1.76.0";
    url = "https://github.com/grpc/grpc.git";
    ref = "v1.76.0";
    rev = "f5ffb68d8a2fd603dff16287e90a4ac571e1fec6";
    hash = "sha256-ztygAJdjRTGlr7Dgq7aENX+8x9ZJuutp1uzr6uE7i3E=";
  };
  grpcModule = buildPackages.fetchurl {
    urls = ["${grpcRegistryRoot}/overlay/MODULE.bazel"];
    hash = "sha256-CbJSU2ESrMzcdUfN/hZSakZAj1cCY/cUkcgTMV8u/EU=";
  };
  grpcPatches = map (patch:
    buildPackages.fetchurl {
      urls = ["${grpcRegistryRoot}/patches/${patch.name}"];
      inherit (patch) hash;
    }) [
    {
      name = "adopt_bzlmod.patch";
      hash = "sha256-VcTAEbxQ5NmrwoZBGweeHOSDIjttotQ2JcfJjUvqTgI=";
    }
    {
      name = "bazel_9_fixes.patch";
      hash = "sha256-bP6aPsx4nrUJvTqzXT/u2xnPWpfO8G/u/wpBeWwDuGs=";
    }
    {
      name = "add_repo_bazel.patch";
      hash = "sha256-MNvogHhurl0FIY6o4tqWv/OfrAO3UAVE9bh7R/ZCMSI=";
    }
  ];
in {
  rules_apple = prepareModule {
    pname = "bazel-rules-apple-source";
    version = "4.3.1";
    source = rulesAppleSource;
    patches = [
      (buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/rules_apple/4.3.1/patches/module_dot_bazel_version.patch"];
        hash = "sha256-d4o/pxZsSxdKwEglKXwpS7rQSYWR+/iQxYbDhxB8mvo=";
      })
    ];
  };
  googleapis = prepareModule {
    pname = "bazel-googleapis-source";
    version = "0.0.0-20250604-de157ca3";
    source = googleapisRegistrySource;
    patches = [(bazelSource + "/third_party/googleapis.patch")];
  };
  rules_kotlin = rulesKotlin;
  zstd-jni = prepareModule {
    pname = "bazel-zstd-jni-source";
    version = "1.5.6-9";
    source = zstdJniBase;
    patches = [(bazelSource + "/third_party/zstd-jni.patch")];
  };
  zlib = prepareModule {
    pname = "bazel-zlib-source";
    version = "1.3.1.bcr.7";
    source = zlibSource;
    patchStrip = 0;
    patches = map (patch:
      buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/zlib/1.3.1.bcr.7/patches/${patch.name}"];
        inherit (patch) hash;
      }) [
      {
        name = "add_build_file.patch";
        hash = "sha256-NnTdCi/k9eS3+ChEbqCj8K6+iIL/vdE11Tzx1Ey2rYw=";
      }
      {
        name = "module_dot_bazel.patch";
        hash = "sha256-p+f/zK1aUs+txvNBeC6MJMMYxADVbnsTH5KRN3sAe4o=";
      }
    ];
  };
  grpc-java = prepareModule {
    pname = "bazel-grpc-java-source";
    version = "1.71.0";
    source = grpcJavaSource;
    # The registry patch requires context fuzz against the release source.
    # Pin its resulting module directly and apply code patches with zero fuzz.
    moduleFile = buildPackages.fetchurl {
      urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/grpc-java/1.71.0/MODULE.bazel"];
      hash = "sha256-oMqEkJoRnOJPWWaXj9tKuFe83bWGazSvLmk/xmSNsig=";
    };
    patches = [
      (bazelSource + "/third_party/grpc-java.patch")
      (bazelSource + "/third_party/grpc-java-12207.patch")
      (bazelSource + "/third_party/grpc-java-12222.patch")
      (bazelSource + "/third_party/grpc-java-addloads.patch")
    ];
  };
  rules_swift = prepareModule {
    pname = "bazel-rules-swift-source";
    version = "3.3.0";
    source = rulesSwiftSource;
    patches = [
      (buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/rules_swift/3.3.0/patches/module_dot_bazel_version.patch"];
        hash = "sha256-XCLbSbW0Xj4cF7VU6Kj5BXtQsNzt7q2hsEHJYbpFqtY=";
      })
    ];
  };
  rules_graalvm = prepareModule {
    pname = "bazel-rules-graalvm-source";
    version = "0.11.1";
    # Both versions share the pinned registry overlay and first two patches.
    # Bazel 9 adds explicit Java rule loads and migrated rule definitions.
    source = rulesGraalvmBase;
    patches = [
      (bazelSource + "/third_party/rules_graalvm_load_fix.patch")
      (bazelSource + "/third_party/rules_graalvm_bazel9_fixes.patch")
    ];
  };
  "abseil-cpp" = moduleSource {
    name = "abseil-cpp";
    version = "20250814.1";
    url = "https://github.com/abseil/abseil-cpp.git";
    ref = "20250814.1";
    rev = "d38452e1ee03523a208362186fd42248ff2609f6";
    hash = "sha256-SCQDORhmJmTb0CYm15zjEa7dkwc+lpW2s1d4DsMRovI=";
  };
  re2 = moduleSource {
    name = "re2";
    version = "2025-11-05.bcr.1";
    url = "https://github.com/google/re2.git";
    ref = "2025-11-05";
    rev = "927f5d53caf8111721e734cf24724686bb745f55";
    hash = "sha256-0J1HVk+eR7VN0ymucW9dNlT36j16XIfCzcs1EVyEIEU=";
  };
  blake3 = prepareModule {
    pname = "bazel-blake3-source";
    version = "1.8.2";
    source = blake3Source;
    patches = [];
    overlays = builtins.mapAttrs (name: hash:
      buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/blake3/1.8.2/overlay/${name}"];
        inherit hash;
      }) {
      "BUILD.bazel" = "sha256-WMNSGBdxrKmjDJtzbX84+Gjix1Or8mhXU6CzcHmwNNE=";
      "MODULE.bazel" = "sha256-cpGnW7rjJprMXhN7GbAEKSI2MhNcGRjhKFVZW8ql0Bc=";
      "c/BUILD.bazel" = "sha256-RBb2IsLnS9VC5B34u0izaV07FJes2srRvB1XnzCCRVU=";
    };
  };
  rules_proto = prepareModule {
    pname = "bazel-rules-proto-source";
    version = "7.1.0";
    source = rulesProtoSource;
    patches = map (patch:
      buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/rules_proto/7.1.0/patches/${patch.name}"];
        inherit (patch) hash;
      }) [
      {
        name = "module_dot_bazel_version.patch";
        hash = "sha256-GFtfNnjXlShEmp3o0HiTq8AWf0YpNxLkmGVMt98QcfI=";
      }
      {
        name = "MODULE.bazel.patch";
        hash = "sha256-QC5hjx/QZTZ3deil1x9qT0Ni6G1+ZiFaQ+xGHtXR0HE=";
      }
    ];
  };
  rules_perl = prepareModule {
    pname = "bazel-rules-perl-source";
    version = "0.2.4";
    source = rulesPerlSource;
    patchStrip = 0;
    patches = [
      (buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/rules_perl/0.2.4/patches/module_dot_bazel_version.patch"];
        hash = "sha256-pNzMxPUBCZaEvGJNW2eZR8X8UoF/pAYzrn/OC7/Fbmg=";
      })
    ];
  };
  grpc = buildPackages.mkDerivation {
    pname = "bazel-grpc-source";
    version = "1.76.0.bcr.1";
    src = grpcSource;
    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir grpc-source
          cp -a "$src"/. grpc-source/
          chmod -R u+w grpc-source
          cd grpc-source
        '';
      }
      {
        name = "build";
        script = ''
          cp ${grpcModule} MODULE.bazel
          ${builtins.concatStringsSep "\n" (map (patch: "patch --batch --fuzz=0 -p1 < ${patch}") grpcPatches)}
          cmp MODULE.bazel ${grpcModule}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -a . "$out"/
        '';
      }
    ];
  };
  protobuf = buildPackages.mkDerivation {
    pname = "bazel-protobuf-source";
    version = "33.4";
    src = protobufSource;
    buildDeps = [buildPackages.patch];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir protobuf-source
          cp -a "$src"/. protobuf-source/
          chmod -R u+w protobuf-source
          cd protobuf-source
        '';
      }
      {
        name = "build";
        script = ''
          # Preserve Bazel's pinned visibility, gRPC, and Java generator fixes.
          patch --batch --fuzz=0 -p1 < ${bazelSource}/third_party/protobuf.patch
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -a . "$out"/
        '';
      }
    ];
  };
  "with_cfg.bzl" = moduleSource {
    name = "with_cfg.bzl";
    version = "0.13.0";
    url = "https://github.com/fmeum/with_cfg.bzl.git";
    ref = "v0.13.0";
    rev = "5aecccb322a82cd35d7ea371a76bd0b918a1d157";
    hash = "sha256-RNN3nGonP82ALGh+99xG+C+q7gsQr2L40LMArmLotKw=";
  };
  bazel_skylib = moduleSource {
    name = "bazel_skylib";
    version = "1.8.2";
    url = "https://github.com/bazelbuild/bazel-skylib.git";
    ref = "1.8.2";
    rev = "bce8d7f8de2e48033e771f9ccdd721edf9df84e8";
    hash = "sha256-iErRflWgJWlXw0iKQDpolWTqjiUSGwgW3owTdfQt+mI=";
  };
  rules_python = moduleSource {
    name = "rules_python";
    version = "1.7.0";
    url = "https://github.com/bazelbuild/rules_python.git";
    ref = "1.7.0";
    rev = "d3ea893113375b0c0f788c3315d8a8f488d69af6";
    hash = "sha256-MThkBmljMrE+AnFP6kxODfYJMk5dQnFcf98mKhNXVKY=";
  };
  rules_java = moduleSource {
    name = "rules_java";
    version = "9.1.0";
    url = "https://github.com/bazelbuild/rules_java.git";
    ref = "9.1.0";
    rev = "b6856588ba834750a1e66b2dd1b274a1f09f66a5";
    hash = "sha256-imlMmHqXbWjgcTqf4QjUd8HJ8M1Y+N8ZWO6jzOqPmHc=";
  };
  rules_cc = moduleSource {
    name = "rules_cc";
    version = "0.2.17";
    url = "https://github.com/bazelbuild/rules_cc.git";
    ref = "0.2.17";
    rev = "541eda5d72e9b5f18e6a24e8d14975afcd865717";
    hash = "sha256-at7x89kYLuHj73nlJCFXTJPS8qfEwSucw3sIXpr/74M=";
  };
  rules_license = moduleSource {
    name = "rules_license";
    version = "1.0.0";
    url = "https://github.com/bazelbuild/rules_license.git";
    ref = "1.0.0";
    rev = "f85e7d6309f28f031bf049f7d6283ce0d41d7546";
    hash = "sha256-GTSHr08f0eSfV8QQ7YdlxEZt1sEkdzLXSFBcMs0YSdk=";
  };
  rules_pkg = moduleSource {
    name = "rules_pkg";
    version = "1.1.0";
    url = "https://github.com/bazelbuild/rules_pkg.git";
    ref = "1.1.0";
    rev = "cd7e10846f97b5cb9b184c87b4ceaf2f1b4b5d3f";
    hash = "sha256-e7DcJ2HAecG7FFReZSdKf1kRGdc1AceAm3vdv8YmdD8=";
  };
  rules_shell = moduleSource {
    name = "rules_shell";
    version = "0.6.1";
    url = "https://github.com/bazelbuild/rules_shell.git";
    ref = "v0.6.1";
    rev = "e071f45e209f3e154210faed3d0e60c29aef3b4a";
    hash = "sha256-iG86PImWmE5Lrp04T54y0HK0C3xC4aAOX20Z9IKB3kI=";
  };
  rules_testing = moduleSource {
    name = "rules_testing";
    version = "0.9.0";
    url = "https://github.com/bazelbuild/rules_testing.git";
    ref = "v0.9.0";
    rev = "db007bfee840cebcb6f955b80973ba866de38947";
    hash = "sha256-gOSBH/RXHn14m+4hTE48lN9xkC4BiqwcLyo5WQy0TsU=";
  };
  rules_jvm_external = prepareModule {
    pname = "bazel-rules-jvm-external-source";
    version = "6.6";
    source = moduleSource {
      name = "rules_jvm_external";
      version = "6.6";
      url = "https://github.com/bazelbuild/rules_jvm_external.git";
      ref = "6.6";
      rev = "664b49e9583d04325fc6f1d8fba38e14fb707c19";
      hash = "sha256-4Er3/DlM+gDb/AskcWHYXxDFAzFW5UIdw1G0dHaP018=";
    };
    patches = [(bazelSource + "/third_party/rules_jvm_external_6.5.patch")];
  };
  bazel_features = moduleSource {
    name = "bazel_features";
    version = "1.42.1";
    url = "https://github.com/bazel-contrib/bazel_features.git";
    ref = "v1.42.1";
    rev = "0b1ba9d4606e0bf4cc9a1694f7cb2e114792cc22";
    hash = "sha256-L3Pie9ISaMdMJhR757DGOXIJXaiaxX+XsMiUHMxynKk=";
  };
  rules_go = moduleSource {
    name = "rules_go";
    version = "0.59.0";
    url = "https://github.com/bazel-contrib/rules_go.git";
    ref = "v0.59.0";
    rev = "b3e12d797150cdc36f27e72f52f6a5c752762641";
    hash = "sha256-bsA2HO2shINGB7PMMCRIIAN/UtBo9uge0qcILBByYGY=";
  };
  platforms = moduleSource {
    name = "platforms";
    version = "1.0.0";
    url = "https://github.com/bazelbuild/platforms.git";
    ref = "1.0.0";
    rev = "ab99943ab6bed53cff461a3afa99fc79d31e4351";
    hash = "sha256-8MRSiwq+ghdB9vNMuczbJxx/K6iNEiVbKRPJTllp7SA=";
  };
  apple_support = moduleSource {
    name = "apple_support";
    version = "1.24.5";
    url = "https://github.com/bazelbuild/apple_support.git";
    ref = "1.24.5";
    rev = "8aad6327b63f91873ab364b49ae67d4313fed939";
    hash = "sha256-Sz4IWoOfW51y/N1PFSktco7XTHUWwWAPKi8E7mvJNNY=";
  };
  stardoc = moduleSource {
    name = "stardoc";
    version = "0.8.0";
    url = "https://github.com/bazelbuild/stardoc.git";
    ref = "0.8.0";
    rev = "7c2aebded256dfe123c17360ec546512991544c8";
    hash = "sha256-n8zoRvIHvnWXc5MyHIApZz8HLHlMO96TWRCc1SWHUi8=";
  };
}
