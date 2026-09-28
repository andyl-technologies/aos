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
  ciRulesSource = moduleSource {
    name = "bazel-ci-rules";
    version = "2.0.0";
    url = "https://github.com/bazelbuild/continuous-integration.git";
    ref = "rules-2.0.0";
    rev = "426a2e8906b6a61100428bb33530aa44f62fab91";
    sparseDirectories = ["rules"];
    hash = "sha256-SpOUApI0MtIUsTsuE+0KhMJ0Lnz66THa1ZKC4lxKpZM=";
  };
  xdsSource = moduleSource {
    name = "xds";
    version = "0.0.0-20240423-555b57e";
    url = "https://github.com/cncf/xds.git";
    rev = "555b57ec207be86f811fb0c04752db6f85e3d7e2";
    fetchCommit = true;
    hash = "sha256-eLY6COTGXMTUrVARdNHUh0Zm3SDGnN7yz3qSr7FZIpg=";
  };
  protocGenValidateSource = moduleSource {
    name = "protoc-gen-validate";
    version = "1.2.1";
    url = "https://github.com/bufbuild/protoc-gen-validate.git";
    ref = "v1.2.1";
    rev = "7b06248484ceeaa947e93ca2747eccf336a88ecc";
    hash = "sha256-kGnfR8o12bvjJH+grAwlYezF6UzWt7lgjGslq+07p3k=";
  };
  caresSource = moduleSource {
    name = "c-ares";
    version = "1.34.5";
    url = "https://github.com/c-ares/c-ares.git";
    ref = "v1.34.5";
    rev = "d3a507e920e7af18a5efb7f9f1d8044ed4750013";
    hash = "sha256-MeQ4eqt7QyRD7YVomXR+fwBzraiYe2s2Eozz0sE8Xgo=";
  };
  caresRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/c-ares/1.34.5.bcr.2";
  googleapisRulesSource = moduleSource {
    name = "googleapis-rules-registry";
    version = "1.0.0";
    url = "https://github.com/fmeum/googleapis-rules-registry.git";
    ref = "v1.0.0";
    rev = "c3488f8c74d8611faca2b19b8bcfd85aae9b0677";
    hash = "sha256-hnT88D4i9OR6dGk3uqH2KDdAVqG6u921n9KnDArMhwY=";
  };
  googleapisRulesModule = name:
    prepareModule {
      pname = "bazel-${name}-source";
      version = "1.0.0";
      source = googleapisRulesSource + "/${name}";
      patches = [];
    };
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
  buildozer = prepareModule {
    pname = "bazel-buildozer-source";
    version = "8.5.1";
    source = moduleSource {
      name = "buildozer";
      version = "8.5.1";
      url = "https://github.com/fmeum/buildozer.git";
      ref = "v8.5.1";
      rev = "e0d9bca2fcd7a233136ec206b85004c5f178f62b";
      hash = "sha256-2MwTsjNM4Mdi2VCjJWDx6py1nDB+3oJIgyrBIi1CV38=";
    };
    patches = [
      (buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/buildozer/8.5.1/patches/module_dot_bazel_version.patch"];
        hash = "sha256-MmTYJnlP+HcNSelJzhZhSADHPFRH04muufK2v1aa+h0=";
      })
    ];
  };
  google_benchmark = moduleSource {
    name = "google-benchmark";
    version = "1.9.4";
    url = "https://github.com/google/benchmark.git";
    ref = "v1.9.4";
    rev = "eddb0241389718a23a42db6af5f0164b6e0139af";
    extraExcludes = ["!/docs/assets/images"];
    hash = "sha256-41DXV3FqcDYMdZ82nLgVfT6Td3eFljyz7KvbbUjCDW4=";
  };
  onetbb = prepareModule {
    pname = "bazel-onetbb-source";
    version = "2022.2.0";
    source = moduleSource {
      name = "onetbb";
      version = "2022.2.0";
      url = "https://github.com/uxlfoundation/oneTBB.git";
      ref = "v2022.2.0";
      rev = "06ce6212da6710f4bb2d20a1904b018aa44069bf";
      # Retain library sources while omitting documentation artwork and the
      # precompiled interface resource of an unrelated example application.
      extraExcludes = ["!/doc" "!/rfcs" "!*.nib" "!*.ico" "!*.gif"];
      hash = "sha256-NGKel1zeZpfix1f2dB+EvCrLXyxo+CjSYXbpCQaUHz4=";
    };
    overlays = builtins.mapAttrs (name: hash:
      buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/onetbb/2022.2.0/overlay/${name}"];
        inherit hash;
      }) {
      "BUILD.bazel" = "sha256-H0/685f789c6XLGbwcIyM1wEpXjOM9JCoCSj+NKf7D4=";
      "MODULE.bazel" = "sha256-WNOp+UFC30zSzJQcykgIr9sNcVYb5eWQMDXMnwBvOHo=";
    };
    patches = [];
  };
  googletest = prepareModule {
    pname = "bazel-googletest-source";
    version = "1.17.0.bcr.2";
    source = moduleSource {
      name = "googletest";
      version = "1.17.0";
      url = "https://github.com/google/googletest.git";
      ref = "v1.17.0";
      rev = "52eb8108c5bdec04579160ae17225d66034bd723";
      hash = "sha256-HIHMxAUR4bjmFLoltJeIAVSulVQ6kVuIT2Ku+lwAx/4=";
    };
    patchStrip = 0;
    patches = map (patch:
      buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/googletest/1.17.0.bcr.2/patches/${patch.name}"];
        inherit (patch) hash;
      }) [
      {
        name = "build_bazel.patch";
        hash = "sha256-tMYspfSBszCA4xVp42vVtO8g5849WEI/04pQCChQl7g=";
      }
      {
        name = "module_bazel.patch";
        hash = "sha256-t2dRUpBMah/K9CX63jyJtEwo7rLSxwjQA4zoFg0pEfU=";
      }
      {
        name = "50b8600c.patch";
        hash = "sha256-DfY+cJQfUwVsahNZUftiU3Noc4z1O1dPu8ckCseO7qg=";
      }
    ];
  };
  wabt = prepareModule {
    pname = "bazel-wabt-source";
    version = "1.0.37";
    source = moduleSource {
      name = "wabt";
      version = "1.0.37";
      url = "https://github.com/WebAssembly/wabt.git";
      ref = "1.0.37";
      rev = "5e81f6aeddf94fd7743c8c2049f5084c74ff6ab1";
      hash = "sha256-1Yn9lavn5rtdm1R5xNRkbkUwspGTe7V09LTcKSdCUqg=";
      extraExcludes = ["!/test" "!/docs"];
    };
    overlays = builtins.mapAttrs (name: hash:
      buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/wabt/1.0.37/overlay/${name}"];
        inherit hash;
      }) {
      "BUILD.bazel" = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
      "MODULE.bazel" = "sha256-w5B+rW+YNI3wmPOABhxcnY9KyaYK79z4ORninDB3faA=";
      "build/BUILD.bazel" = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
      "build/wabt_build.bzl" = "sha256-t6gvWTSYW0jdwM2fTy7Afor07fPEg3cCuPwLGLp75uk=";
      "include/wabt/BUILD.bazel" = "sha256-Ee2jCK8Yi73cfaVkmhQEVdOLA47Cn9r6UD/w+Z9m+hE=";
      "src/BUILD.bazel" = "sha256-gmn6MOmrOkI6DkybedMq3uR5xJ4385Mu3Tb7AU2G+b4=";
      "src/tools/BUILD.bazel" = "sha256-hW7TDmzsvtYO69A79n2nVSp/m3KuhBdwrIaMz56gBrE=";
      "third_party/picosha2/BUILD.bazel" = "sha256-OMR47fn/GTIk4IQizwgHJPxEySq1qkBBuZGlzW3G3Qg=";
      "third_party/wasm-c-api/BUILD.bazel" = "sha256-Gacj2iQv+/54ih5TnVwq4zCIyaBGWrGqj1UbshSr2GI=";
    };
    patches = [];
  };
  rules_fuzzing = prepareModule {
    pname = "bazel-rules-fuzzing-source";
    version = "0.6.0";
    source = moduleSource {
      name = "rules-fuzzing";
      version = "0.6.0";
      url = "https://github.com/bazel-contrib/rules_fuzzing.git";
      ref = "v0.6.0";
      rev = "e6a9720d7bfa8d7c01df1151722fd9377d306bab";
      hash = "sha256-a/TjhjYDv/HYaZyH5svvNAbq2oxnFdKtudYudgwAR8o=";
    };
    patches = [
      (buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/rules_fuzzing/0.6.0/patches/module_dot_bazel_version.patch"];
        hash = "sha256-bwykr2MuQBRkcjo3eGjonIpeGKFiv1DbosSZXJ07tt8=";
      })
    ];
  };
  bazel_ci_rules = prepareModule {
    pname = "bazel-ci-rules-source";
    version = "2.0.0";
    source = ciRulesSource + "/rules";
    patches = [];
  };
  xds = prepareModule {
    pname = "bazel-xds-source";
    version = "0.0.0-20240423-555b57e";
    source = xdsSource;
    patches = [
      (buildPackages.fetchurl {
        urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/xds/0.0.0-20240423-555b57e/patches/bzlmod.patch"];
        hash = "sha256-zrpUCLxhXC7WrPx1SB5ZXy1xROlKk8ZOEaYkwCdiZg4=";
      })
    ];
  };
  protoc-gen-validate = prepareModule {
    pname = "bazel-protoc-gen-validate-source";
    version = "1.2.1.bcr.1";
    source = protocGenValidateSource;
    moduleFile = buildPackages.fetchurl {
      urls = ["https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/protoc-gen-validate/1.2.1.bcr.1/overlay/MODULE.bazel"];
      hash = "sha256-S/CWdrYvpYeuB+BzQgp27Idm3M51ReX4xoz6jkhLUSA=";
    };
    patches = [(bazelSource + "/third_party/protoc-gen-validate.patch")];
  };
  c-ares = prepareModule {
    pname = "bazel-c-ares-source";
    version = "1.34.5.bcr.2";
    source = caresSource;
    patches = [];
    overlays = builtins.mapAttrs (name: hash:
      buildPackages.fetchurl {
        urls = ["${caresRegistryRoot}/overlay/${name}"];
        inherit hash;
      }) {
      "REPO.bazel" = "sha256-ATsuuuEy6sq6KDwrG2UUUOpazWHV9alEqqgMgUNzUTs=";
      "BUILD.bazel" = "sha256-1+l9iZQha2wglZonkBVbl6HEoFk8IHX2UTwUPHfS/K0=";
      "MODULE.bazel" = "sha256-dAoQthKAad2p9f3crfbfWDPgLodJeo17JAcHYZe/J8g=";
      "configs/ares_build.h" = "sha256-P4N/yKYYgfpqTsK+UPR1zYM/YPvSf1Joim9zNmnM2o4=";
      "configs/config_android/ares_config.h" = "sha256-o7Z0jA5pjw24FfOD3cliaIKsJbl9+yaj6SL9/BCEGfk=";
      "configs/config_darwin/ares_config.h" = "sha256-9uKPfRa8jxEdbKMSm7ABJ9NXqPXIv8c9p0YlMoQVtcY=";
      "configs/config_freebsd/ares_config.h" = "sha256-8R8Z4GcRbjssa4BdutiaRcNZnxNYkB3uphxqRAXMjkY=";
      "configs/config_linux/ares_config.h" = "sha256-jTDrf69PC4GRU8R28BZppydUVI4SFlnHOSg3jRLTfqI=";
      "configs/config_openbsd/ares_config.h" = "sha256-vU7qUaAiscCW9bw4+SjLNnPqbbj8hpKQ7jst0x9xYtU=";
      "configs/config_windows/ares_config.h" = "sha256-ai/WNOv3agYcaIZNDYPrvASwAAWFJYhthOrrK3r4sRw=";
    };
  };
  googleapis-rules-registry = googleapisRulesModule "googleapis-rules-registry";
  googleapis-java = googleapisRulesModule "googleapis-java";
  googleapis-grpc-java = googleapisRulesModule "googleapis-grpc-java";
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
          # The retained binary integrity table names protoc 33.0. Validate the
          # source-built compiler against the library's real 33.4 version.
          patch --batch --forward --fuzz=0 -p1 < ${./bazel-patches/protobuf-source-toolchain-version.patch}
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
