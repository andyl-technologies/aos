##! Pinned source modules for Bazel 8's download-disabled bootstrap graph.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
  bazelSource8,
}: let
  moduleSource = import ./_bazel-module-source.nix {inherit fetchgit buildPackages;};
  registryRevision = "18e405773f40bfe226ef2e2ea7bc0f1a71d39fd9";
  grpcRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/grpc/1.66.0.bcr.2";

  grpcSource = moduleSource {
    name = "grpc";
    version = "1.66.0";
    url = "https://github.com/grpc/grpc.git";
    ref = "v1.66.0";
    rev = "13cecab1c4f45902197a9f8fe4e787eb9c4d4db1";
    hash = "sha256-z/eMNWpnOZBqfyqWmXHkZXzAwwVs2uzgKlQ3mAZshlE=";
  };
  grpcModule = fetchurl {
    urls = ["${grpcRegistryRoot}/MODULE.bazel"];
    hash = "sha256-D6Kw/QKM41T+vw/pDx7Y/s+/wzEYzd2VrAQYzCgzM6A=";
  };
  grpcPatches = [
    (fetchurl {
      urls = ["${grpcRegistryRoot}/patches/add_module_bazel.patch"];
      hash = "sha256-e9fko9TGrDkj30T+Py0JwEJDjHtBoPGcgwQGnIGYrNg=";
    })
    (fetchurl {
      urls = ["${grpcRegistryRoot}/patches/adopt_bzlmod.patch"];
      hash = "sha256-lURfsZ7KmQyn5dvf0hZMnEQ2xoiGPVcMiNQMcC/yID4=";
    })
    (fetchurl {
      urls = ["${grpcRegistryRoot}/patches/disable-layering-check.patch"];
      hash = "sha256-/QbrEMxke9gUgbFjpMTKEk3y1NGk/56CeyWQgl6JEWI=";
    })
  ];

  googleapisRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/googleapis/0.0.0-20240819-fe8ba054a";
  googleapisSource = moduleSource {
    name = "googleapis";
    version = "0.0.0-20240819-fe8ba054a";
    url = "https://github.com/googleapis/googleapis.git";
    rev = "fe8ba054ad4f7eca946c2d14a63c3f07c0b586a0";
    hash = "sha256-0odOAFekdecyPZNrSimUnFOctksVMEZjTpPmE9DbexU=";
    fetchCommit = true;
  };
  googleapisPatch = fetchurl {
    urls = ["${googleapisRegistryRoot}/patches/add_module_bazel.patch"];
    hash = "sha256-SYfuiYfFrWWpalA+agDGXVV4ZgiyouUK61JWGVaaD6A=";
  };
  googleapisModule = fetchurl {
    urls = ["${googleapisRegistryRoot}/MODULE.bazel"];
    hash = "sha256-EXt8e+cyftXWxIInRTPy29eGMTE/YHCU1GJcKCA8rN8=";
  };

  zstdJniRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/zstd-jni/1.5.6-9";
  zstdJniSource = moduleSource {
    name = "zstd-jni";
    version = "1.5.6-9";
    url = "https://github.com/luben/zstd-jni.git";
    ref = "v1.5.6-9";
    rev = "59b0b19c30b6942ad7eef8bb9a8c14e22290be3d";
    hash = "sha256-XldyA/RbW0tcet6cp05P6E/GSatZ0rCs6kOT01U8xSE=";
  };
  zstdJniModule = fetchurl {
    urls = ["${zstdJniRegistryRoot}/MODULE.bazel"];
    hash = "sha256-EwldcadY35fjpR1vSTURcZsNAl4F4SPBCpm0/JvUkTk=";
  };
  zstdJniPatches = [
    (fetchurl {
      urls = ["${zstdJniRegistryRoot}/patches/Native.java.patch"];
      hash = "sha256-ruexYrt24UCKcwzePANDdZ4+nPLzVpZrkl3o0prkE7w=";
    })
    (fetchurl {
      urls = ["${zstdJniRegistryRoot}/patches/add_build_file.patch"];
      hash = "sha256-k67/p9wSUWEfSeeLVPabVleF+lH9YLxlog1auvezsts=";
    })
    (fetchurl {
      urls = ["${zstdJniRegistryRoot}/patches/module_dot_bazel.patch"];
      hash = "sha256-6nP0rVTjiLmtC5YqCYq1bi+dQI3pcgCGIsVqZ+27H1A=";
    })
  ];

  abseilRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/abseil-cpp/20240722.0.bcr.2";
  abseilSource = moduleSource {
    name = "abseil-cpp";
    version = "20240722.0";
    url = "https://github.com/abseil/abseil-cpp.git";
    ref = "20240722.0";
    rev = "4447c7562e3bc702ade25105912dce503f0c4010";
    hash = "sha256-51jpDhdZ0n+KLmxh8KVaTz53pZAB0dHjmILFX+OLud4=";
  };
  abseilModule = fetchurl {
    urls = ["${abseilRegistryRoot}/overlay/MODULE.bazel"];
    hash = "sha256-w2YbRMnT8X8LZf+1RIlqrriRJzmOqGdTe6usGBM6ACo=";
  };
  abseilPatch = fetchurl {
    urls = ["${abseilRegistryRoot}/patches/jetson.patch"];
    hash = "sha256-KRONt49ouN+ytVat9Y9Lqqzcrd2HkZFPid1oj2wtmeg=";
  };

  zlibRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/zlib/1.3.1.bcr.5";
  zlibSource = moduleSource {
    name = "zlib";
    version = "1.3.1";
    url = "https://github.com/madler/zlib.git";
    ref = "v1.3.1";
    rev = "51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf";
    hash = "sha256-TkPLWSN5QcPlL9D0kc/yhH0/puE9bFND24aj5NVDKYs=";
  };
  zlibModule = fetchurl {
    urls = ["${zlibRegistryRoot}/MODULE.bazel"];
    hash = "sha256-7sUXtbvlSSYpRm4R2ukI0EM2QwIoPeJVgePrlEMmxMo=";
  };
  zlibPatches = [
    (fetchurl {
      urls = ["${zlibRegistryRoot}/patches/add_build_file.patch"];
      hash = "sha256-SdbiiqOKN9dcerx8E+mFC2Pd/Q2KuL67/3+50WxCJLc=";
    })
    (fetchurl {
      urls = ["${zlibRegistryRoot}/patches/module_dot_bazel.patch"];
      hash = "sha256-ln6iWXu370RclA0exBzU2YboB6sDIn76lsAzkNXWuvk=";
    })
  ];

  jvmExternalRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/rules_jvm_external/6.0";
  jvmExternalSource = moduleSource {
    name = "rules_jvm_external";
    version = "6.0";
    url = "https://github.com/bazelbuild/rules_jvm_external.git";
    ref = "6.0";
    rev = "e4bfab1096dc7f3c4246b488b8d2bb4cf70f3b23";
    hash = "sha256-tiFP2Y5nVfOrZCq7nt9Lwn+mXMw3AoK2sEjRNfJUreg=";
  };
  jvmExternalModule = fetchurl {
    urls = ["${jvmExternalRegistryRoot}/MODULE.bazel"];
    hash = "sha256-N8k6WnjTLoldUvhqjQQWF26RXaq9ApzLVZTbQi6HxJU=";
  };
  jvmExternalPatch = fetchurl {
    urls = ["${jvmExternalRegistryRoot}/patches/module_dot_bazel.patch"];
    hash = "sha256-+Ci4gFKoiHYV4zl1HFIS8JtdDSogzDh6neAEBNd+zLA=";
  };

  blake3RegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/blake3/1.5.1.bcr.1";
  blake3Source = moduleSource {
    name = "blake3";
    version = "1.5.1";
    url = "https://github.com/BLAKE3-team/BLAKE3.git";
    ref = "1.5.1";
    rev = "54930c95227daaac4dcf1eb3028e2f4e0768d139";
    hash = "sha256-STWAnJjKrtb2Xyj6i1ACwxX/gTkQo5jUHilcqcgJYxc=";
  };
  blake3Module = fetchurl {
    urls = ["${blake3RegistryRoot}/MODULE.bazel"];
    hash = "sha256-byKng3kNg0yOLJGrhYSOeB5lB4qWME6Z5FlXY2IrFxo=";
  };
  blake3Patches = [
    (fetchurl {
      urls = ["${blake3RegistryRoot}/patches/add_build_file.patch"];
      hash = "sha256-BmZOqWOTfHup68uNZXOh2mP+b971CWY3QufbkIe6eEM=";
    })
    (fetchurl {
      urls = ["${blake3RegistryRoot}/patches/module_dot_bazel.patch"];
      hash = "sha256-dKnHpXqvNwW2m7vYxnfWEoBhphBysqbeBxAMVX3b5a0=";
    })
    (fetchurl {
      urls = ["${blake3RegistryRoot}/patches/fix_windows_arm_build_pr_389.patch"];
      hash = "sha256-9G3QDBp5OuyYP7vwPKjqK+uTUZmjhLpKSE7nshz8guc=";
    })
  ];

  rulesProtoRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/rules_proto/7.0.2";
  rulesProtoSource = moduleSource {
    name = "rules_proto";
    version = "7.0.2";
    url = "https://github.com/bazelbuild/rules_proto.git";
    ref = "7.0.2";
    rev = "c138c719d7bdca9805d6974c9b3a40ebf40fb840";
    hash = "sha256-zizYBFXpD3p45a6wMBuVUWqPQPQbdC9DiBDPf9bBPCA=";
  };
  rulesProtoModule = fetchurl {
    urls = ["${rulesProtoRegistryRoot}/MODULE.bazel"];
    hash = "sha256-v4F5O9bSrYmjekBpPlbGGw7jD3p/268+q79fOd5H3qI=";
  };
  rulesProtoPatch = fetchurl {
    urls = ["${rulesProtoRegistryRoot}/patches/module_dot_bazel_version.patch"];
    hash = "sha256-kxckjuQWVpV7S42vfiX3heOtrOWXlhW/tAfaQFbgNjA=";
  };

  grpcJavaRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/grpc-java/1.66.0";
  grpcJavaSource = moduleSource {
    name = "grpc-java";
    version = "1.66.0";
    url = "https://github.com/grpc/grpc-java.git";
    ref = "v1.66.0";
    rev = "cf784069508fc5767a85c915e43bb43ccfc84c76";
    hash = "sha256-vU0Z3Y7BLa6TTxi27rPLEPPftBGUZbK+KerylxXVubM=";
  };
  grpcJavaModule = fetchurl {
    urls = ["${grpcJavaRegistryRoot}/MODULE.bazel"];
    hash = "sha256-hv8mIJ+shGrbidsR83FLPcAJD7L7gVdWc8x0iAzaTn4=";
  };
  grpcJavaPatch = fetchurl {
    urls = ["${grpcJavaRegistryRoot}/patches/module_dot_bazel.patch"];
    hash = "sha256-TUbU6+Jm8Kj2MG5uY9bxXcESlNtR4a+dTwE0MJahrQU=";
  };

  stardocRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/stardoc/0.7.1";
  stardocSource = moduleSource {
    name = "stardoc";
    version = "0.7.1";
    url = "https://github.com/bazelbuild/stardoc.git";
    ref = "0.7.1";
    rev = "2ac0981b7c35ff46cf66cc92467c37411c7bfacc";
    hash = "sha256-orS7umDGwldVTLupd6J3nf3tDvtahmw1YN1y/aVUUa4=";
  };
  stardocModule = fetchurl {
    urls = ["${stardocRegistryRoot}/MODULE.bazel"];
    hash = "sha256-NUj66k7l3aVYD5rxUOedD2rqk0/GDBzFD0792UIHWec=";
  };

  rulesAppleRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/rules_apple/3.16.0";
  rulesAppleSource = moduleSource {
    name = "rules_apple";
    version = "3.16.0";
    url = "https://github.com/bazelbuild/rules_apple.git";
    ref = "3.16.0";
    rev = "5f7d38d51351d2ff0cbe3ffb9b74c00b1294b8a6";
    hash = "sha256-0sMEz0U8FLT4QFeOGbs8fTZQy3YGIfh9lteD9IzusMk=";
  };
  rulesAppleModule = fetchurl {
    urls = ["${rulesAppleRegistryRoot}/MODULE.bazel"];
    hash = "sha256-DRyvC4N1lCzpjqlEvnVKGIdAQeTgRZQB2SVXdiTTpUo=";
  };
  rulesApplePatch = fetchurl {
    urls = ["${rulesAppleRegistryRoot}/patches/module_dot_bazel_version.patch"];
    hash = "sha256-tc1zjSKWZcwJgw84Baye8gdG6De+/REqSj9Ra17Xcoo=";
  };

  chicoryRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/chicory/1.1.0";
  chicorySource = moduleSource {
    name = "chicory";
    version = "1.1.0";
    url = "https://github.com/dylibso/chicory.git";
    ref = "1.1.0";
    rev = "469f7b273cc05db1db7ac2a5d59e91b41fcda8cc";
    hash = "sha256-+ZnY8+f8SPDj9171ovzS7H3oaLzMlinCJhbS2PHQJdo=";
    # Upstream tracks two precompiled WASM tools without file extensions.
    extraExcludes = [
      "!/wabt/src/main/resources/wat2wasm"
      "!/wabt/src/main/resources/wast2json"
    ];
  };
  chicoryPatch = fetchurl {
    urls = ["${chicoryRegistryRoot}/patches/rm-errorprone-annotations.patch"];
    hash = "sha256-l85uwkvGGeWu8n440DwCX47s04syKq7QHHzSzKjVR9E=";
  };
  chicoryOverlayHashes = {
    "MODULE.bazel" = "sha256-LTH1To/fCWPp9K9t9VPe96q2kntGIdpFVbwhICGXU0A=";
    "host-module/annotations/BUILD.bazel" = "sha256-MQZi1EDrUnxd080ZSsmuT78tM29qz7l4I94/xy2kBFQ=";
    "host-module/processor/BUILD.bazel" = "sha256-nxWfD+O80D0wNsVoqery0rzib7ZkS3fza9gaEm2C55w=";
    "log/BUILD.bazel" = "sha256-XqbVcm6y4+rgiyVYc2s1y8RSZ+QDVZ0AOd8l+uiggNY=";
    "runtime/BUILD.bazel" = "sha256-0MJQDX44Qe9rfBHcNeVQCPrAwQcG8mbrYj+g66xqlPM=";
    "wasi/BUILD.bazel" = "sha256-x0iC+Po7ZDOYy8z/B5Yh/rU+G2AA3OGYhv1BcWO3lPI=";
    "wasm/BUILD.bazel" = "sha256-M0GF0CnFj3QIWr+QiJj8Bm3zWVBFr+OB8LDo9gKDeek=";
  };
  chicoryOverlays = builtins.mapAttrs (path: hash:
    fetchurl {
      urls = ["${chicoryRegistryRoot}/overlay/${path}"];
      inherit hash;
    })
  chicoryOverlayHashes;
  chicoryOverlayScript = builtins.concatStringsSep "\n" (builtins.map (path: ''
    mkdir -p ${builtins.dirOf path}
    cp ${builtins.getAttr path chicoryOverlays} ${path}
  '') (builtins.attrNames chicoryOverlayHashes));

  appleSupportRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/apple_support/1.23.1";
  appleSupportSource = moduleSource {
    name = "apple_support";
    version = "1.23.1";
    url = "https://github.com/bazelbuild/apple_support.git";
    ref = "1.23.1";
    rev = "4c51f10063687af77eabbbdc035124d798ca3a3f";
    hash = "sha256-EGVl830AkhaY3ujSih69kyajdL0ob4tEnQyL9yIlCIQ=";
  };
  appleSupportModule = fetchurl {
    urls = ["${appleSupportRegistryRoot}/MODULE.bazel"];
    hash = "sha256-U3Y/7UVqloz5GbMkBCfPOp1UgexUZqvJ1dxRvHAIdEI=";
  };
  appleSupportPatch = fetchurl {
    urls = ["${appleSupportRegistryRoot}/patches/module_dot_bazel_version.patch"];
    hash = "sha256-yqwfzmg9lIV674KI+GHtlok/967e8C2Ap8bPggzPm58=";
  };

  rulesSwiftRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/rules_swift/2.1.1";
  rulesSwiftSource = moduleSource {
    name = "rules_swift";
    version = "2.1.1";
    url = "https://github.com/bazelbuild/rules_swift.git";
    ref = "2.1.1";
    rev = "f9681793be03df5fbaeb2f46223de5f74e9096f4";
    hash = "sha256-21wJ3j9WyqRSLC9vSHzs2xu2SIG7n/pf9dgZnYgJmy8=";
  };
  rulesSwiftModule = fetchurl {
    urls = ["${rulesSwiftRegistryRoot}/MODULE.bazel"];
    hash = "sha256-SUkAqA+UT8eqYVAMIHPZcp3/C3ZPDom4JOt0aVm8EEY=";
  };
  rulesSwiftPatch = fetchurl {
    urls = ["${rulesSwiftRegistryRoot}/patches/module_dot_bazel_version.patch"];
    hash = "sha256-/kZbNxPjPQxNaVxijhzrPhwIf8mGwidxih95QYLXSo4=";
  };

  cAresRegistryRoot = "https://raw.githubusercontent.com/bazelbuild/bazel-central-registry/${registryRevision}/modules/c-ares/1.15.0";
  cAresSource = moduleSource {
    name = "c-ares";
    version = "1.15.0";
    url = "https://github.com/c-ares/c-ares.git";
    ref = "cares-1_15_0";
    rev = "e982924acee7f7313b4baa4ee5ec000c5e373c30";
    hash = "sha256-m3EIqqQo9Mt51Fv2Yk9oZ3qy+tHQv18MV35Bv4K2djI=";
  };
  cAresBuildPatch = fetchurl {
    urls = ["${cAresRegistryRoot}/patches/add_build_file.patch"];
    hash = "sha256-+SUCFxBIkR0GE9FRFPps/e6AnA9cQIGANBHK14UAKwQ=";
  };
  cAresModulePatch = fetchurl {
    urls = ["${cAresRegistryRoot}/patches/module_dot_bazel.patch"];
    hash = "sha256-SVQeSrnvd7IishMhmg8S3PK6/6bbt1IqwVEqKDfdYgk=";
  };
in {
  rules_cc = moduleSource {
    name = "rules_cc";
    version = "0.1.1";
    url = "https://github.com/bazelbuild/rules_cc.git";
    ref = "0.1.1";
    rev = "a1162270a0bb680190e8b4f3dab066f15a1ede6c";
    hash = "sha256-oecNUTdtTZ6b3Gdvom9UOuJCO+UtSBxZ+wnx8haCgco=";
  };

  rules_shell = moduleSource {
    name = "rules_shell";
    version = "0.2.0";
    url = "https://github.com/bazelbuild/rules_shell.git";
    ref = "v0.2.0";
    rev = "2c164bf53643eb9a76e6327d2c41881b3eb4c827";
    hash = "sha256-cAIF123auuvMX5uUZmy7lAYq89eraNI7nx+pvFDTfRk=";
  };

  rules_python = moduleSource {
    name = "rules_python";
    version = "0.40.0";
    url = "https://github.com/bazelbuild/rules_python.git";
    ref = "0.40.0";
    rev = "1944874f6ba507f70d8c5e70df84622e0c783254";
    hash = "sha256-OYMDqpC3+puoa3fzf7jOUL37A54ip5oU5I+JTulLL/8=";
  };

  rules_java = moduleSource {
    name = "rules_java";
    version = "8.14.0";
    url = "https://github.com/bazelbuild/rules_java.git";
    ref = "8.14.0";
    rev = "02f488deec4eaf8188d8433762554dcc4e6083f7";
    hash = "sha256-RXTY4EOTUz9SzX3G0dj7uTqAHydgrx9O8od6H2JTvGQ=";
  };

  bazel_skylib = moduleSource {
    name = "bazel_skylib";
    version = "1.7.1";
    url = "https://github.com/bazelbuild/bazel-skylib.git";
    ref = "1.7.1";
    rev = "27d429d8d036af3d010be837cc5924de1ca8d163";
    hash = "sha256-l39sFBR5cMZY92AYNk5+jQV6uaIY7ug8Huvh/8yJFXY=";
  };

  protobuf = moduleSource {
    name = "protobuf";
    version = "29.0";
    url = "https://github.com/protocolbuffers/protobuf.git";
    ref = "v29.0";
    rev = "2d4414f384dc499af113b5991ce3eaa9df6dd931";
    hash = "sha256-LOIB/xwWKII2DIR7aZpoMnCK8StD7hhv9cCLyO2bRg4=";
    # Three prepacked compatibility fixtures remain in the Git checkout
    # without this additional exclusion.
    extraExcludes = ["!*.srcjar"];
  };

  bazel_features = moduleSource {
    name = "bazel_features";
    version = "1.30.0";
    url = "https://github.com/bazel-contrib/bazel_features.git";
    ref = "v1.30.0";
    rev = "d5ecc8a30dff140d5ab89fee5457cf756a47c742";
    hash = "sha256-lm/k+yWhS9jLNKT+joO1AQPl1/TpyaID7o9RkNWyNHU=";
  };

  rules_fuzzing = moduleSource {
    name = "rules_fuzzing";
    version = "0.5.2";
    url = "https://github.com/bazelbuild/rules_fuzzing.git";
    ref = "v0.5.2";
    rev = "691c8938ff87681f7281cc4ba840e74e3b63c54b";
    hash = "sha256-+NZG/nBDWzMmsNPA4JEneA36ZxUQFZjSul1HMz5EE44=";
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
    version = "1.0.1";
    url = "https://github.com/bazelbuild/rules_pkg.git";
    ref = "1.0.1";
    rev = "6a44f01087cf504eeee7dffce7cabe042a2f0bac";
    hash = "sha256-OJRWcI7fKtf9pBt8iJlfEC4+4skADIkeTY0cmR9aOj0=";
  };

  rules_go = moduleSource {
    name = "rules_go";
    version = "0.48.0";
    url = "https://github.com/bazel-contrib/rules_go.git";
    ref = "v0.48.0";
    rev = "354a98f4acf2333b7603ede50dd5fbc20ae315b1";
    hash = "sha256-Xjag+Of9Qa89gvhZLV4wbuJmjHgiEScrnOFhB6uKFvk=";
  };

  grpc = mkDerivation {
    pname = "bazel-grpc-bcr-source";
    version = "1.66.0.bcr.2";
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
          ${builtins.concatStringsSep "\n" (builtins.map (patchFile: ''patch --batch -p1 < ${patchFile}'') grpcPatches)}
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

  googleapis = mkDerivation {
    pname = "bazel-googleapis-bcr-source";
    version = "0.0.0-20240819-fe8ba054a";
    src = googleapisSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir googleapis-source
          cp -a "$src"/. googleapis-source/
          chmod -R u+w googleapis-source
          cd googleapis-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p1 < ${googleapisPatch}
          cmp MODULE.bazel ${googleapisModule}
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

  zstd-jni = mkDerivation {
    pname = "bazel-zstd-jni-bcr-source";
    version = "1.5.6-9";
    src = zstdJniSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir zstd-jni-source
          cp -a "$src"/. zstd-jni-source/
          chmod -R u+w zstd-jni-source
          cd zstd-jni-source
        '';
      }
      {
        name = "build";
        script = ''
          ${builtins.concatStringsSep "\n" (builtins.map (patchFile: ''patch --batch -p1 < ${patchFile}'') zstdJniPatches)}
          cmp MODULE.bazel ${zstdJniModule}
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

  abseil-cpp = mkDerivation {
    pname = "bazel-abseil-bcr-source";
    version = "20240722.0.bcr.2";
    src = abseilSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir abseil-source
          cp -a "$src"/. abseil-source/
          chmod -R u+w abseil-source
          cd abseil-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p0 < ${abseilPatch}
          cp ${abseilModule} MODULE.bazel
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

  zlib = mkDerivation {
    pname = "bazel-zlib-bcr-source";
    version = "1.3.1.bcr.5";
    src = zlibSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir zlib-source
          cp -a "$src"/. zlib-source/
          chmod -R u+w zlib-source
          cd zlib-source
        '';
      }
      {
        name = "build";
        script = ''
          ${builtins.concatStringsSep "\n" (builtins.map (patchFile: ''patch --batch -p0 < ${patchFile}'') zlibPatches)}
          cmp MODULE.bazel ${zlibModule}
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

  rules_jvm_external = mkDerivation {
    pname = "bazel-rules-jvm-external-bcr-source";
    version = "6.0";
    src = jvmExternalSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir rules-jvm-external-source
          cp -a "$src"/. rules-jvm-external-source/
          chmod -R u+w rules-jvm-external-source
          cd rules-jvm-external-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p0 < ${jvmExternalPatch}
          cmp MODULE.bazel ${jvmExternalModule}
          # Module overrides bypass Bazel's single_version_override patch.
          patch --batch --fuzz=0 -p1 < ${bazelSource8}/third_party/rules_jvm_external_6.0.patch
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

  blake3 = mkDerivation {
    pname = "bazel-blake3-bcr-source";
    version = "1.5.1.bcr.1";
    src = blake3Source;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir blake3-source
          cp -a "$src"/. blake3-source/
          chmod -R u+w blake3-source
          cd blake3-source
        '';
      }
      {
        name = "build";
        script = ''
          ${builtins.concatStringsSep "\n" (builtins.map (patchFile: ''patch --batch -p0 < ${patchFile}'') blake3Patches)}
          cmp MODULE.bazel ${blake3Module}
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

  rules_proto = mkDerivation {
    pname = "bazel-rules-proto-bcr-source";
    version = "7.0.2";
    src = rulesProtoSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir rules-proto-source
          cp -a "$src"/. rules-proto-source/
          chmod -R u+w rules-proto-source
          cd rules-proto-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p1 < ${rulesProtoPatch}
          cmp MODULE.bazel ${rulesProtoModule}
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

  grpc-java = mkDerivation {
    pname = "bazel-grpc-java-bcr-source";
    version = "1.66.0";
    src = grpcJavaSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir grpc-java-source
          cp -a "$src"/. grpc-java-source/
          chmod -R u+w grpc-java-source
          cd grpc-java-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p1 < ${grpcJavaPatch}
          cmp MODULE.bazel ${grpcJavaModule}
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

  stardoc = mkDerivation {
    pname = "bazel-stardoc-bcr-source";
    version = "0.7.1";
    src = stardocSource;

    buildDeps = [buildPackages.sed buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir stardoc-source
          cp -a "$src"/. stardoc-source/
          chmod -R u+w stardoc-source
          cd stardoc-source
        '';
      }
      {
        name = "build";
        script = ''
          # The release packaging drops upstream's marked dev-only tail.
          sed '/^### INTERNAL ONLY/,$d' MODULE.bazel > MODULE.bazel.released
          cmp MODULE.bazel.released ${stardocModule}
          mv MODULE.bazel.released MODULE.bazel
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

  rules_apple = mkDerivation {
    pname = "bazel-rules-apple-bcr-source";
    version = "3.16.0";
    src = rulesAppleSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir rules-apple-source
          cp -a "$src"/. rules-apple-source/
          chmod -R u+w rules-apple-source
          cd rules-apple-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p1 < ${rulesApplePatch}
          cmp MODULE.bazel ${rulesAppleModule}
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

  chicory = mkDerivation {
    pname = "bazel-chicory-bcr-source";
    version = "1.1.0";
    src = chicorySource;

    buildDeps = [buildPackages.patch];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir chicory-source
          cp -a "$src"/. chicory-source/
          chmod -R u+w chicory-source
          cd chicory-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p0 < ${chicoryPatch}
          ${chicoryOverlayScript}
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

  apple_support = mkDerivation {
    pname = "bazel-apple-support-bcr-source";
    version = "1.23.1";
    src = appleSupportSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir apple-support-source
          cp -a "$src"/. apple-support-source/
          chmod -R u+w apple-support-source
          cd apple-support-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p1 < ${appleSupportPatch}
          cmp MODULE.bazel ${appleSupportModule}
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

  rules_swift = mkDerivation {
    pname = "bazel-rules-swift-bcr-source";
    version = "2.1.1";
    src = rulesSwiftSource;

    buildDeps = [buildPackages.patch buildPackages.diffutils];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir rules-swift-source
          cp -a "$src"/. rules-swift-source/
          chmod -R u+w rules-swift-source
          cd rules-swift-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p1 < ${rulesSwiftPatch}
          cmp MODULE.bazel ${rulesSwiftModule}
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

  "c-ares" = mkDerivation {
    pname = "bazel-c-ares-bcr-source";
    version = "1.15.0";
    src = cAresSource;

    buildDeps = [buildPackages.patch];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          mkdir c-ares-source
          cp -a "$src"/. c-ares-source/
          chmod -R u+w c-ares-source
          cd c-ares-source
        '';
      }
      {
        name = "build";
        script = ''
          patch --batch -p0 < ${cAresBuildPatch}
          patch --batch -p0 < ${cAresModulePatch}
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
}
