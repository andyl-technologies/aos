##! Pinned source modules for Bazel 8's download-disabled bootstrap graph.
{
  mkDerivation,
  fetchgit,
  fetchurl,
  buildPackages,
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
}
