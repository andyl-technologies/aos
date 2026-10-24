##! Fixed x86 controller components; complete native admission remains refused
{
  mkDerivation,
  gem5-native-original-scope-foundation,
  gem5-x86-linux-loader-check,
}: let
  native = gem5-native-original-scope-foundation;
  helperNames = [
    "native-controller.py"
    "native-controller-models.py"
    "native-model-assets.py"
    "native-controller-x86.py"
    "native-controller-x86-model.py"
    "x86-linux-loader.py"
  ];
  helpers = builtins.path {
    path = ./_gem5;
    name = "gem5-fixed-x86-controller-components";
    filter = path: type:
      type
      == "directory"
      && builtins.baseNameOf path == "_gem5"
      || builtins.elem (builtins.baseNameOf path) helperNames;
  };
  sourceMetadata = builtins.toJSON {
    schema = "crucible.gem5.x86-model-components.v1";
    model_id = "x86-linux-pc-atomic-functional-v1";
    native_dialect = "crucible.gem5.x86-linux-native/1";
    native_executable = "${native}/bin/gem5";
    native_corresponding_source = "${native.source}";
    loader_component_check = "${gem5-x86-linux-loader-check}/share/checks/x86-linux-loader.json";
    helper_hashes = builtins.listToAttrs (map (name: {
        inherit name;
        value = builtins.hashFile "sha256" (./_gem5 + "/${name}");
      })
      helperNames);
    recipe_sha256 = builtins.hashFile "sha256" ./gem5-x86-model-components.nix;
    loader_recipe_sha256 = builtins.hashFile "sha256" ./gem5-x86-linux-loader-check.nix;
    public_catalog_qualified = false;
    native_source_authority_qualified = false;
    exact_capture_qualified = false;
    guest_readiness_qualified = false;
    device_parity_qualified = false;
    cpu_timing_qualified = false;
  };
in
  mkDerivation {
    pname = "gem5-x86-model-components";
    inherit sourceMetadata;
    passAsFile = ["sourceMetadata"];
    version = "1";
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64"];
          os = ["linux"];
        }
      ];
      target = [];
      role = "public-package";
    };
    buildDeps = [];
    # Distribution keeps the complete matching native source and the required
    # source-built loader check. Components never stand in for a whole node gate.
    runtimeDeps = [native native.source gem5-x86-linux-loader-check];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/gem5/x86-model-components" \
            "$out/share/licenses/gem5-x86-model-components" "$out/nix-support"
          cp ${helpers}/*.py "$out/share/gem5/x86-model-components/"
          cp "$sourceMetadataPath" "$out/share/gem5/x86-model-components/manifest.json"
          cp ${./gem5-x86-model-components.nix} "$out/share/gem5/x86-model-components/recipe.nix"
          cp ${../../LICENSES/MIT.txt} "$out/share/licenses/gem5-x86-model-components/LICENSE"
          printf '%s\n' '${native.source}' > "$out/nix-support/corresponding-native-source"
        '';
      }
    ];
    meta = {
      description = "Source-owned fixed x86 Linux controller and checked initramfs loader components, without public catalog or native capture/readiness/timing qualification";
      license = "MIT";
    };
  }
