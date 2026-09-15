##! Shared typed descriptor for package-owned native-adapter observation assets.
{
  lib,
  observerPackage,
}: let
  inherit (lib.abilities) types;
in {
  observer = {
    artifact = lib.abilities.packageOutput {
      package = observerPackage.pname;
      output = observerPackage.outputName or "out";
    };
    entryPoint = "bin/aos-native-adapter-observer";
    arguments = types.record {
      fields.request_path = types.string {
        maxLength = 4096;
        syntax = null;
      };
      optional = [];
    };
    result = types.record {
      fields = {
        provider = types.localKey;
        kind = types.localKey;
        scope = types.localKey;
        observation = types.string {
          maxLength = 1048576;
          syntax = null;
        };
      };
      optional = [];
    };
  };
}
