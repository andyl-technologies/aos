##! Checks explicit target selection and lossless frozen-package metadata.
{lib}: let
  freeze = import ../build/freeze-pkgs.nix {inherit lib;};
  outputPath = "/nix/store/00000000000000000000000000000000-frozen-package";
  libraryPath = "/nix/store/11111111111111111111111111111111-frozen-library";
  package = {
    type = "derivation";
    outPath = outputPath;
    outputs = ["out" "lib"];
    out.outPath = outputPath;
    lib.outPath = libraryPath;
  };
  packages = {
    coreutils = package;
    aos-test-agent = package;
    helper = package;
    builder = _: throw "builder functions must not be evaluated";
    darling = throw "x86_64-only packages must not be evaluated for AArch64";
    darwin-runtimes = throw "Darwin-only packages must not be evaluated for Linux";
  };

  serialized = freeze.freezeSelectedToJSON {
    packageSet = packages;
    packageNames = ["aos-test-agent" "coreutils" "helper"];
  };
  restored = freeze.frozenFromJSON serialized;
  unclassified = freeze.frozenFromJSON (freeze.freezeSelectedToJSON {
    packageSet = {helper = package;};
    packageNames = ["helper"];
  });
in
  assert builtins.attrNames restored == ["aos-test-agent" "coreutils" "helper"];
  assert toString restored.coreutils == outputPath;
  assert toString restored.coreutils.lib == libraryPath;
  assert builtins.match ".*/nix/store/.*" serialized == null;
  assert builtins.getContext serialized == {};
  assert toString unclassified.helper == outputPath; true
