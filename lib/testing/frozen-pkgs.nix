##! Checks target filtering and lossless frozen-package metadata without builds.
{lib}: let
  freeze = import ../build/freeze-pkgs.nix {inherit lib;};
  platformSupport = import ../../pkgs/_platform-support.nix;
  platform = (import ../platform.nix).mkPlatform "aarch64-linux";
  outputPath = "/nix/store/00000000000000000000000000000000-frozen-package";
  libraryPath = "/nix/store/11111111111111111111111111111111-frozen-library";
  package = {
    type = "derivation";
    outPath = outputPath;
    outputs = ["out" "lib"];
    out.outPath = outputPath;
    lib.outPath = libraryPath;
    passthru.systemdUnitInventory = {"fixture.service" = "lib/systemd/system/fixture.service";};
  };
  packages = {
    inherit platformSupport;
    stdenv.hostPlatform = platform;
    coreutils = package;
    aos-test-agent = package;
    helper = package;
    builder = _: throw "builder functions must not be evaluated";
    darling = throw "x86_64-only packages must not be evaluated for AArch64";
    darwin-runtimes = throw "Darwin-only packages must not be evaluated for Linux";
  };

  serialized = freeze.freezeToJSON packages;
  restored = freeze.frozenFromJSON serialized;
  unclassified = freeze.frozenFromJSON (freeze.freezeToJSON {helper = package;});
in
  assert builtins.attrNames restored == ["aos-test-agent" "coreutils" "helper"];
  assert toString restored.coreutils == outputPath;
  assert toString restored.coreutils.lib == libraryPath;
  assert restored.coreutils.systemdUnitInventory == package.passthru.systemdUnitInventory;
  assert builtins.match ".*/nix/store/.*" serialized == null;
  assert builtins.getContext serialized == {};
  assert toString unclassified.helper == outputPath; true
