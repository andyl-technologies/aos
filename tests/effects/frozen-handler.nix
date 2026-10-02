##! Handler identity and executable survive the build-free on-host package view.
let
  lib = import ../../lib {system = "x86_64-linux";};
  freeze = import ../../lib/build/freeze-pkgs.nix {inherit lib;};
  payload = import ./_fixture-payload.nix "fixture-package";
  program = {
    type = "derivation";
    pname = "fixture-package";
    name = "fixture-package-1";
    version = "1";
    outputName = "out";
    outPath = payload;
    meta.mainProgram = "actual-handler";
  };
  frozen = freeze.frozenFromJSON (freeze.freezeSelectedToJSON {
    packageSet.handler = program;
    packageNames = ["handler"];
  });
  graphFor = selected:
    (lib.evalModules {
      inherit lib;
      modules = [
        ../../lib/effects/module.nix
        {
          aos.abilities.fixture.operations.apply = {
            handler.program = selected;
            effects.default = {};
          };
        }
      ];
    }).config.aos.activation.graph;
in {
  equivalentGraph = assert graphFor program == graphFor frozen.handler; true;
  primaryExecutable = assert lib.getExe frozen.handler == lib.getExe program; true;
  secondaryExecutable = assert lib.getExe (lib.getOutput "out" frozen.handler) == lib.getExe program; true;
  retainedVersion = assert frozen.handler.version == "1"; true;
}
