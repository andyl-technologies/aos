##! Source identity deduplication preserves resolver and inline module boundaries.
let
  lib = import ../../lib {system = "x86_64-linux";};
  declarations = {lib, ...}: {
    options.importVisits = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      extensible = true;
    };
  };
  source = ./_source-imports/leaf.nix;
  left = ./_source-imports/left.nix;
  right = ./_source-imports/right.nix;
  diamond = lib.evalModules {modules = [declarations left right source];};
  cycle = lib.evalModules {modules = [declarations ./_source-imports/cycle-a.nix];};
  inline = {
    _file = "same-authored-file.nix";
    importVisits = ["inline"];
  };
  repeatedInline = lib.evalModules {modules = [declarations inline inline];};
  spoofed = lib.evalModules {
    modules = [declarations ./_source-imports/spoof-first.nix ./_source-imports/spoof-second.nix];
  };
  provenance = lib.evalModules {
    modules = [declarations source];
    operatorModules = [source];
    runtimeModules = [source];
  };
  leafModules = evaluated:
    builtins.filter (module: module.config ? platform) evaluated._modules;
  record = name: {
    inherit name;
    version = "1";
    module = ./_source-imports/cycle-a.nix;
  };
  contexts = lib.evalModules {
    modules = [declarations];
    packageModules = [(record "first") (record "second")];
  };
in {
  diamondImportsOnce = assert diamond.config.importVisits == ["leaf"];
  assert diamond.config.platform "platform" == "platform";
  assert builtins.length (leafModules diamond) == 1; true;
  sourceCyclesTerminate = assert cycle.config.importVisits == ["cycle-b" "cycle-a"]; true;
  repeatedInlineDefinitionsMerge = assert repeatedInline.config.importVisits == ["inline" "inline"]; true;
  authoredFileIsNotSourceIdentity = assert spoofed.config.importVisits == ["first" "second"]; true;
  resolverProvenanceStaysSeparate = assert builtins.sort builtins.lessThan (map (module: module._provenance) (leafModules provenance)) == ["@base" "@host" "@runtime"]; true;
  packageContextsStaySeparate = assert builtins.sort builtins.lessThan
  (map (module: module._provenance) (builtins.filter (module: module.config ? importVisits) contexts._modules))
  == ["package:first" "package:first" "package:second" "package:second"]; true;
}
