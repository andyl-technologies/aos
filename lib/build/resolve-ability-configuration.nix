##! Runs bounded provider selection around complete AOS module evaluations.
{
  lib,
  initialPackageModules,
  evaluate,
  discoverPackageModules ? _: [],
  maxRounds ? 16,
}: let
  canonicalModules =
    lib.abilities.canonicalizeAuthenticatedModuleRecords;
  moduleIdentity = record:
    builtins.unsafeDiscardStringContext (builtins.toJSON {
      inherit (record) name version;
      module = builtins.toString record.module;
      configRoot = builtins.toString record.configRoot;
      outputs = record.outputs;
    });
  mergeModules = current: discovered: let
    byIdentity = builtins.listToAttrs (builtins.map (record: {
        name = moduleIdentity record;
        value = record;
      })
      (canonicalModules (current ++ discovered)));
  in
    builtins.attrValues byIdentity;
  emptySelection = {
    instances = {};
    bindings = {};
    requests = {};
    requirements = {};
  };
  selectionModuleFor = selection: {
    module = {
      aos.abilities = {
        inherit (selection) instances bindings;
      };
    };
    inherit (selection) requests requirements;
  };
  mergeSelection = selection: additions: {
    instances = selection.instances // additions.instances;
    bindings = selection.bindings // additions.bindings;
    requests = selection.requests // additions.requests;
    requirements = selection.requirements // additions.requirements;
  };
  forceBindings = bindings:
    builtins.deepSeq (builtins.attrValues bindings) bindings;
  providerModulesFor = packageModules: abilities: bindings:
    import ./provider-modules-for-bindings.nix {
      inherit lib abilities packageModules bindings;
    };
  resolve = {
    packageModules,
    selection ? emptySelection,
    round ? 0,
  }: let
    selectionModule = selectionModuleFor selection;
    packageEvaluation = evaluate {
      inherit packageModules selectionModule;
      providerModules = [];
    };
    bindings = forceBindings packageEvaluation.config.aos.abilities.bindings;
    providerModules =
      providerModulesFor
      packageModules
      packageEvaluation.config.aos.abilities
      bindings;
    uncheckedEvaluation = evaluate {
      inherit packageModules providerModules selectionModule;
    };
    evaluation =
      builtins.seq
      (lib.abilities.checkedProviderModuleEvaluation {
        before = packageEvaluation.config.aos.abilities;
        after = uncheckedEvaluation.config.aos.abilities;
      })
      uncheckedEvaluation;
    discoveredModules = discoverPackageModules {
      inherit evaluation packageEvaluation packageModules providerModules selection;
      inherit bindings;
    };
    nextPackageModules = mergeModules packageModules discoveredModules;
    packageSetChanged =
      builtins.map moduleIdentity nextPackageModules
      != builtins.map moduleIdentity packageModules;
    additions = lib.abilities.selectBindings evaluation.config.aos.abilities;
    nextSelection = mergeSelection selection additions;
    nextBindings = forceBindings (bindings // additions.bindings);
    selectionChanged = nextSelection != selection;
    pending = evaluation.config.aos.abilities.compositionPendingRequests;
  in
    if round >= maxRounds
    then throw "ability selection did not converge within ${toString maxRounds} complete module evaluations"
    else if packageSetChanged
    then
      resolve {
        packageModules = nextPackageModules;
        inherit selection;
        round = round + 1;
      }
    else if selectionChanged
    then
      resolve {
        inherit packageModules;
        selection = nextSelection;
        round = round + 1;
      }
    else {
      inherit evaluation packageEvaluation packageModules providerModules selection;
      bindings = nextBindings;
      checked =
        if builtins.deepSeq (builtins.attrValues pending) pending != {}
        then throw "complete ability evaluation has unresolved provider requests"
        else builtins.deepSeq (builtins.attrValues nextBindings) true;
    };
in
  resolve {
    packageModules = canonicalModules initialPackageModules;
  }
