##! Named artifact roles preserve package identities and original store contexts.
{
  lib,
  pkgs,
}: let
  artifacts = import ../../lib/packages/artifacts.nix {};
  payload = marker:
    pkgs.mkDerivation {
      pname = "binding-payload";
      version = "1";
      src = null;
      phases = [
        {
          name = "install";
          script = ''mkdir -p "$out"; echo ${marker} > "$out/marker"'';
        }
      ];
    };
  predecessor = payload "before";
  candidate = payload "after";
  owner = pkgs.mkDerivation {
    pname = "binding-owner";
    version = "1";
    src = null;
    outputs = ["out" "tools"];
    module = ./package-interface;
    runtimeDeps = {inherit predecessor candidate;};
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out" "$tools"'';
      }
    ];
  };
  bindings = owner.deployment.runtimeDependencies;
  record = lib.packageModules.recordFor owner;
  sources = builtins.getContext "${candidate}";
  alias = artifacts.value record.artifacts.dependencies.candidate;
  replaced = owner.overrideAttrs (_: {runtimeDeps = {current = candidate;};});
in {
  distinctRoles = assert builtins.attrNames bindings == ["candidate" "predecessor"];
  assert bindings.candidate.name == "binding-payload";
  assert bindings.predecessor.name == "binding-payload";
  assert bindings.candidate.path != bindings.predecessor.path; true;
  buildDependencies = assert builtins.isList owner.runtimeDeps;
  assert builtins.map builtins.toString owner.runtimeDeps == builtins.map builtins.toString [candidate predecessor]; true;
  retainedIdentity = assert builtins.toString alias == builtins.toString candidate;
  assert alias.name == candidate.pname;
  assert builtins.getContext "${alias}" == sources; true;
  metadataHasNoPayloadContexts = assert builtins.getContext (builtins.toJSON bindings) == {}; true;
  secondaryOutput = assert owner.tools.deployment.runtimeDependencies == bindings;
  assert (lib.packageModules.recordFor owner.tools).artifacts.dependencies == record.artifacts.dependencies; true;
  staleCatalogRejected = assert !(builtins.tryEval (builtins.deepSeq (artifacts.canonicalReference (owner // {tools = candidate;})) true)).success; true;
  overrides = assert builtins.attrNames replaced.deployment.runtimeDependencies == ["current"];
  assert builtins.length replaced.runtimeDeps == 1; true;
  ambiguousListRejected = assert !(builtins.tryEval (builtins.deepSeq (artifacts.keyed [predecessor candidate]) true)).success; true;
  emptyBindingRejected = assert !(builtins.tryEval (builtins.deepSeq (artifacts.keyed {"" = candidate;}) true)).success; true;
}
