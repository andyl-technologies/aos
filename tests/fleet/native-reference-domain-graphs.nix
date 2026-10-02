##! Checks original domain dependency graphs and controlled retirement without VM flights.
{
  lib,
  pkgs,
}: let
  root = ../..;
  aos = {inherit lib pkgs;};
  wrapper = backend: backendExecutable:
    import (root + /tests/abilities/native-handler-interception/package.nix) {
      inherit (aos.pkgs) mkDerivation python3;
      inherit backend backendExecutable;
    };
  filesystem = wrapper aos.pkgs.aos-filesystem-provider "bin/aos-filesystem-provider";
  configuration = wrapper aos.pkgs.systemd "bin/aos-service-handler";
  firewall = wrapper aos.pkgs.aos-network-ruleset-provider "bin/aos-network-ruleset-provider";
  markers = import (root + /tests/abilities/native-dependency-barrier/package.nix) {inherit (aos.pkgs) mkDerivation python3;};
  evaluate = extra:
    aos.lib.evalPackageModules {
      scope = ["test" "domain-dependencies"];
      packages = [filesystem configuration firewall markers];
      operatorModules = [
        (root + /tests/fleet/_native-reference-filesystem-configuration.nix)
        (root + /tests/fleet/_native-reference-firewall-interception.nix)
        (root + /tests/fleet/_native-reference-domain-dependencies.nix)
        extra
      ];
    };
  original = evaluate {};
  suffix = node: builtins.genList (index: builtins.elemAt node.identity (builtins.length node.identity - 3 + index)) 3;
  find = graph: identity: let
    matches = builtins.filter (id: suffix graph.nodes.${id} == identity) (builtins.attrNames graph.nodes);
  in
    assert builtins.length matches == 1;
      builtins.head matches;
  operations = ["directory" "allocate" "persistentAllocate" "entry" "file" "ruleset"];
  ability = operation:
    if operation == "ruleset"
    then "networkPolicy"
    else if operation == "file"
    then "configuration"
    else "filesystem";
  key = operation:
    if operation == "ruleset"
    then "host"
    else "native-qualification";
  selected = graph: operation: find graph [(ability operation) operation (key operation)];
  checked = operation: let
    graph = original.deployment.graph;
    effect = selected graph operation;
    parent = find graph ["nativeDependencyBarrier" "ensure" "parent-${operation}"];
    child = find graph ["nativeDependencyBarrier" "ensure" "child-${operation}"];
    removed = evaluate (aos.lib.recursiveUpdate {aos.nativeDomainQualification.dependencyParents.${operation} = false;}
      (
        if operation == "ruleset"
        then {aos.networkPolicy.enable = false;}
        else {aos.nativeDomainQualification.enabled.${operation} = false;}
      ));
    ids = map suffix (builtins.attrValues removed.deployment.graph.nodes);
    program =
      if operation == "ruleset"
      then firewall
      else if operation == "file"
      then configuration
      else filesystem;
  in
    assert builtins.elem parent graph.nodes.${effect}.dependencies;
    assert builtins.elem effect graph.nodes.${child}.dependencies;
    assert graph.nodes.${effect}.handler.artifact == program.outPath;
    assert !(builtins.elem [(ability operation) operation (key operation)] ids);
    assert !(builtins.elem ["nativeDependencyBarrier" "ensure" "parent-${operation}"] ids);
    assert !(builtins.elem ["nativeDependencyBarrier" "ensure" "child-${operation}"] ids); true;
  orphan = evaluate {aos.nativeDomainQualification.enabled.persistentAllocate = false;};
  orphanIdentities = map suffix (builtins.attrValues orphan.deployment.graph.nodes);
in
  {
    persistentOrphan = assert builtins.elem ["nativeDependencyBarrier" "ensure" "parent-persistentAllocate"] orphanIdentities;
    assert !(builtins.elem ["nativeDependencyBarrier" "ensure" "child-persistentAllocate"] orphanIdentities);
    assert !(builtins.elem ["filesystem" "persistentAllocate" "native-qualification"] orphanIdentities);
    assert orphan.deployment.retire == []; true;
  }
  // builtins.listToAttrs (map (operation: {
      name = operation;
      value = checked operation;
    })
    operations)
