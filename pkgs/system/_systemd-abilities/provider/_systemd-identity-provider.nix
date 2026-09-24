##! Pure systemd identity composition and provider transition wiring.
{
  config,
  lib,
  packageName,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  interfaces = serviceManagement.interfaces;
  emptyProvision = {
    requests = {};
    outputs = {};
    resourceFragments = {};
  };
  executableReference = artifact: entry_point: {
    inherit artifact;
    inherit entry_point;
    arguments = [];
  };
  systemdArtifact = lib.abilities.packageOutput {};
  bashArtifact = lib.abilities.packageOutput {package = "bash";};
  bindingFor = bindings: requestName: let
    matches = builtins.filter (binding: binding.request == requestName) (builtins.attrValues bindings);
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "a systemd identity request must have exactly one selected binding";
  referenceFor = selected: instance: key: {
    interface = selected.identity;
    resource = {
      provider = instance.id;
      inherit key;
    };
    operations = selected.methods;
    lifetime = "instance";
  };
  kinds = {
    principal = {
      selected = interfaces.principalResolution;
      resourceKind = "aos.identity.principal";
      effectsAlias = "systemd-principal-effects";
      outputName = "principal-name";
    };
    group = {
      selected = interfaces.groupResolution;
      resourceKind = "aos.identity.group";
      effectsAlias = "systemd-group-effects";
      outputName = "group-name";
    };
    group-membership = {
      selected = interfaces.groupMembership;
      resourceKind = "aos.identity.group-membership";
      effectsAlias = "systemd-group-membership-effects";
      outputName = null;
    };
  };
  providerFor = kind: let
    specification = kinds.${kind};
    effectsInterface = lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration
      config.aos.abilities.interfaces."${packageName}:${specification.effectsAlias}"
    );
    provide = context: let
      entries = builtins.map (requestName: let
        binding = bindingFor context.bindings requestName;
        reference = referenceFor specification.selected context.instance binding.slot;
      in {
        inherit requestName binding reference;
        parameters = context.requests.${requestName}.parameters;
      }) (builtins.attrNames context.requests);
    in
      emptyProvision
      // {
        outputs = builtins.listToAttrs (builtins.map (entry: {
            name = entry.requestName;
            value =
              if specification.outputName == null
              then {resource = entry.reference;}
              else {
                ${specification.outputName} = entry.parameters.name;
                resource = entry.reference;
              };
          })
          entries);
        resourceFragments = builtins.listToAttrs (builtins.map (entry: {
            name = entry.binding.slot;
            value = {
              kind = specification.resourceKind;
              lifetime = "instance";
              value = entry.parameters;
            };
          })
          entries);
      };
    compose = {resources, ...}: {
      outputs = {};
      requests =
        builtins.mapAttrs (key: resource: {
          requirement = "identity-effects";
          scope = ["identity-effects"];
          slot = key;
          parameters.desired = resource.value;
        })
        resources;
      realizations =
        builtins.mapAttrs (_: _: {
          schema = "aos.systemd.identity-realization/v1";
          backend = "systemd-sysusers";
          systemd_sysusers = executableReference systemdArtifact "bin/systemd-sysusers";
          login_shell = executableReference bashArtifact "bin/bash";
          nologin_shell = executableReference systemdArtifact "bin/nologin";
        })
        resources;
    };
    transition = import ./_systemd-identity-transition.nix {
      inherit effectsInterface;
      resourceInterface = specification.selected.identity;
      inherit (specification) resourceKind;
      inherit (lib.abilities) transitionFragment;
    };
  in {
    inherit provide compose transition;
  };
in
  builtins.listToAttrs (builtins.map (kind: {
    name = kinds.${kind}.selected.alias;
    value = providerFor kind;
  }) (builtins.attrNames kinds))
