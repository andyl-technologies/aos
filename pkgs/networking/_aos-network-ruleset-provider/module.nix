##! nftables implementation of the provider-neutral aggregate network ruleset.
{lib, ...}: let
  networkPolicy = lib.abilities.interfaces.networkPolicy;
  ruleset = networkPolicy.interfaces.ruleset;
  artifact = lib.abilities.packageOutput {};
  effectsAlias = "network-ruleset-effects";
  effectsDeclaration = lib.abilities.declareInterface {
    name = "aos.network.ruleset-effects";
    description = "Executes admitted aggregate network-ruleset operations through nftables.";
    abi = 1;
    inherit (ruleset.declaration) requestType methods lifecycle;
    outputs = {};
    guarantees = [];
    aggregation = ruleset.declaration.aggregation // {controllerGroup = effectsAlias;};
  };
  effectsIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration effectsDeclaration
  );
  providerModule = {
    artifact = lib.abilities.packageOutput {output = "module";};
    path = "provider.nix";
  };
  facetImplementation = interface: {
    description = "Contributes ${interface.declaration.name} to the selected nftables ruleset.";
    interface = interface.identity;
    inherit artifact providerModule;
    inherit (interface) methods;
    guarantees = [];
    desiredType = null;
    requiredFeatures = [];
  };
in {
  config.aos.abilities = {
    interfaces.${effectsAlias} = effectsDeclaration;

    implementations = {
      network-ruleset = {
        description = "Converges one aggregate host network ruleset through nftables.";
        interface = ruleset.identity;
        inherit artifact providerModule;
        inherit (ruleset) methods;
        guarantees = [];
        requirements.effects = {
          alias = "effects";
          description = "Invokes the package-owned nftables terminal handler.";
          accepted_interfaces = [effectsIdentity];
          inherit (ruleset) methods;
          guarantees = [];
          strength = "required";
          fallback = null;
        };
        desiredType = networkPolicy.realizationType;
        compositionType = networkPolicy.aggregateRequest;
        requiredFeatures = [];
      };

      network-ingress-policy = facetImplementation networkPolicy.interfaces.ingress;
      network-forwarding-policy = facetImplementation networkPolicy.interfaces.forwarding;

      ${effectsAlias} = {
        description = "Executes authorized aggregate network-ruleset operations through nftables.";
        interface = effectsAlias;
        inherit artifact;
        inherit (ruleset) methods;
        guarantees = [];
        handlerDescriptor = {
          inherit artifact;
          entryPoint = "bin/aos-network-ruleset-provider";
          arguments = networkPolicy.aggregateRequest;
          result = networkPolicy.observationType;
        };
        desiredType = null;
        requiredFeatures = [];
      };
    };
  };
}
