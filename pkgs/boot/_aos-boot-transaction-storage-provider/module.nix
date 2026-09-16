##! ESP-backed implementation of the portable boot transaction-storage view.
{lib, ...}: let
  view = lib.abilities.interfaces.bootTransactionStorage.interfaces.view;
  artifact = lib.abilities.packageOutput {};
  terminalAlias = "boot-transaction-storage-view-effects";
  terminalDeclaration =
    view.declaration
    // {
      name = "aos.boot.transaction-storage-view-effects";
      outputs = {};
      aggregation =
        view.declaration.aggregation
        // {
          controllerGroup = terminalAlias;
        };
    };
  terminalIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration terminalDeclaration
  );
in {
  config.aos.abilities = {
    interfaces.${terminalAlias} = terminalDeclaration;

    implementations = {
      ${view.alias} = {
        description = "Selects the exact ESP-backed initrd transaction journal.";
        interface = view.identity;
        inherit artifact;
        inherit (view) methods;
        guarantees = [];
        requirements.effects = {
          alias = "effects";
          description = "Invokes the checked ESP transaction-storage terminal.";
          accepted_interfaces = [terminalIdentity];
          inherit (view) methods;
          guarantees = [];
          strength = "required";
          fallback = null;
        };
        providerModule = {
          artifact = lib.abilities.packageOutput {output = "module";};
          path = "provider.nix";
        };
        desiredType = view.realizationType;
        requiredFeatures = [];
      };

      ${terminalAlias} = {
        description = "Authenticates the package-materialized ESP transaction journal.";
        interface = terminalIdentity;
        inherit artifact;
        inherit (view) methods;
        guarantees = [];
        handlerDescriptor = {
          inherit artifact;
          entryPoint = "bin/aos-boot-transaction-storage-provider";
          arguments = view.requestType;
          result = view.observationType;
        };
        providerModule = null;
        desiredType = null;
        requiredFeatures = [];
      };
    };
  };
}
