##! Controller and terminal implementations for transaction boot preparation.
{lib, ...}: let
  interface = lib.abilities.interfaces.bootPreparation.interfaces.preparation;
  artifact = lib.abilities.packageOutput {};
  terminalAlias = "boot-preparation-command";
  terminalDeclaration =
    interface.declaration
    // {
      name = "aos.boot.preparation-command";
      description = "Executes one checked transaction-scoped boot preparation command.";
      outputs = {};
      aggregation =
        interface.declaration.aggregation
        // {
          controllerGroup = "boot-preparation-command";
        };
    };
  terminalIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration terminalDeclaration
  );
  realizationType = lib.abilities.types.record {
    fields.schema = lib.abilities.types.enum ["aos.boot.preparation-realization/v1"];
  };
in {
  config.aos.abilities = {
    interfaces.${terminalAlias} = terminalDeclaration;

    implementations = {
      boot-preparation = {
        description = "Controls exact transaction-scoped boot preparations through a checked terminal command binding.";
        interface = interface.identity;
        inherit artifact;
        desiredType = realizationType;
        inherit (interface) methods;
        guarantees = [];
        requirements.command = {
          alias = "command";
          description = "Selects the terminal command executor used by the preparation controller.";
          accepted_interfaces = [terminalIdentity];
          inherit (interface) methods;
          guarantees = [];
          strength = "required";
          fallback = null;
        };
        providerModule = {
          inherit artifact;
          path = "share/aos/providers/boot-preparation.nix";
        };
        requiredFeatures = [];
      };

      ${terminalAlias} = {
        description = "Executes exact boot preparation commands selected by the package-owned controller.";
        interface = terminalAlias;
        inherit artifact;
        desiredType = null;
        inherit (interface) methods;
        guarantees = [];
        handlerDescriptor = {
          inherit artifact;
          entryPoint = "bin/aos-boot-preparation-provider";
          arguments = interface.requestType;
          result = interface.observationType;
        };
        requiredFeatures = [];
      };
    };
  };
}
