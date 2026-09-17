##! AOS package policy consumed by the selected attestation service provider.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.packageRuntime.packageAttestationQuote;
  readinessDeclaration = config.aos.abilities.interfaces."aos:package-profile-readiness";
  readinessIdentity = lib.abilities.interfaceIdentity (
    lib.abilities.interfaceDocumentFromDeclaration readinessDeclaration
  );
  hostStage =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
in {
  options.aos.packageRuntime.packageAttestationQuote.packageProfileEnabled = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = false;
    internal = true;
    description = "Whether quote production waits for package-profile convergence.";
  };

  config.aos.abilities = lib.mkIf (hostStage && cfg.packageProfileEnabled) {
    requirementTemplates.package-profile-readiness = {
      description = "Require completion of the selected system package profile before producing a quote.";
      interface = readinessIdentity.name;
      inherit (readinessIdentity) abi descriptor;
      methods = [];
      guarantees = [];
      strength = "required";
      fallback = null;
    };
    instances.package-attestation-policy = {};
    requests.package-profile-readiness = {
      requirement = "package-profile-readiness";
      consumer = "package-attestation-policy";
      scope = ["system-profile"];
      parameters = "system-profile";
    };
  };
}
