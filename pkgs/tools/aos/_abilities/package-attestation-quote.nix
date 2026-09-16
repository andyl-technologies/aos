##! AOS package policy consumed by the selected attestation service provider.
{lib, ...}: {
  options.aos.packageRuntime.packageAttestationQuote.packageProfileEnabled = lib.mkOption {
    type = lib.abilities.types.boolean;
    default = false;
    internal = true;
    description = "Whether quote production waits for package-profile convergence.";
  };
}
