##! Systemd implementation of provider-neutral login-session tracking.
{
  abilitySelection ? null,
  lib,
  packageArtifactFor,
  ...
}: let
  interface = lib.abilities.interfaces.loginSessionTracking.interface;
  selectedBindings =
    if abilitySelection == null
    then []
    else abilitySelection.bindingsForImplementation interface.alias;
  selected =
    if selectedBindings == []
    then false
    else if builtins.length selectedBindings == 1
    then (builtins.head selectedBindings).request.value.parameters.enabled
    else throw "the systemd login-session implementation requires exactly one selected policy";
  systemd = packageArtifactFor (lib.abilities.packageOutput {});
  linuxPam = packageArtifactFor (lib.abilities.packageOutput {package = "linux-pam";});
in {
  config = lib.mkMerge [
    {
      aos.abilities.implementations.${interface.alias} = {
        description = "Registers authenticated login sessions through pam_systemd.";
        interface = interface.identity;
        artifact = lib.abilities.packageOutput {};
        methods = [];
        guarantees = [];
        providerModule = {
          artifact = lib.abilities.packageOutput {output = "module";};
          path = "provider/systemd.nix";
        };
        requiredFeatures = [];
      };
    }
    (lib.mkIf selected {
      aos.pam.sessionTrackingRule = {
        control = "optional";
        modulePath = "${systemd}/lib/security/pam_systemd.so";
        args = [];
      };
      aos.contributions.pamServices.systemd-user = {
        unixAuth = false;
        startSession = false;
        setLoginUid = false;
        useDefaultRules = false;
        text = ''
          account required ${linuxPam}/lib/security/pam_unix.so no_pass_expiry
          session  required ${linuxPam}/lib/security/pam_loginuid.so
          session  optional ${linuxPam}/lib/security/pam_keyinit.so force revoke
          session  required ${linuxPam}/lib/security/pam_namespace.so
          session  optional ${linuxPam}/lib/security/pam_umask.so silent
          session  optional ${systemd}/lib/security/pam_systemd.so
        '';
      };
    })
  ];
}
