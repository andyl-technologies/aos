##! Selected systemd projection of provider-neutral login-session tracking.
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
  config = lib.mkIf selected {
    aos.pam.sessionTrackingRule = {
      control = "optional";
      modulePath = "${systemd}/lib/security/pam_systemd.so";
      args = [];
    };
    environment.etc."pam.d/systemd-user".text = ''
      account required ${linuxPam}/lib/security/pam_unix.so no_pass_expiry
      session  required ${linuxPam}/lib/security/pam_loginuid.so
      session  optional ${linuxPam}/lib/security/pam_keyinit.so force revoke
      session  required ${linuxPam}/lib/security/pam_namespace.so
      session  optional ${linuxPam}/lib/security/pam_umask.so silent
      session  optional ${systemd}/lib/security/pam_systemd.so
    '';
  };
}
