##! Adds native systemd login-session policy to the shared PAM domain.
{
  config,
  lib,
  package,
  dependencies,
  ...
}: {
  config = lib.mkIf config.aos.pam.enable {
    aos.pam.sessionTrackingRule = {
      control = "optional";
      modulePath = "${package}/lib/security/pam_systemd.so";
      args = [];
    };
    aos.pam.packageServices.systemd-user = {
      useDefaultRules = false;
      text = ''
        account required ${dependencies.linux-pam}/lib/security/pam_unix.so no_pass_expiry
        session required ${dependencies.linux-pam}/lib/security/pam_loginuid.so
        session optional ${dependencies.linux-pam}/lib/security/pam_keyinit.so force revoke
        session required ${dependencies.linux-pam}/lib/security/pam_namespace.so
        session optional ${dependencies.linux-pam}/lib/security/pam_umask.so silent
        session optional ${package}/lib/security/pam_systemd.so
      '';
    };
  };
}
