##! Package-owned login-session tracking requirement for Linux PAM.
{
  config,
  lib,
  ...
}: let
  enabled = lib.attrByPath ["aos" "pam" "enable"] true config;
  sessionTracking = lib.abilities.interfaces.loginSessionTracking.interface;
  configured = enabled && config.aos.abilities.environment != null;
in {
  config.aos.abilities = {
    requirementTemplates.login-session-tracking = {
      description = "Requires integration with the selected system manager for login sessions.";
      interface = sessionTracking.identity.name;
      inherit (sessionTracking.identity) abi descriptor;
    };
    instances = lib.mkIf configured {session = {};};
    requests = lib.mkIf configured {
      login-session-tracking = {
        requirement = "login-session-tracking";
        consumer = "session";
        scope = ["login-sessions"];
        parameters.enabled = true;
      };
    };
  };
}
