##! Preserves server identities and service policy in native re-evaluation.
{
  config,
  options,
  lib,
  ...
}: let
  cfg = config.aos.roles.server;
  identity = config.aos.abilities.identity.operations;
in {
  options.aos.roles.server.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Enable server identities, chrony, SSH, and standard security policy.";
  };
  config = lib.mkIf (cfg.enable && (config.aos.boot.stage or "host") == "host") ({
      # Admit these role requirements before evaluating their service policy.
      aos.apm.desiredPackages = lib.mkAfter ["openssh" "chrony"];

      aos.services.chrony.enable = lib.mkDefault true;
      aos.services.ssh.enable = lib.mkDefault true;
      aos.security.level = lib.mkDefault "standard";
      aos.abilities.identity.operations = {
        group.effects.server-registry.input = {
          name = "aos-gitd";
          requested_id = 800;
        };
        principal.effects.server-registry.input = {
          name = "aos-gitd";
          requested_id = 800;
          primary_group = identity.group.effects.server-registry.outputs.name;
          home_directory = "/var/lib/aos-registry-server/registries";
          description = "AOS registry server";
        };
      };
    }
    // lib.optionalAttrs (options ? "aos-registry-server") {
      "aos-registry-server".enable = lib.mkDefault true;
    });
}
