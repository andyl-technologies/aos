##! Authors disposable resources for native filesystem and firewall flights.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.nativeDomainQualification;
  directories = ["directory" "allocate" "persistentAllocate" "entry"];
  pathFor = name: "/var/lib/aos/native-domain-qualification-${name}";
  directoryEffect = name:
    lib.mkIf cfg.enabled.${name} {
      effects.native-qualification = {
        input = {
          path = pathFor name;
          mode = cfg.mode;
        };
        lifetime =
          if name == "persistentAllocate"
          then "persistent"
          else "instance";
      };
    };
in {
  options.aos.nativeDomainQualification = {
    enabled = lib.mkOption {
      type = lib.types.submodule {
        options = lib.genAttrs (directories ++ ["file"]) (_:
          lib.mkOption {
            type = lib.types.bool;
            default = true;
          });
      };
      default = {};
      description = "Controlled native domain effects selected by qualification.";
    };
    mode = lib.mkOption {
      type = lib.types.str;
      default = "0750";
      description = "Requested disposable directory mode.";
    };
    content = lib.mkOption {
      type = lib.types.str;
      default = "native-domain-baseline\n";
      description = "Requested disposable configuration file bytes.";
    };
    firewallPort = lib.mkOption {
      type = lib.types.int;
      default = 18190;
      description = "Disposable native firewall allowance.";
    };
  };

  config = {
    aos.abilities.filesystem.operations = lib.genAttrs directories directoryEffect;
    aos.abilities.configuration.operations.file.effects = lib.mkIf cfg.enabled.file {
      native-qualification.input = {
        path = pathFor "file";
        content = cfg.content;
        mode = "0640";
      };
    };
    aos.networkPolicy = {
      enable = lib.mkDefault true;
      allowedTCP = lib.mkForce [22 18081 18082 cfg.firewallPort];
      allowedUDP = lib.mkForce [];
      defaultPolicy = lib.mkForce "drop";
      forwardPolicy = lib.mkForce "drop";
    };
  };
}
