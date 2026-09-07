##! modules/sandbox/controller.nix — shared sandbox controller identity
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.sandbox.controller;
  brokers = config.aos.sandbox;
in {
  options.aos.sandbox.controller = {
    uid = lib.mkOption {
      type = lib.types.int;
      default = brokers.hostBroker.controllerUid;
      defaultText = "config.aos.sandbox.hostBroker.controllerUid";
      description = "Stable UID of the unprivileged sandbox controller.";
    };

    gid = lib.mkOption {
      type = lib.types.int;
      default = brokers.hostBroker.controllerGid;
      defaultText = "config.aos.sandbox.hostBroker.controllerGid";
      description = "Stable GID of the unprivileged sandbox controller.";
    };
  };

  config = lib.mkIf (brokers.hostBroker.enable || brokers.mountBroker.enable) {
    assertions = [
      {
        assertion = cfg.uid > 0 && cfg.uid < 65536;
        message = "aos.sandbox.controller.uid must be in 1..65535";
      }
      {
        assertion = cfg.gid > 0 && cfg.gid < 65536;
        message = "aos.sandbox.controller.gid must be in 1..65535";
      }
    ];

    aos.users.users.aos-sandboxd = {
      uid = cfg.uid;
      group = "aos-sandboxd";
      home = "/var/lib/aos/sandboxd";
      shell = "/sbin/nologin";
      description = "AOS sandbox node controller";
      extraGroups = [];
    };
    aos.users.groups.aos-sandboxd = {
      gid = cfg.gid;
      members = [];
    };
  };
}
