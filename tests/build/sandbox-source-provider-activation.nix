# RootMount-to-SourceProvider activation remains explicit and socket-scoped.
{
  pkgs,
  lib,
}: let
  systemdOptions = {lib, ...}: {
    options.assertions = lib.mkOption {
      type = lib.types.listOf lib.types.anything;
      default = [];
    };
    options.systemd.services = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
    options.systemd.sockets = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
    options.aos.sandbox.hostBroker.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
    };
    options.aos.sandbox.hostBroker.credentials.journalMacKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
    };
    options.aos.sandbox.sourceProvider.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
    };
  };
  mount = lib.evalModules {
    specialArgs = {inherit pkgs;};
    modules = [
      systemdOptions
      ../../modules/sandbox/mount-broker.nix
      {aos.sandbox.mountBroker.enable = true;}
    ];
  };
  inactive = mount.config.systemd.services.aos-sandbox-mountd;
  active =
    (mount.extendModules {
      modules = [{aos.sandbox.sourceProvider.enable = true;}];
    }).config.systemd.services.aos-sandbox-mountd;
in
  assert !(lib.elem "aos-source-providerd.socket" inactive.requires);
  assert !(lib.elem "aos-source-providerd.socket" inactive.after);
  assert !(lib.hasSuffix " --source-provider" inactive.serviceConfig.ExecStart);
  assert lib.elem "aos-source-providerd.socket" active.requires;
  assert lib.elem "aos-source-providerd.socket" active.after;
  assert lib.hasSuffix " --source-provider" active.serviceConfig.ExecStart;
    pkgs.mkDerivation {
      pname = "sandbox-source-provider-activation-contract";
      version = "0";
      src = null;
      buildDeps = [];
      runtimeDeps = [];
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
