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
  providerOnly =
    (mount.extendModules {
      modules = [{aos.sandbox.sourceProvider.enable = true;}];
    }).config.systemd.services.aos-sandbox-mountd;
  activeConfiguration = mount.extendModules {
    modules = [{
      aos.sandbox.sourceProvider.enable = true;
      aos.sandbox.mountBroker.sourceProviderSession.enable = true;
    }];
  };
  active = activeConfiguration.config.systemd.services.aos-sandbox-mountd;
  invalidConfiguration = mount.extendModules {
    modules = [{aos.sandbox.mountBroker.sourceProviderSession.enable = true;}];
  };
  connectorAssertion = check:
    check.message == "aos.sandbox.mountBroker.sourceProviderSession.enable requires aos.sandbox.sourceProvider.enable";
in
  assert !(lib.elem "aos-source-providerd.socket" inactive.requires);
  assert !(lib.elem "aos-source-providerd.socket" inactive.after);
  assert !(lib.hasSuffix " --source-provider" inactive.serviceConfig.ExecStart);
  assert !(lib.elem "aos-source-providerd.socket" providerOnly.requires);
  assert !(lib.elem "aos-source-providerd.socket" providerOnly.after);
  assert !(lib.hasSuffix " --source-provider" providerOnly.serviceConfig.ExecStart);
  assert lib.length (lib.filter connectorAssertion activeConfiguration.config.assertions) == 1;
  assert lib.all (check: check.assertion) (lib.filter connectorAssertion activeConfiguration.config.assertions);
  assert lib.any (check: !check.assertion) (lib.filter connectorAssertion invalidConfiguration.config.assertions);
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
