##! Native console services preserve host and initrd terminal policy.
{
  lib,
  pkgs,
}: let
  evaluate = stage: operatorModules:
    lib.evalPackageModules {
      scope = ["test" "getty" stage];
      packages = [pkgs.util-linux pkgs.systemd pkgs.nftables pkgs.aos-network-ruleset-provider];
      operatorModules = [{aos.getty.autologin.stage = stage;}] ++ operatorModules;
    };
  disabled = evaluate "host" [];
  host = evaluate "host" debug.config.aos.activation.stages.host.configuration;
  initrd = evaluate "initrd" debug.config.aos.activation.stages.initrd.configuration;
  fleetModule = import ../../pkgs/system/_systemd-abilities/testing/fleet-module.nix {
    inherit lib;
    packages = {inherit (pkgs) bash coreutils systemd;};
  };
  fleet = (fleetModule {
    bootMode = "kernel";
    varProvisioning = "baked";
    varSizeMiB = 2048;
    bakeAgentUnit = false;
    debugMac = "52:54:00:12:34:57";
    mac = "52:54:00:12:34:56";
    ip = "192.0.2.5";
    defaultAgentPackage = pkgs.aos-test-agent;
    inherit (pkgs) writeTextFile;
  }) {config.aos.packages = {};};
  fleetPolicies = fleet.aos.activation.stages.initrd.configuration;
  fleetInitrd = evaluate "initrd" (debug.config.aos.activation.stages.initrd.configuration ++ fleetPolicies);
  fleetBootstrap = import ../../pkgs/system/_systemd-abilities/bootstrap-services.nix {
    inherit lib pkgs;
    config = fleetInitrd.config;
  };
  withoutGettyContract = lib.evalModules {
    inherit lib;
    modules = fleetPolicies;
  };
  forceDisabled = evaluate "host" (debug.config.aos.activation.stages.host.configuration
    ++ [
      ({lib, ...}: {
        aos.services."getty.virtual-console".enable = lib.mkForce false;
        aos.services."getty.serial-console".enable = lib.mkForce false;
      })
    ]);
  hostVirtual = host.config.aos.services."getty.virtual-console";
  initrdVirtual = initrd.config.aos.services."getty.virtual-console";
  hostSerial = host.config.aos.services."getty.serial-console";
  initrdSerial = initrd.config.aos.services."getty.serial-console";
  bootstrap = import ../../pkgs/system/_systemd-abilities/bootstrap-services.nix {
    inherit lib pkgs;
    config = initrd.config;
  };
  initrdInputs = map (node: node.input) (gettyNodes initrd);
  fleetMasks = fleet.boot.initrd.systemd.maskedUnits;
  gettyNodes = evaluated:
    builtins.filter (node:
      builtins.elem (lib.last node.identity) ["getty.virtual-console" "getty.serial-console"])
    (builtins.attrValues evaluated.deployment.graph.nodes);
  debug = lib.evalModules {
    inherit lib;
    specialArgs = {inherit pkgs;};
    modules = [
      ../../modules/profiles/debug.nix
      ../../modules/base/activation-stages.nix
      ({lib, ...}: {
        options = {
          environment.systemPackages = lib.mkOption {
            type = lib.types.listOf lib.types.package;
            default = [];
          };
          environment.etc = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = {};
          };
          aos.boot.initrd.packageRoots = lib.mkOption {
            type = lib.types.listOf lib.types.package;
            default = [];
          };
        };
        config.aos.profiles.debug = {
          enable = true;
          autologin = true;
        };
      })
    ];
  };
  invalidStage = builtins.tryEval (builtins.deepSeq
    (evaluate "build" []).config.aos.getty.autologin.stage
    true);
in
  assert host.config.aos.security.level == "debug";
  assert map builtins.toString debug.config.environment.systemPackages == [(builtins.toString pkgs.util-linux)];
  assert map builtins.toString debug.config.aos.boot.initrd.packageRoots == [(builtins.toString pkgs.util-linux)];
  assert host.config.aos.getty.autologin.enable;
  assert initrd.config.aos.getty.autologin.enable;
  assert builtins.all (source: lib.hasPrefix "/nix/store/" (builtins.toString source))
  (debug.config.aos.activation.stages.host.configuration ++ debug.config.aos.activation.stages.initrd.configuration);
  assert debug.config.environment.etc.shadow.mode == "0000";
  assert gettyNodes disabled == [];
  assert gettyNodes forceDisabled == [];
  assert builtins.length (gettyNodes host) == 2;
  assert builtins.length (gettyNodes initrd) == 2;
  assert gettyNodes fleetInitrd == [];
  assert !(fleetBootstrap ? "getty.virtual-console") && !(fleetBootstrap ? "getty.serial-console");
  assert !(withoutGettyContract.config.aos.getty.autologin.enable or false);
  assert !invalidStage.success;
  assert (builtins.head hostVirtual.lifecycle.start).executable
  == {
    path = "${pkgs.util-linux}/libexec/aos-autologin-getty";
    arguments = ["--noclear" "tty1" "linux"];
  };
  assert hostVirtual.lifecycle.restart == "always";
  assert hostVirtual.lifecycle.stop_timeout_millis == 90000;
  assert hostSerial.lifecycle.stop_timeout_millis == 90000;
  assert hostVirtual.activationOwner == "ability" && hostVirtual.autoStart;
  assert hostSerial.activationOwner == "ability" && hostSerial.autoStart;
  assert hostVirtual.manager_identity == null && hostSerial.manager_identity == null;
  assert hostVirtual.dependencies.after == ["systemd-user-sessions.service"];
  assert hostVirtual.dependencies.wanted_by == ["getty.target"];
  assert hostVirtual.dependencies.implicit_dependencies;
  assert hostVirtual.terminal.device == "/dev/tty1";
  assert hostVirtual.terminal.reset;
  assert hostVirtual.terminal.hangup;
  assert hostVirtual.terminal.deallocate;
  assert hostVirtual.terminal.send_hangup_on_stop;
  assert hostVirtual.terminal.start_when_idle;
  assert hostVirtual.terminal.session_identifier == "tty1";
  assert (builtins.head hostSerial.lifecycle.start).executable.arguments == ["-s" "ttyS0" "115200" "vt100"];
  assert !hostSerial.terminal.deallocate;
  assert (builtins.head initrdVirtual.lifecycle.start).executable.arguments == ["--noclear" "tty0" "linux"];
  assert initrdVirtual.dependencies.after == [];
  assert initrdVirtual.dependencies.wanted_by == ["sysinit.target"];
  assert initrdSerial.dependencies.wanted_by == ["sysinit.target"];
  assert initrdVirtual.lifecycle.stop_timeout_millis == 5000;
  assert initrdSerial.lifecycle.stop_timeout_millis == 5000;
  assert bootstrap ? "getty.virtual-console" && bootstrap ? "getty.serial-console";
  assert initrdVirtual.manager_identity.name == "debug-shell-console";
  assert initrdSerial.manager_identity.name == "debug-shell-serial";
  assert builtins.all (input: input.activation_owner == "image" && !input.auto_start) initrdInputs;
  assert builtins.all (input: builtins.elem "${input.manager_identity.name}.service" fleetMasks) initrdInputs;
  assert !initrdVirtual.dependencies.implicit_dependencies;
  assert initrdVirtual.terminal.device == "/dev/tty0";
  assert !initrdVirtual.terminal.deallocate;
  assert !initrdVirtual.terminal.send_hangup_on_stop;
  assert !initrdVirtual.terminal.start_when_idle;
  assert initrdVirtual.terminal.session_identifier == null; true
