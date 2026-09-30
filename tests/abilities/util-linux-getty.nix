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
  assert !invalidStage.success;
  assert (builtins.head hostVirtual.lifecycle.start).executable
  == {
    path = "${pkgs.util-linux}/libexec/aos-autologin-getty";
    arguments = ["--noclear" "tty1" "linux"];
  };
  assert hostVirtual.lifecycle.restart == "always";
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
  assert initrdVirtual.dependencies.wanted_by == ["initrd-fs.target"];
  assert !initrdVirtual.dependencies.implicit_dependencies;
  assert initrdVirtual.terminal.device == "/dev/tty0";
  assert !initrdVirtual.terminal.deallocate;
  assert !initrdVirtual.terminal.send_hangup_on_stop;
  assert !initrdVirtual.terminal.start_when_idle;
  assert initrdVirtual.terminal.session_identifier == null; true
