##! Checks final evaluated signer settings; this predicate grants no runtime authority.
{
  config,
  lib,
  pkgs,
  package,
  unit,
  identity,
  expectedExec,
}: let
  settings = unit.serviceConfig;
  emptyDirective = value: value == null || value == "" || value == [];
  disabledDirective = value: emptyDirective value || value == false || value == 0
    || (builtins.isString value && builtins.elem (lib.toLower value) ["no" "false" "0"]);
  connectedPrivateTmp = value: value == true || value == 1
    || (builtins.isString value && builtins.elem (lib.toLower value) ["yes" "true" "1" "connected"]);
  auxiliaryCommands = ["ExecCondition" "ExecStartPre" "ExecStartPost" "ExecReload" "ExecReloadPost" "ExecStop" "ExecStopPost"];
in
  config.aos.security.selinux.enable
  && config.aos.security.selinux.bootMode == "immutable-stage0"
  && package == pkgs.aos-sandboxd
  && (import ./_fixed-systemd-profile.nix {inherit config pkgs;})
  && disabledDirective (settings.PrivateUsers or false)
  && disabledDirective (settings.PrivatePIDs or false)
  && disabledDirective (settings.PrivateBPF or false)
  && disabledDirective (settings.DynamicUser or false)
  && emptyDirective (settings.UserNamespacePath or null)
  && emptyDirective (settings.DelegateNamespaces or null)
  && disabledDirective (settings.RootEphemeral or false)
  && connectedPrivateTmp (settings.PrivateTmp or false)
  && connectedPrivateTmp (settings.PrivateVarTmp or settings.PrivateTmp or false)
  && builtins.all (name: emptyDirective (settings.${name} or null))
    ["RootDirectory" "RootImage" "RootMStack" "MountImages" "ExtensionImages" "ExtensionDirectories" "TemporaryFileSystem"
     "RuntimeDirectory" "StateDirectory" "CacheDirectory" "LogsDirectory" "ConfigurationDirectory"]
  && emptyDirective (settings.PAMName or null)
  && emptyDirective (settings.EnvironmentFile or null)
  && (settings.ExecStart or null) == expectedExec
  && (settings.User or null) == identity
  && (settings.Group or null) == identity
  && builtins.all (name: emptyDirective (settings.${name} or null)) auxiliaryCommands
  && builtins.all (name: emptyDirective (unit.${name} or null)) ["script" "preStart" "postStart" "preStop" "postStop" "reload"]
