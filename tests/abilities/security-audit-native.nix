##! Checks package-owned audit configuration and service declarations.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "security-audit";
    module = {};
    packages = [pkgs.audit];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  daemon = requests."audit:auditd-lifecycle".parameters;
  loader = requests."audit:audit-rules-lifecycle".parameters;
  loaderDependencies = requests."audit:audit-rules-dependencies".parameters;
in
  assert config.aos.kernel.commandLineParts.audit == ["audit=1"];
  assert config.aos.abilities.runtimeChecks."audit:audit".description == "Audit policy checks";
  assert daemon.service == "auditd";
  assert daemon.execution_model == "foreground";
  assert daemon.configuration_change_action == "reload";
  assert daemon.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "audit";};
        entry_point = "sbin/auditd";
        arguments = ["-n"];
      };
      ignore_failure = false;
    }
  ];
  assert loader.service == "audit-rules";
  assert loader.execution_model == "oneshot";
  assert loader.remain_after_exit;
  assert builtins.elem (lib.abilities.resultOf "audit:auditd-lifecycle" "resource") loaderDependencies.prerequisites;
  assert requests."audit:auditd-configuration-file".parameters.destination
  == "/etc/audit/auditd.conf";
  assert requests."audit:audit-rules-file".parameters.destination
  == "/etc/audit/audit.rules";
  assert (config.systemd.services or {}) == {};
  assert !(config.environment.etc ? "audit/auditd.conf");
  assert !(config.environment.etc ? "audit/audit.rules"); true
