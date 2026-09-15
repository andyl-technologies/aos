##! Checks package-owned audit configuration and service declarations.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "security-audit";
    module = ../../modules/security/audit.nix;
    packages = [pkgs.audit];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  daemon = requests."audit:auditd-lifecycle".parameters;
  loader = requests."audit:audit-rules-lifecycle".parameters;
in
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
  assert requests."audit:auditd-configuration-file".parameters.destination
  == "/etc/audit/auditd.conf";
  assert requests."audit:audit-rules-file".parameters.destination
  == "/etc/audit/audit.rules";
  assert config.systemd.services == {};
  assert !(config.environment.etc ? "audit/auditd.conf");
  assert !(config.environment.etc ? "audit/audit.rules"); true
