##! Checks package-owned SELinux configuration and early service ordering.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "security-selinux";
    module.aos.security.selinux.enable = true;
    packages = [pkgs.refpolicy pkgs.systemd];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  loader = requests."refpolicy:selinux-policy-load-lifecycle".parameters;
  loaderDependencies = requests."refpolicy:selinux-policy-load-dependencies".parameters;
  autorelabel = requests."refpolicy:selinux-autorelabel-lifecycle".parameters;
in
  assert loader.execution_model == "oneshot";
  assert loader.remain_after_exit;
  assert loader.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "refpolicy";};
        entry_point = "libexec/aos-selinux-load-policy";
        arguments = ["refpolicy" "enforcing"];
      };
      ignore_failure = false;
    }
  ];
  assert loaderDependencies.before
  == [
    {
      _type = "aos-request-output-reference";
      request = "refpolicy:early-system";
      output = "resource";
    }
    {
      _type = "aos-request-output-reference";
      request = "refpolicy:runtime-entry-population";
      output = "resource";
    }
  ];
  assert loaderDependencies.wanted_by
  == [
    {
      _type = "aos-request-output-reference";
      request = "refpolicy:early-system";
      output = "resource";
    }
  ];
  assert autorelabel.enabled;
  assert autorelabel.condition
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "coreutils";};
        entry_point = "bin/test";
        arguments = ["-f" "/.autorelabel"];
      };
      ignore_failure = false;
    }
  ];
  assert requests."refpolicy:selinux-config".parameters.destination == "/etc/selinux/config";
  assert requests."refpolicy:semanage-config".parameters.destination == "/etc/selinux/semanage.conf";
  assert requests."refpolicy:early-system".parameters.milestone == "early-system";
  assert requests."refpolicy:runtime-entry-population".parameters.entries == [];
  assert config.aos.contributions.kernelParameters.refpolicy
  == [
    "enforcing=0"
    "security=selinux"
    "selinux=1"
  ];
  assert config.aos.contributions.filesystemTrees
  == [
    {
      target = "selinux/refpolicy/contexts";
      source = {
        artifact = lib.abilities.packageOutput {package = "refpolicy";};
        path = "etc/selinux/refpolicy/contexts";
      };
    }
  ];
  assert config.aos.contributions.runtimeChecks.selinux.description == "SELinux checks";
  assert lib.abilities.types.isPortableOptionTree evaluated.options.aos.contributions;
  assert (config.systemd.services or {}) == {};
  assert !(config.environment.etc ? "selinux/config");
  assert !(config.environment.etc ? "selinux/semanage.conf"); true
