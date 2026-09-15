##! Checks package-owned SELinux configuration and early service ordering.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "security-selinux";
    module = {
      imports = [../../modules/security/selinux.nix];
      aos.security.selinux.enable = true;
    };
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
      request = "refpolicy:sysinit-target";
      output = "unit-resource";
    }
    {
      _type = "aos-request-output-reference";
      request = "refpolicy:tmpfiles-setup";
      output = "unit-resource";
    }
  ];
  assert loaderDependencies.wanted_by
  == [
    {
      _type = "aos-request-output-reference";
      request = "refpolicy:sysinit-target";
      output = "unit-resource";
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
  assert config.systemd.services == {};
  assert !(config.environment.etc ? "selinux/config");
  assert !(config.environment.etc ? "selinux/semanage.conf"); true
