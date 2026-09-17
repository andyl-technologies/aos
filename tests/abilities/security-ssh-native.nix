##! Checks package-owned OpenSSH configuration and service declarations.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "security-ssh";
    module = ../../modules/security/ssh.nix;
    packages = [pkgs.openssh];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  daemon = requests."openssh:sshd-lifecycle".parameters;
  dependencies = requests."openssh:sshd-dependencies".parameters;
in
  assert daemon.service == "sshd";
  assert daemon.execution_model == "foreground";
  assert daemon.restart == "on-failure";
  assert daemon.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "openssh";};
        entry_point = "sbin/sshd";
        arguments = ["-D" "-f" "/etc/ssh/sshd_config"];
      };
      ignore_failure = false;
    }
  ];
  assert !requests."openssh:sshd-keygen-lifecycle".parameters.enabled;
  assert requests."openssh:sshd-keygen-lifecycle".parameters.remain_after_exit;
  assert requests."openssh:sshd-keygen-lifecycle".parameters.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "openssh";};
        entry_point = "libexec/aos-openssh-host-key";
        arguments = [];
      };
      ignore_failure = false;
    }
  ];
  assert requests."openssh:sshd-keygen-environment".parameters.search_path == [];
  assert !requests."openssh:aos-ssh-ready-lifecycle".parameters.enabled;
  assert requests."openssh:aos-ssh-ready-lifecycle".parameters.start_timeout_millis == 90000;
  assert requests."openssh:aos-ssh-ready-lifecycle".parameters.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "openssh";};
        entry_point = "libexec/aos-openssh-host-policy-wait";
        arguments = [];
      };
      ignore_failure = false;
    }
  ];
  assert requests."openssh:aos-ssh-ready-environment".parameters.search_path == [];
  assert dependencies.requires
  == [
    {
      _type = "aos-request-output-reference";
      request = "openssh:sshd-keygen-lifecycle";
      output = "service-resource";
    }
    {
      _type = "aos-request-output-reference";
      request = "openssh:sshd-config";
      output = "retained-resource";
    }
    {
      _type = "aos-request-output-reference";
      request = "openssh:privilege-separation-directory";
      output = "retained-resource";
    }
  ];
  assert requests."openssh:sshd-config".parameters.destination == "/etc/ssh/sshd_config";
  assert requests."openssh:authorized-keys-directory".parameters.destination
  == "/etc/ssh/authorized_keys";
  assert requests."openssh:privilege-separation-directory".parameters.destination == "/var/empty";
  assert requests."openssh:sshd-principal".parameters.requested_id == 198;
  assert requests."openssh:network-ingress".parameters
  == {
    endpoints = [
      {
        transport = "tcp";
        port = 22;
      }
    ];
    prerequisites = [];
  };
  assert config.aos.contributions.pamServices.sshd
  == {
    unixAuth = false;
    startSession = true;
    setLoginUid = true;
  };
  assert config.aos.contributions.runtimeChecks.ssh.description == "SSH server checks";
  assert lib.abilities.types.isPortableOptionTree evaluated.options.aos.contributions;
  assert (config.systemd.services or {}) == {};
  assert !(config.environment.etc ? "ssh/sshd_config");
  assert !(config.environment.etc ? "tmpfiles.d/aos-ssh.conf"); true
