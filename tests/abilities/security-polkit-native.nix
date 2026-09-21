##! Checks package-owned polkit identity and service declarations.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "security-polkit";
    module.aos.security.polkit.enable = true;
    packages = [pkgs.polkit pkgs.dbus pkgs.systemd];
  };
  config = evaluated.config;
  requests = config.aos.abilities.requests;
  lifecycle = requests."polkit:polkit-lifecycle".parameters;
  dependencies = requests."polkit:polkit-dependencies".parameters;
  identity = requests."polkit:polkit-identity".parameters;
in
  assert lifecycle.service == "polkit";
  assert lifecycle.configuration_change_action == "reload";
  assert lifecycle.start
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "polkit";};
        entry_point = "lib/polkit-1/polkitd";
        arguments = ["--no-debug" "--log-level=notice"];
      };
      ignore_failure = false;
    }
  ];
  assert identity.principal
  == {
    _type = "aos-request-output-reference";
    request = "polkit:service-principal";
    output = "principal-name";
  };
  assert dependencies.requires
  == [
    {
      _type = "aos-request-output-reference";
      request = "polkit:system-bus-availability";
      output = "resource";
    }
  ];
  assert dependencies.wants == [];
  assert requests."polkit:system-bus-availability".parameters.scope == "system-bus";
  assert requests."polkit:polkit-resources".parameters.memory_swap_max_bytes.value
  == 33554432;
  assert requests."polkit:polkit-resources".parameters.locked_memory_bytes.value == 0;
  assert requests."polkit:polkit-resources".parameters.oom_policy == "stop";
  assert requests."polkit:polkit-linux_device_policy".parameters.rules
  == [
    {
      selector = {
        kind = "number";
        device_type = "character";
        major = 1;
        minor = 3;
      };
      read = true;
      write = true;
      create_node = false;
    }
  ];
  assert requests."polkit:local-rules-file".parameters.destination
  == "/etc/polkit-1/rules.d/10-aos.rules";
  assert requests."polkit:packaged-actions-file".parameters.destination
  == "/etc/polkit-1/actions/org.freedesktop.policykit.policy";
  assert config.aos.contributions.pamServices."polkit-1"
  == {
    unixAuth = true;
    startSession = false;
    setLoginUid = false;
  };
  assert requests."polkit:wrapper-pkexec".parameters.entry.source.reference
  == {
    artifact = lib.abilities.packageOutput {package = "polkit";};
    path = "bin/pkexec";
  };
  assert requests."polkit:wrapper-pkexec".parameters.prerequisites
  == [(lib.abilities.resultOf "aos:wrapper-bin" "resource")];
  assert config.aos.contributions.runtimeChecks.polkit.description
  == "polkit policy and privilege checks";
  assert lib.abilities.types.isPortableOptionTree evaluated.options.aos.contributions;
  assert (config.systemd.services or {}) == {};
  assert !(config.environment.etc ? "polkit-1/rules.d/10-aos.rules");
  assert !(config.environment.etc ? "polkit-1/actions/org.freedesktop.policykit.policy");
  assert !(config.environment.etc ? "tmpfiles.d/aos-polkit.conf"); true
