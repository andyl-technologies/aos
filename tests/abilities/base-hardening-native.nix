##! Checks hardening tunables independently of the early /etc overlay.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "base-hardening";
    module = ../../modules/security/hardening.nix;
    packages = [pkgs.aos-kernel-tunable-provider pkgs.systemd];
  };
  enabledCoreDump = evaluate {
    name = "base-hardening-coredump";
    module = {
      imports = [../../modules/security/hardening.nix];
      aos.security.hardening.coreDump.enable = true;
    };
    packages = [pkgs.aos-kernel-tunable-provider pkgs.systemd];
  };
  config = evaluated.config;
  request = config.aos.abilities.requests."system:security-tunables";
  requirement = config.aos.abilities.requirementTemplates."system:kernel-tunables";
  crashDumpRequest = config.aos.abilities.requests."system:crash-dump-policy";
  enabledCrashDumpRequest = enabledCoreDump.config.aos.abilities.requests."system:crash-dump-policy";
  render = enabled:
    import ../../pkgs/system/_systemd-abilities/platform/_crash-dump-configuration.nix {
      policy = {inherit enabled;};
      systemd = "/systemd";
      coreutils = "/coreutils";
    };
  disabledRendering = render false;
  enabledRendering = render true;
in
  assert requirement.methods == ["apply" "observe" "remove"];
  assert request.parameters.values."kernel.dmesg_restrict" == "1";
  assert request.parameters.values."kernel.kptr_restrict" == "2";
  assert !(request.parameters.values ? "kernel.core_pattern");
  assert !crashDumpRequest.parameters.enabled;
  assert enabledCrashDumpRequest.parameters.enabled;
  assert config.aos.abilities.implementations."systemd:crash-dump-policy".interface
  == lib.abilities.interfaces.crashDumpPolicy.interface.identity;
  assert disabledRendering.corePattern == "|/coreutils/bin/false";
  assert enabledRendering.corePattern
  == "|/systemd/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %e";
  assert lib.hasInfix "Storage=none" disabledRendering.etc."systemd/coredump.conf".text;
  assert lib.hasInfix "Storage=journal" enabledRendering.etc."systemd/coredump.conf".text;
  assert request.parameters.dependencies == [];
  assert (config.systemd.services or {}) == {}; true
