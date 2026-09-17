##! Checks hardening tunables independently of the early /etc overlay.
{
  lib,
  pkgs,
}: let
  evaluate = import ./base-module-evaluation.nix {inherit lib pkgs;};
  evaluated = evaluate {
    name = "base-hardening";
    module = ../../modules/security/hardening.nix;
    packages = [pkgs.aos-kernel-tunable-provider];
  };
  enabledCoreDump = evaluate {
    name = "base-hardening-coredump";
    module = {
      imports = [../../modules/security/hardening.nix];
      aos.security.hardening.coreDump.enable = true;
    };
    packages = [pkgs.aos-kernel-tunable-provider];
  };
  config = evaluated.config;
  request = config.aos.abilities.requests."system:security-tunables";
  requirement = config.aos.abilities.requirementTemplates."system:kernel-tunables";
  enabledCoreDumpRequest =
    enabledCoreDump.config.aos.abilities.requests."system:security-tunables";
in
  assert requirement.methods == ["apply" "observe" "remove"];
  assert request.parameters.values."kernel.dmesg_restrict" == "1";
  assert request.parameters.values."kernel.kptr_restrict" == "2";
  assert request.parameters.values."kernel.core_pattern" == "|${pkgs.coreutils}/bin/false";
  assert enabledCoreDumpRequest.parameters.values."kernel.core_pattern"
  == "|${pkgs.systemd}/lib/systemd/systemd-coredump %P %u %g %s %t %c %h %e";
  assert request.parameters.dependencies == [];
  assert !(config.environment.etc ? "sysctl.d/80-aos-hardening.conf");
  assert !(config.environment.etc ? "sysctl.d/81-aos-coredump.conf");
  assert config.environment.etc ? "systemd/coredump.conf";
  assert (config.systemd.services or {}) == {}; true
