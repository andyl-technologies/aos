##! systems/server-secureboot-lockdown.nix — Lockdown test fixture (RFC-0006 phase 2)
##!
##! server-secureboot plus the lockdown deployment kernel: lockdown LSM,
##! enforced module signing (with the throwaway test module-signing key),
##! and signed kexec. Boots under enforcing Secure Boot exactly like
##! server-secureboot, but the running kernel additionally refuses
##! unsigned modules and locks down the integrity/confidentiality
##! surface. `tests/fleet/secure-boot-lockdown.nix` drives it.
##!
##! Auto-registers as `systems.server-secureboot-lockdown`.
{
  lib,
  pkgs,
  ...
}: {
  imports = [./server-secureboot.nix];

  aos.boot.secureBoot.lockdown = {
    enable = true;
    mode = "confidentiality";
    moduleSigningKey = "${pkgs.secure-boot-test-keys}/modsign.pem";
  };
}
