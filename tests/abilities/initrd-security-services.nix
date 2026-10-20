##! Native package-owned initrd identity and whole-root verification declarations.
{
  lib,
  pkgs,
}: let
  checks = import ../effects/boot-consumers.nix;
  identityScript = builtins.readFile ../../pkgs/security/_aos-boot-identity/aos-boot-identity-success.sh;
  verificationScript = builtins.readFile ../../pkgs/security/_aos-verity-root-guard/aos-verity-root-verify.sh;
  seedProfilesScript = builtins.readFile ../../pkgs/boot/_aos-boot-preparations/aos-seed-profiles.sh;
  managerCommands = ["systemctl" "bootctl" "aos-systemd-veritysetup-generator" "/run/systemd"];
in
  assert builtins.all (value: value) (builtins.attrValues checks);
  assert builtins.all (command: !(lib.hasInfix command identityScript)) managerCommands;
  assert builtins.all (command: !(lib.hasInfix command verificationScript)) managerCommands;
  assert builtins.all (command: !(lib.hasInfix command seedProfilesScript)) ["systemctl" "bootctl"]; true
