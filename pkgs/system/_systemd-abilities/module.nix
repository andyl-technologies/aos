##! Selects native systemd runtime handlers and package-owned host policies.
{package, ...}: let
  program =
    package
    // {
      mainProgram = "aos-service-handler";
      meta.mainProgram = "aos-service-handler";
    };
in {
  imports = [
    ./dbus-registrations.nix
    ./core.nix
    ./resource-handlers.nix
    ./packaged-unit.nix
    ./network-handlers.nix
    ./initrd-handoff-plan.nix
    ./verity-root.nix
    ./journald-policy.nix
    ./crash-dump-policy.nix
    ./pam-policy.nix
    ./platform/users.nix
  ];
  aos.abilities = {
    serviceManagement.operations.realize.handler = {inherit program;};
    device.operations.present.handler = {inherit program;};
  };
}
