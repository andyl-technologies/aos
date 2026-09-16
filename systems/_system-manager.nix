##! Exact system-manager selection shared by current system variants.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.systemd];

  aos.abilities.instances."systemd:system-manager-provider".implementation =
    "systemd:system-manager";

  aos.abilities.bindings."system-manager:systemd" = {
    request = "system:manager";
    implementation = "systemd:system-manager";
    providerInstance = "systemd:system-manager-provider";
    slot = "system-manager";
  };
}
