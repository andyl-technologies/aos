##! Concrete immutable image builder selection for current system variants.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.systemd];

  aos.abilities.bindings."image-builder:systemd" = {
    request = "aos:image-builder";
    implementation = "systemd:image-builder";
    providerInstance = "systemd:image-builder-provider";
    slot = "image-builder";
  };
}
