##! Restarts the original durable initrd transaction after observer interruption.
{lib, ...}: {
  # Keep dependent boot jobs waiting through this intentional interruption.
  boot.initrd.systemd.services.aos-ability-initrd-controller.serviceConfig.RestartMode = "direct";

  aos.services."boot-preparations.aos-ability-initrd-controller" = {
    lifecycle.restart = lib.mkForce "on-failure";
    # Append beside package declarations instead of the operator override band.
    dependencies = {
      requires = lib.mkOverride 100 (lib.mkAfter ["aos-ability-initrd-interruption-observer.service"]);
      after = lib.mkOverride 100 (lib.mkAfter ["aos-ability-initrd-interruption-observer.service"]);
    };
  };
}
