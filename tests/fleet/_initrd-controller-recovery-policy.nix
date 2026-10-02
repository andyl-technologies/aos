##! Restarts the original durable initrd transaction after observer interruption.
{lib, ...}: {
  aos.services."boot-preparations.aos-ability-initrd-controller" = {
    lifecycle.restart = lib.mkForce "on-failure";
    # Append beside package declarations instead of the operator override band.
    dependencies = {
      requires = lib.mkOverride 100 (lib.mkAfter ["aos-ability-initrd-interruption-observer.service"]);
      after = lib.mkOverride 100 (lib.mkAfter ["aos-ability-initrd-interruption-observer.service"]);
    };
  };
}
