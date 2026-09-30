##! Restarts the original durable initrd transaction after observer interruption.
{lib, ...}: {
  aos.services."boot-preparations.aos-ability-initrd-controller".lifecycle.restart =
    lib.mkForce "on-failure";
}
