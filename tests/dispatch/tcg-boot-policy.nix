##! Retains startup allowances for the native boot path under software emulation.
{lib, ...}: {
  aos.services =
    lib.genAttrs [
      "boot-preparations.aos-ability-initrd-controller"
      "boot-preparations.aos-ability-initrd-handoff-barrier"
      "boot-preparations.aos-ability-host-receiver"
    ] (_: {
      lifecycle.start_timeout_millis = lib.mkForce 300000;
      readiness.timeout_millis = lib.mkForce 300000;
    });
}
