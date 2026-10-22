##! Retains immutable-stage0 policy selection for native initrd configuration labeling.
{
  aos.security.selinux = {
    enable = true;
    bootMode = "immutable-stage0";
  };
}
