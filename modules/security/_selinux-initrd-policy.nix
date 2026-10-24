##! Retains immutable-stage0 policy selection for native initrd configuration labeling.
{
  aos.security.selinux = {
    enable = true;
    bootMode = "immutable-stage0";
    policy = "aos";
  };

  # libselinux also requires this file to report SELinux as enabled. Without
  # it, libmount silently drops rootcontext even after stage 0 loads policy.
  aos.abilities.configuration.operations.file.effects.selinux-initrd-config.input = {
    path = "/etc/selinux/config";
    mode = "0444";
    content = "SELINUX=enforcing\nSELINUXTYPE=aos\n";
  };
}
