##! Explicit service and security admission for server-role acceptance fixtures.
{pkgs, ...}: {
  # Workload acceptance keeps its allowances separate from the bootable base.
  aos.image.budgets = {
    maxRuntimeClosureMiB = 3072;
    maxDevelopmentPayloadMiB = 80;
  };

  aos.packages.chrony = {
    package = pkgs.chrony;
    bundle = true;
  };
  aos.packages.openssh = {
    package = pkgs.openssh;
    bundle = true;
  };
  aos.packages.audit = {
    package = pkgs.audit;
    bundle = true;
  };
  aos.packages.nftables = {
    package = pkgs.nftables;
    bundle = true;
  };
  aos.packages.aos-network-ruleset-provider = {
    package = pkgs.aos-network-ruleset-provider;
    enable = true;
  };
}
