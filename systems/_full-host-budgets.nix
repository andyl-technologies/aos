##! Bounded bootable-base image budgets for server and edge variants.
{lib, ...}: {
  # OCI images use a separate package slice and closure budget.
  aos.image.budgets.maxRootMiB = lib.mkDefault 960;
  # The source-built minimal base measures 1516 MiB including native initrd
  # and qualification companions. Workload fixtures set their own allowances.
  aos.image.budgets.maxRuntimeClosureMiB = lib.mkDefault 1792;
  aos.image.budgets.maxDevelopmentPayloadMiB = lib.mkDefault 48;
  aos.image.budgets.maxDownloadMiB = lib.mkDefault 1280;
}
