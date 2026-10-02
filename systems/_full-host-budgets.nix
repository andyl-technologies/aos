##! Shared full-host image budgets for server and edge variants.
{lib, ...}: {
  # OCI images use a separate package slice and closure budget.
  aos.image.budgets.maxRootMiB = lib.mkDefault 960;
  # Current host payloads and retained qualification companions exceed 2643
  # MiB before the initrd; the activation fixture measures 2861 MiB in total.
  aos.image.budgets.maxRuntimeClosureMiB = lib.mkDefault 3072;
  aos.image.budgets.maxDevelopmentPayloadMiB = lib.mkDefault 80;
  aos.image.budgets.maxDownloadMiB = lib.mkDefault 1280;
}
