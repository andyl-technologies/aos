##! Shared full-host image budgets for server and edge variants.
{lib, ...}: {
  # OCI images use a separate package slice and closure budget.
  aos.image.budgets.maxRootMiB = lib.mkDefault 960;
  aos.image.budgets.maxRuntimeClosureMiB = lib.mkDefault 2560;
  aos.image.budgets.maxDevelopmentPayloadMiB = lib.mkDefault 80;
  aos.image.budgets.maxDownloadMiB = lib.mkDefault 1280;
}
