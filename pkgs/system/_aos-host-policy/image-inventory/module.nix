##! Retains the authenticated image-owned managed-leaf inventory.
{package, ...}: {
  aos.configurationLower.baselineInventory = "${package}/managed-paths.json";
}
