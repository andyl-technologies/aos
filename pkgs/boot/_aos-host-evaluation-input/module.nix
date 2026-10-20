##! Binds initrd provisioning to the admitted host evaluation descriptor.
{package, ...}: {
  aos.storageProvisioning.evaluationContext = "${package}/evaluation.json";
}
