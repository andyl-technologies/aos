##! Retains the prior authored payload used to qualify an actual native update.
{lib, ...}: {
  aos.nativeKubernetesQualification = {
    message = lib.mkForce "predecessor";
    label = lib.mkForce "predecessor";
  };
}
