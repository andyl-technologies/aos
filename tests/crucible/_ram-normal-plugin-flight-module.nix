# Uses the original plugin flight's requested six-CPU service envelope.
{
  lib,
  normalServiceFixtureInputs,
  ...
}: {
  imports = [./_ram-normal-service-module.nix];
  aos.crucibleCampaign = {
    package = normalServiceFixtureInputs.flightSuite;
    processResources = {
      # This is a separate explicit Main policy. The normal RAM gate and the
      # original plugin guest/request vectors retain their existing limits.
      memoryMaxBytes = lib.mkForce 8589934592;
      metadataBytes = lib.mkForce 2147483648;
      tasksMax = lib.mkForce 1024;
      fileDescriptors = lib.mkForce 16384;
      cpuQuotaPercent = lib.mkForce 600;
      runtimeSeconds = lib.mkForce 1800;
    };
  };
}
