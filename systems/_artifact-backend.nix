##! Selects the native OCI artifact package for Linux image compositions.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.aos-oci-backend];
}
