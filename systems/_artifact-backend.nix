##! Admit image-builder contracts without installing their build-only payload.
{pkgs, ...}: {
  aos.packages.aos-oci-backend = {
    package = pkgs.aos-oci-backend;
    enable = true;
  };
}
