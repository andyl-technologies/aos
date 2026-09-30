##! Selects the retained storage domain for image and initrd evaluation.
{pkgs, ...}: {
  environment.systemPackages = [pkgs.storage-interface];
  aos.boot.initrd.packageRoots = [pkgs.storage-interface];
}
