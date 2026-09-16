##! modules/base/config-seed.nix — on-host configuration files backend
##!
##! The initrd files backend for on-host configuration. The neutral `/etc` overlay
##! composes a per-generation lower at `/run/etc/config-<gen>/etc`. On reboot
##! this unit validates and mounts the committed generation's retained EROFS
##! artifact before the overlay is mounted. The materializer emits only
##! host/package-owned deltas; image-owned `@base` files come from the immutable
##! running image lower.
##! Gen-0 (or a legacy generation with no manifest) remains an empty fallback.
##!
##! The selected `aos-boot-preparations` package owns both initrd service
##! declarations. This image module only selects the package into the initrd
##! fixed point and retains its runtime closure before switch-root.
{pkgs, ...}: {
  config = {
    # Keep the materializer's complete runtime closure in stage 1 explicitly.
    # Rendered unit scripts are also part of the initrd closure graph, but this
    # declaration makes the backend self-contained if unit materialization is
    # refactored independently of the initrd package set.
    aos.boot.initrd.packageRoots = [pkgs.aos-boot-preparations];
  };
}
