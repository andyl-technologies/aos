##! systems/server-secureboot.nix — Secure Boot test fixture (RFC-0006)
##!
##! Identical to systems/server.nix but with Secure Boot signing turned
##! on, pointed at the throwaway `secure-boot-test-keys`. Its image's UKI
##! and sd-boot are db-signed, and it ships the guest-side enrollment
##! tooling (efitools + `aos-sb-enroll`). The server profile already
##! bundles the `aos-test-agent` role (so the fleet harness can drive
##! it); `tests/fleet/secure-boot.nix` boots this image, enrolls keys,
##! reboots into enforcing mode, and asserts SB is active — then tampers
##! the UKI and asserts the firmware refuses it.
##!
##! Auto-registers as `systems.server-secureboot`.
{
  lib,
  pkgs,
  ...
}: {
  imports = [./server.nix];

  aos.boot.secureBoot = {
    enable = true;
    # TEST keys only — see pkgs/boot/secure-boot-test-keys.nix. db.key
    # signs the UKI + sd-boot; the .auth blobs are enrolled guest-side.
    # (For a test fixture it is acceptable that the keygen closure — incl.
    # db.key — reaches the image; a production deployment points dbKey at
    # an offline key reference and enrollAuthDir at public-only blobs.)
    dbKey = "${pkgs.secure-boot-test-keys}/db.key";
    dbCert = "${pkgs.secure-boot-test-keys}/db.crt";
    enrollAuthDir = "${pkgs.secure-boot-test-keys}";
  };
}
