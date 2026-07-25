##! systems/server-secureboot.nix — Secure Boot test fixture (RFC-0006)
##!
##! Identical to systems/server.nix but with Secure Boot signing turned
##! on, pointed at the throwaway `secure-boot-test-keys`. Its image's UKI
##! and sd-boot are db-signed, and it ships the guest-side enrollment
##! tooling (efitools + `aos-sb-enroll`). As a test fixture it re-bundles
##! the `aos-test-agent` package (the server profile keeps it out of the
##! production image, but the fleet harness needs it to drive image-boot
##! machines); `tests/fleet/secure-boot.nix` boots this image, enrolls
##! keys, reboots into enforcing mode, and asserts SB is active — then
##! tampers the UKI and asserts the firmware refuses it.
##!
##! Auto-registers as `systems.server-secureboot`.
{
  lib,
  pkgs,
  ...
}: {
  imports = [./server.nix];

  # This is a test fixture, not the universal production image.
  aos.roles.server.enable = true;

  # Keep secure/measured-boot VM iteration practical. Production server images
  # retain the module default (zstd-19); this throwaway-key fixture trades only
  # test artifact size for substantially faster compression.
  aos.image.erofsCompressionLevel = 1;

  # The server profile sets the test fixtures to `bundle = mkDefault false`
  # to keep them out of the production image. This is a test-only fixture
  # system, so re-bundle the guest agent: the fleet harness activates it on
  # image-boot machines, which requires the payload to be present in the image
  # (lib/testing/fleet.nix).
  aos.packages.aos-test-agent.bundle = true;

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
