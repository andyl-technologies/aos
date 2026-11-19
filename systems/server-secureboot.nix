##! systems/server-secureboot.nix — Secure Boot test fixture
##!
##! Identical to systems/server.nix but with Secure Boot signing turned
##! on, pointed at the throwaway `secure-boot-test-keys`. Its image's UKI
##! and sd-boot are db-signed, and it ships the guest-side enrollment
##! tooling (efitools + `aos-sb-enroll`). As a test fixture it re-bundles
##! the `aos-test-agent` package (the server profile keeps it out of the
##! production image, but the fleet harness needs it to drive image-boot
##! machines). Its authored policy enables the server role, so it also
##! bundles that role's chrony and OpenSSH packages, keeping the image
##! buildable as a standalone system. `tests/fleet/secure-boot.nix` boots
##! this image, enrolls keys, reboots into enforcing mode, and asserts SB
##! is active — then tampers the UKI and asserts the firmware refuses it.
##!
##! Auto-registers as `systems.server-secureboot`.
{
  config,
  lib,
  pkgs,
  packageModulesAvailable ? false,
  ...
}: {
  # The authored policy also enables the server role. Its services, such as
  # chrony, take their lifecycle from package modules that only the host stage
  # loads, so the image evaluation takes just the boot requirement. As in
  # systems/server-test.nix, the role's service packages are bundled so the
  # host stage has their modules.
  imports =
    [./server.nix ./_server-test-packages.nix]
    ++ lib.optionals (!packageModulesAvailable) [{aos.boot.secureBoot.enable = true;}];
  aos.activation.stages.host.configuration = [
    (builtins.path {
      path = ./_native-policy/secure-boot.nix;
      name = "aos-secure-boot-policy.nix";
    })
  ];
  aos.activation.stages.initrd.configuration = [
    (builtins.path {
      path = ./_native-policy/secure-boot.nix;
      name = "aos-secure-boot-policy.nix";
    })
  ];

  # Signed normal and A/B recovery UKIs must coexist with the inactive-copy
  # publication transaction. Keep this test fixture's larger firmware storage
  # contract scoped away from the production server image.
  aos.image.budgets = {
    maxFirmwarePartitionMiB =
      if pkgs.stdenv.hostPlatform.constraints.cpu == "aarch64"
      then 768
      else 544;
  };
  aos.image.allowTestArtifacts = true;

  # The server profile sets the test fixtures to `bundle = mkDefault false`
  # to keep them out of the production image. This is a test-only fixture
  # system, so re-bundle the guest agent: the fleet harness activates it on
  # image-boot machines, which requires the payload to be present in the image
  # (lib/testing/fleet.nix).
  aos.packages.aos-test-agent = {
    package = pkgs.aos-test-agent;
    bundle = lib.mkIf ((config.aos.boot.stage or "host") == "host") true;
  };

  # The authored secure-boot policy enables aos.roles.server in the image's own
  # host stage, and that role enables the chrony and SSH services. The role
  # only names them in aos.apm.desiredPackages, which the on-host evaluator
  # resolves from a registry; image assembly never resolves that list, so the
  # build-time host evaluation must already carry the service packages or the
  # enabled services have no package-owned lifecycle. Bundle exactly the role's
  # requirements, the same payload that _server-test-packages.nix supplies to
  # the fleet tests that compose this fixture.
  aos.packages.chrony = {
    package = pkgs.chrony;
    bundle = true;
  };
  aos.packages.openssh = {
    package = pkgs.openssh.server;
    bundle = true;
  };

  aos.boot.secureBoot = {
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
