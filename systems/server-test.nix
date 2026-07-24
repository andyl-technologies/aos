##! systems/server-test.nix — Server image with fleet-test affordances.
##!
##! systems/server.nix is the production image and is deliberately slim: the
##! guest test agent is not baked in, and the diagnostic / registry-workflow
##! CLI tools are kept off the system PATH (the image-slimming work — see
##! modules/profiles/server.nix and modules/base/build.nix). Fleet tests boot
##! THIS variant instead of re-adding those affordances in every suite:
##!
##!   - bundles the `aos-test-agent` package, so the fleet harness can drive
##!     non-baked image machines, whose agent arrives via the bundled package
##!     rather than a baked /var seed
##!     (lib/testing/fleet.nix);
##!   - puts the CLI tools fleet test scripts invoke by bare name back on
##!     PATH — git/sqlite/socat to hand-seed a registry, curl/jq to probe
##!     HTTP and parse JSON, nft to inspect the firewall ruleset.
##!
##! Suites layer their per-test fixture packages (aos-registry-server,
##! test-http-server, …) on top via `mkSystem [ ./server-test.nix { … } ]`.
##! Production images never import this, so they stay slim.
##!
##! Auto-registers as systems.server-test.
{pkgs, ...}: {
  imports = [./server.nix];

  # Runtime policy is deliberately absent from the production golden image.
  # This fixture opts into a server role and local recovery console just as a
  # test host.nix would.
  aos.roles.server.enable = true;
  aos.profiles.debug = {
    enable = true;
    autologin = true;
  };

  # Preserve the production EROFS format and all boot semantics while avoiding
  # zstd-19 recompression on every iterative fleet-test image rebuild.
  aos.image.erofsCompressionLevel = 1;

  # Guest agent for image machines (baked machines also get it from
  # their /var seed; the extra bundled copy is inert there). See
  # lib/testing/fleet.nix `mkMachinesWithIndex`. Bundling this exposed package
  # is safe on TPM-less test machines because aos-attest.service skips cleanly
  # without a TPM (modules/base/apm.nix) rather than failing the reconcile.
  aos.packages.aos-test-agent.bundle = true;

  # CLI tools fleet scripts run in-guest by bare name; image slimming dropped
  # these from the server profile's PATH.
  environment.systemPackages = [
    pkgs.curl
    pkgs.git
    pkgs.jq
    pkgs.nftables
    pkgs.socat
    pkgs.sqlite
  ];
}
