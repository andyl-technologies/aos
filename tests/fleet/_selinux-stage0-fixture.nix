# Test-only low-level wiring for deliberately non-production stage-0 packages.
{lib, pkgs}: stage0: {
  # Runtime-negative fixtures must be able to embed malformed or mismatched
  # policy bytes. Keep that capability below the production SELinux module so
  # its final assertions remain fail-closed for every deployable composition.
  aos.boot.kernelParams = [
    "selinux=1"
    "security=selinux"
    "enforcing=1"
    "aos.selinux.root_handoff=1"
    "rootflags=nodev"
  ];
  aos.boot.initrd.stage0 = stage0;
  aos.security.selinux._qualificationAdmissionRelease = true;
  aos.kernel._extraConfigFragments = [
    (builtins.readFile ../../pkgs/kernel/config/selinux-immutable.config)
  ];

  system.build.immutableSelinuxPolicy = pkgs.aos-selinux-production-policy;
  environment.etc."selinux/aos".source =
    "${pkgs.aos-selinux-production-policy}/etc/selinux/aos";
  environment.etc."ld.so.preload".text = "";

  assertions = [
    {
      assertion = stage0 != null;
      message = "the SELinux stage-0 test fixture requires a stage-0 package";
    }
    {
      assertion = lib.hasPrefix "/nix/store/" (toString stage0);
      message = "the SELinux stage-0 test fixture requires a store derivation";
    }
  ];
}
