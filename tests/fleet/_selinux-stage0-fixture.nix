# Test-only low-level wiring for deliberately non-production stage-0 packages.
{
  lib,
  pkgs,
}: stage0: {
  # Runtime-negative fixtures must be able to embed malformed or mismatched
  # policy bytes. Keep that capability below the production SELinux module so
  # its final assertions remain fail-closed for every deployable composition.
  aos.boot.kernelParams = [
    "selinux=1"
    "security=selinux"
    "enforcing=1"
    "aos.selinux.root_handoff=1"
  ];
  aos.boot.initrd.stage0 = stage0;
  # Native initrd replay must label the writable /etc upper even when this
  # low-level fixture deliberately bypasses production stage-0 assertions.
  aos.activation.stages.initrd = import ../../modules/security/_selinux-initrd-configuration.nix {
    inherit lib;
    policy = pkgs.aos-selinux-production-policy;
  };
  aos.security.selinux._qualificationAdmissionRelease = true;
  aos.kernel._extraConfigFragments = [
    (builtins.readFile ../../pkgs/kernel/config/selinux-immutable.config)
  ];

  system.build.immutableSelinuxPolicy = pkgs.aos-selinux-production-policy;
  # Native activation resolves unit labels through this exact installed policy.
  environment.etc."selinux/config".text = ''
    SELINUX=enforcing
    SELINUXTYPE=aos
  '';
  environment.etc."selinux/aos".source = "${pkgs.aos-selinux-production-policy}/etc/selinux/aos";
  environment.etc."ld.so.preload" = {
    text = "";
    mode = "0644";
  };

  assertions = [
    {
      assertion = !builtins.isNull stage0;
      message = "the SELinux stage-0 test fixture requires a stage-0 package";
    }
    {
      assertion = lib.hasPrefix "/nix/store/" (toString stage0);
      message = "the SELinux stage-0 test fixture requires a store derivation";
    }
  ];
}
