##! Portable SELinux policy selection shared by mutable and immutable providers.
{lib, ...}: {
  options.aos.security.selinux = {
    enable = (lib.mkEnableOption "SELinux mandatory access control") // {extensible = true;};
    mode = lib.mkOption {
      type = lib.types.enum ["enforcing" "permissive" "disabled"];
      default = "enforcing";
      description = "SELinux operating mode.";
    };
    policy = lib.mkOption {
      type = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9._-]*";
      default = "refpolicy";
      description = "SELinux policy store name to load.";
    };
    autorelabel = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Relabel the root filesystem when /.autorelabel exists.";
    };
    bootMode = lib.mkOption {
      type = lib.types.enum [
        "legacy"
        "immutable-stage0"
      ];
      default = "legacy";
      description = ''
        Policy admission path. Legacy compiles a mutable module store after
        local filesystems mount. Immutable-stage0 loads the kernel-matched
        policy from a signed static PID 1 before labeled stage-1 systemd.
      '';
    };
  };
}
