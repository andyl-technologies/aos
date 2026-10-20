##! Extends the native ZFS dataset provider with confined state-root labels.
##!
##! Dataset creation, mount effects and storage policy remain package-owned.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.filesystems.zfs;
  confinedViews = config.aos.security.selinux.enable && config.aos.security.selinux.bootMode == "immutable-stage0" && config.aos.sandbox.policyAuthority.enable;
  hasExactRootContext = dataset: expected:
    lib.filter (option: lib.hasPrefix "rootcontext=" option) dataset.mountOptions
    == [expected]
    && !(lib.any (option: lib.hasPrefix "context=" option || lib.hasPrefix "fscontext=" option || lib.hasPrefix "defcontext=" option) dataset.mountOptions);
in {
  config = lib.mkIf (cfg.enable && cfg.systemState && confinedViews) {
    assertions = [
      {
        assertion =
          cfg.datasets.var.mountPoint
          == "/var"
          && cfg.datasets."var/lib".mountPoint == "/var/lib"
          && hasExactRootContext cfg.datasets.var "rootcontext=system_u:object_r:var_t"
          && hasExactRootContext cfg.datasets."var/lib" "rootcontext=system_u:object_r:var_lib_t";
        message = "Confined signer views require the declared ZFS /var and /var/lib mounted roots and exactly their image-owned SELinux root contexts; whole-filesystem label overrides are not supported.";
      }
    ];
    aos.filesystems.zfs.datasets = {
      # Pin mounted root types without relabeling existing dataset contents.
      var.mountOptions = lib.mkAfter ["rootcontext=system_u:object_r:var_t"];
      "var/lib".mountOptions = lib.mkAfter ["rootcontext=system_u:object_r:var_lib_t"];
    };
  };
}
