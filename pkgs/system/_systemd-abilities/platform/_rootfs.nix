##! Selected platform immutable root filesystem policy.
##!
##! Owns the AOS root layout, trusted image inputs, and concrete filesystem
##! policy used by this image provider.
{
  pkgs,
  lib,
  system,
  name,
  kernel,
  managerConfiguration,
  managerRootfsPlan,
  closureInfoFor,
  runtimeClosureAudit,
}: let
  config = system.config;
  sb = config.aos.boot.secureBoot;
  externalFinalization = sb.externalFinalization.enable;
  localSecureBootSigning = sb.enable && !externalFinalization;
  dbCertificate = sb._effectiveDbCert;
  verityEnabled = config.aos.security.verity.enable;

  activeImageDbCerts = import ./_active-db-certs.nix {inherit pkgs lib config;};

  rootfs = import ./_rootfs-builder.nix ({
      inherit pkgs lib system kernel managerConfiguration managerRootfsPlan closureInfoFor runtimeClosureAudit;
      pname = "aos-image-${name}-rootfs";
      label = "aos-root";
      fsType = config.aos.filesystems.rootFsType;
      erofsCompressionLevel = config.aos.image.erofsCompressionLevel;
      extraClosures = config.aos.image.hostConfigClosures;
      # The toplevel already retains these roots; export their commands into
      # the immutable /usr tree used by boot guards and the system profile.
      symlinkFarmPkgs = config.environment.systemPackages;
      kernelModulePackages = config.aos.kernel.modulePackages;
      firmwarePackages = lib.optionals config.aos.kernel.includeFirmware config.aos.kernel.firmwarePackages;
      postPopulate = ''
        ${lib.optionalString sb.enable ''
          mkdir -p rootfs/usr/lib/aos/image-trust
          cp ${dbCertificate} rootfs/usr/lib/aos/image-trust/boot-db.crt
          cp ${activeImageDbCerts}/active-db-certs.pem \
            rootfs/usr/lib/aos/image-trust/active-db-certs.pem
        ''}
        ${lib.optionalString (config.aos.apm.drainScript != null) ''
          mkdir -p rootfs/usr/lib/aos
          cp ${config.aos.apm.drainScript} rootfs/usr/lib/aos/drain
          chmod 0555 rootfs/usr/lib/aos/drain
        ''}
        ${lib.optionalString (config.aos.apm.healthScript != null) ''
          cp ${config.aos.apm.healthScript} rootfs/usr/lib/aos/health
          chmod 0555 rootfs/usr/lib/aos/health
        ''}
      '';
      shrinkToFit = true;
      headroomMiB = 64;
    }
    // lib.optionalAttrs verityEnabled {
      verity = true;
      secureBootKey =
        if localSecureBootSigning
        then sb.dbKey
        else null;
      secureBootCert =
        if sb.enable
        then dbCertificate
        else null;
    });
in {
  inherit activeImageDbCerts rootfs;
}
