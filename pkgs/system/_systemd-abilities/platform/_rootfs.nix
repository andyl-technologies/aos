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
}: let
  config = system.config;
  sb = config.aos.boot.secureBoot;
  externalFinalization = sb.externalFinalization.enable;
  localSecureBootSigning = sb.enable && !externalFinalization;
  dbCertificate = sb._effectiveDbCert;
  verityEnabled = config.aos.security.verity.enable;

  activeRegistryDbCerts = lib.concatLists (
    map
    (registry: registry.sbDbCerts)
    (builtins.attrValues config.aos.apm.registries)
  );
  activeRegistryDbCertFiles =
    lib.imap
    (index: certificate:
      pkgs.writeTextFile {
        name = "aos-recovery-active-db-${toString index}";
        destination = "/certificate.pem";
        text = certificate;
      })
    activeRegistryDbCerts;
  activeImageDbCerts =
    if sb.enable
    then
      pkgs.mkDerivation {
        pname = "aos-recovery-active-db-certs";
        version = "1";
        src = null;
        buildDeps = [pkgs.coreutils];
        runtimeDeps = [];
        propagatedDeps = [];
        phases = [
          {
            name = "install";
            script = ''
              mkdir -p $out
              cp ${dbCertificate} $out/active-db-certs.pem
              chmod u+w $out/active-db-certs.pem
              ${lib.concatMapStringsSep "\n" (certificate: ''
                  printf '\n' >> $out/active-db-certs.pem
                  cat ${certificate}/certificate.pem >> $out/active-db-certs.pem
                '')
                activeRegistryDbCertFiles}
            '';
          }
        ];
      }
    else null;

  rootfs = import ./_rootfs-builder.nix ({
      inherit pkgs lib system kernel managerConfiguration managerRootfsPlan closureInfoFor;
      pname = "aos-image-${name}-rootfs";
      label = "aos-root";
      fsType = config.aos.filesystems.rootFsType;
      erofsCompressionLevel = config.aos.image.erofsCompressionLevel;
      extraClosures = config.aos.image.hostConfigClosures;
      kernelModulePackages = config.aos.kernel.modulePackages;
      firmwarePackages = config.aos.kernel.firmwarePackages;
      postPopulate = ''
        ${lib.optionalString config.aos.boot.initrd.abilityHandoff.enable ''
          mkdir -p rootfs/usr/lib/aos/initrd
          cp ${config.system.build.initrdStaticAbilityContract}/contract.json \
            rootfs/usr/lib/aos/initrd/static-ability-contract.json
          chmod 0444 rootfs/usr/lib/aos/initrd/static-ability-contract.json
          cp ${config.system.build.initrdSourceStageBundle} \
            rootfs/usr/lib/aos/initrd/source-stage-bundle.json
          chmod 0444 rootfs/usr/lib/aos/initrd/source-stage-bundle.json
        ''}

        ${lib.optionalString sb.enable ''
          mkdir -p rootfs/usr/lib/aos/image-trust
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
