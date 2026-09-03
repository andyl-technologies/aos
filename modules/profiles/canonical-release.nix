##! Canonical production release image profile
##!
##! Activates the fail-closed, public-only Nix half of production image
##! publication. A deployment overlay supplies public certificates and
##! authenticated-variable blobs. Private keys are deliberately not options of
##! this profile and every signing operation happens in the release finalizer.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.profiles.canonicalRelease;
  authorities = cfg.publicAuthorities;
  sourceEvaluation = !(config.aos.config.frozenArtifacts ? "secure-boot-db-public");
in {
  options.aos.profiles.canonicalRelease = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Emit public-only unsigned image assemblies for canonical production
        publication. This profile fails evaluation until every public trust
        input is supplied by a deployment overlay.
      '';
    };

    publicAuthorities = {
      secureBootCertificate = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Public Secure Boot db certificate path.";
      };

      moduleSigningCertificate = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Public X.509 certificate embedded for kernel module verification.";
      };

      pcrPolicyKey = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Public key used to verify signed PCR policies.";
      };

      firmwareEnrollment = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Public-only directory containing db.auth, KEK.auth, and PK.auth.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = !sourceEvaluation || authorities.secureBootCertificate != null;
        message = "canonical release images require a public Secure Boot certificate.";
      }
      {
        assertion = !sourceEvaluation || authorities.moduleSigningCertificate != null;
        message = "canonical release images require a public module-signing certificate.";
      }
      {
        assertion = !sourceEvaluation || authorities.pcrPolicyKey != null;
        message = "canonical release images require a public PCR-policy key.";
      }
      {
        assertion = !sourceEvaluation || authorities.firmwareEnrollment != null;
        message = "canonical release images require public firmware enrollment artifacts.";
      }
      {
        assertion = !config.aos.security.selinux.enable;
        message = "canonical release images currently exclude SELinux until the immutable root is labeled and qualified.";
      }
      {
        assertion =
          config.aos.boot.secureBoot.externalFinalization.secureBootRole
          != config.aos.boot.secureBoot.externalFinalization.moduleRole
          && config.aos.boot.secureBoot.externalFinalization.secureBootRole
          != config.aos.boot.secureBoot.externalFinalization.pcrRole
          && config.aos.boot.secureBoot.externalFinalization.moduleRole
          != config.aos.boot.secureBoot.externalFinalization.pcrRole;
        message = "canonical release image signing roles must remain distinct.";
      }
    ];

    aos.image = {
      enable = true;
      allowTestArtifacts = false;
    };
    aos.security.verity.enable = true;
    # The current refpolicy boots an unlabeled immutable root and is not a
    # production MAC boundary. Keep the public claim explicitly false until a
    # labeled-root image and enforcing qualification gate replace this line.
    aos.security.level = "hardened";
    aos.security.selinux.enable = false;
    aos.boot.recovery.enable = true;
    aos.boot.secureBoot = {
      enable = true;
      dbCert = authorities.secureBootCertificate;
      enrollAuthDir = authorities.firmwareEnrollment;
      externalFinalization.enable = true;
      lockdown = {
        enable = true;
        moduleSigningCert = authorities.moduleSigningCertificate;
      };
      measuredBoot = {
        enable = true;
        pcrPublicKey = authorities.pcrPolicyKey;
      };
    };
  };
}
