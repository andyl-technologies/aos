##! modules/base/secure-boot.nix — UEFI Secure Boot signing + enrollment
##!
##! Declares `aos.boot.secureBoot`. When enabled it does two things:
##!
##!  1. Exposes the db signing key/cert that the selected package image
##!     builder reads to sign its boot artifacts. Signing is OFF by default,
##!     so the base image stays
##!     byte-reproducible and carries no key — SB material is a
##!     deployment overlay (RFC-0006 key-custody.md).
##!
##!  2. Installs the guest-side enrollment path: efitools plus an
##!     `aos-sb-enroll` command that writes the db → KEK → PK
##!     authenticated variables through efivarfs. Setting PK takes the
##!     firmware out of Setup Mode into User (enforcing) mode. This is
##!     the same first-boot enrollment hook a bare-metal deployment uses;
##!     the secure-boot CI test drives it explicitly.
##!
##! The key/cert and the enrollment `.auth` blobs come from a key
##! hierarchy the deployment owns; the CI test points them at the
##! throwaway `pkgs.secure-boot-test-keys`.
{
  config,
  lib,
  pkgs,
  packageModulesAvailable ? false,
  ...
}: let
  cfg = config.aos.boot.secureBoot;
  externalFinalization = cfg.externalFinalization.enable;
  frozenArtifacts = config.aos.config.frozenArtifacts;
  configArtifacts = config.aos.config.artifacts;
  copyPublicFile = name: source: destination:
    pkgs.mkDerivation {
      pname = "aos-public-${name}";
      version = "1";
      src = null;
      buildDeps = [pkgs.coreutils];
      runtimeDeps = [];
      propagatedDeps = [];
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            cp ${source} "$out/${destination}"
            chmod 0444 "$out/${destination}"
          '';
        }
      ];
      meta.description = "Public-only ${name} authority";
    };
  dbCertificateSource = copyPublicFile "secure-boot-certificate" cfg.dbCert "certificate.pem";
  moduleCertificateSource = copyPublicFile "module-signing-certificate" cfg.lockdown.moduleSigningCert "certificate.pem";
  enrollmentSource = pkgs.mkDerivation {
    pname = "aos-public-firmware-enrollment";
    version = "1";
    src = null;
    buildDeps = [pkgs.coreutils];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          for file in db.auth KEK.auth PK.auth; do
            cp ${cfg.enrollAuthDir}/"$file" "$out/$file"
            chmod 0444 "$out/$file"
          done
        '';
      }
    ];
    meta.description = "Public-only UEFI authenticated-variable enrollment set";
  };
  enrollAuthDir =
    if cfg._effectiveEnrollAuthDir == null
    then "/nonexistent/aos-secure-boot-auth"
    else cfg._effectiveEnrollAuthDir;

  # Lockdown deployment kernel (phase 2). The reproducible base kernel
  # deliberately omits lockdown + module signing (they require a
  # non-public key — pkgs/kernel/config/security.config). Here we build
  # a deployment variant via the kernel's extraConfig hook: lockdown LSM
  # (auto-engaged under SB via LOCK_DOWN_IN_EFI_SECURE_BOOT), enforced
  # module signing with the deployment key, and signed-kexec so the apm
  # kernel hot-reload path keeps working under lockdown. The store-path
  # in CONFIG_MODULE_SIG_KEY carries string context, so the key
  # derivation becomes a build input automatically.
  # pkgs.linuxWith (not pkgs.linux.override) — extraConfig is a linux.nix
  # function arg the inherited override can't reach (see pkgs/default.nix).
  lockdownKernel = pkgs.linuxWith ''
    CONFIG_SECURITY_LOCKDOWN_LSM=y
    CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
    CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT=y
    CONFIG_MODULE_SIG=y
    CONFIG_MODULE_SIG_ALL=${
      if externalFinalization
      then "n"
      else "y"
    }
    CONFIG_MODULE_SIG_FORCE=y
    CONFIG_MODULE_SIG_SHA256=y
    ${
      if externalFinalization
      then ''
        CONFIG_MODULE_SIG_KEY=""
        CONFIG_SYSTEM_TRUSTED_KEYS="${toString cfg.lockdown._effectiveModuleSigningCert}"
      ''
      else ''
        CONFIG_MODULE_SIG_KEY="${toString cfg.lockdown.moduleSigningKey}"
      ''
    }
    CONFIG_KEXEC_FILE=y
    CONFIG_KEXEC_SIG=y
    CONFIG_KEXEC_SIG_FORCE=y
    CONFIG_KEXEC_BZIMAGE_VERIFY_SIG=y
  '';

  # Enrollment order is load-bearing: db and KEK first (still in Setup
  # Mode), then PK last — writing PK transitions to User Mode and SB
  # begins enforcing. efi-updatevar shells out to `mount -l` to locate
  # efivarfs, so util-linux must be on PATH; other paths are baked as
  # absolute store paths.
  enrollScript = config.aos.config.artifacts.secure-boot-enroll;
  enrollScriptSource = pkgs.writeShellScriptBin "aos-sb-enroll" ''
    set -eu
    export PATH=${pkgs.util-linux}/bin:${pkgs.coreutils}/bin:$PATH
    if [ ! -d /sys/firmware/efi/efivars ]; then
      echo "aos-sb-enroll: efivarfs not mounted — not a UEFI boot?" >&2
      exit 1
    fi
    uv=${pkgs.efitools}/bin/efi-updatevar
    "$uv" -f ${enrollAuthDir}/db.auth  db
    "$uv" -f ${enrollAuthDir}/KEK.auth KEK
    "$uv" -f ${enrollAuthDir}/PK.auth  PK
    echo "aos-sb-enroll: enrolled db, KEK, PK (now in User Mode)"
  '';

  # The PCR-policy public key must live inside the initrd: first-boot
  # sealing of /var reads it pre-switch-root. The initrd copies a fixed
  # package set, not the whole toplevel closure, so the measured-boot branch
  # retains a normal native artifact with a checked-in module. Re-evaluation
  # receives this same public-only artifact rather than a derivation builder.
  pcrKeyForInitrd = pkgs.mkDerivation {
    pname = "aos-pcr-pubkey";
    version = "1";
    module = ../../pkgs/boot/_aos-boot-storage/pcr-policy-key;
    moduleDeps = [pkgs.aos-boot-storage];
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp ${toString cfg.measuredBoot.pcrPublicKey} "$out/pcr.pem"
        '';
      }
    ];
  };
  retainPcrPolicy = _: {
    packages = [pcrKeyForInitrd];
    configuration = [];
  };
in {
  imports = lib.optionals (!packageModulesAvailable) [../../pkgs/boot/_aos-boot-storage/measurement-options.nix];
  options.aos.boot.secureBoot = {
    externalFinalization = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Build an unsigned release assembly and require the release
          coordinator to obtain all private-key operations from external
          role-bound signers. No private signing key may enter the Nix store
          when this mode is enabled.
        '';
      };

      secureBootRole = lib.mkOption {
        type = lib.types.nonEmptyStr;
        default = "secure-boot-release";
        description = "External signer role authorized for PE/COFF artifacts.";
      };

      moduleRole = lib.mkOption {
        type = lib.types.nonEmptyStr;
        default = "kernel-module-release";
        description = "External signer role authorized for kernel modules.";
      };

      pcrRole = lib.mkOption {
        type = lib.types.nonEmptyStr;
        default = "pcr-policy-release";
        description = "External signer role authorized for PCR policies.";
      };
    };

    dbKey = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Path to the db private key (PEM) used to sign the UKI and
        sd-boot. In production this is a key reference held offline; the
        value must resolve at image-build time.
      '';
    };

    dbCert = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Path to the db certificate (PEM); required with dbKey.";
    };

    _effectiveDbCert = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      readOnly = true;
      internal = true;
      description = "Public-only Secure Boot certificate retained by the image.";
    };

    enrollAuthDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Directory containing the signed authenticated-variable blobs
        `db.auth`, `KEK.auth`, `PK.auth` that `aos-sb-enroll` writes via
        efivarfs. These are public material (no private keys); point a
        production deployment at a public-only directory.
      '';
    };

    _effectiveEnrollAuthDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      readOnly = true;
      internal = true;
      description = "Public-only firmware enrollment artifact retained by the image.";
    };

    lockdown = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Build and boot a lockdown deployment kernel: lockdown LSM +
          enforced module signing + signed kexec. Requires
          `aos.boot.secureBoot.enable` (lockdown is only meaningful once
          the firmware enforces SB; it auto-engages under SB via
          LOCK_DOWN_IN_EFI_SECURE_BOOT). Closes the gap a signed-but-not-
          locked kernel leaves open — loading unsigned modules,
          /dev/mem, kexec of an unsigned image (RFC-0006 phase 2).
        '';
      };

      mode = lib.mkOption {
        type = lib.types.enum ["integrity" "confidentiality"];
        default = "confidentiality";
        description = ''
          Lockdown mode passed on the kernel cmdline. `confidentiality`
          is stricter (also blocks reads that could leak kernel memory);
          `integrity` blocks only writes that could alter the running
          kernel. Under SB the LSM defaults to integrity; this can raise
          it.
        '';
      };

      moduleSigningKey = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Path to a combined PEM (private key + X.509 cert) for
          CONFIG_MODULE_SIG_KEY. A deployment-owned key, distinct from
          the UEFI db key. The kernel embeds the cert and signs its
          modules with this at build time.
        '';
      };

      moduleSigningCert = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Public X.509 certificate embedded in an external-finalization
          lockdown kernel. The release finalizer signs every shipped module
          with the corresponding external role before image assembly.
        '';
      };

      _effectiveModuleSigningCert = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        readOnly = true;
        internal = true;
        description = "Public-only module certificate retained by the image.";
      };
    };

    measuredBoot = {
      pcrPrivateKey = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Path to the PCR-policy private key (PEM). ukify signs the UKI's
          PCR policy with it at build time. A release-time offline key,
          distinct from the db key and the module-signing key.
        '';
      };
    };
  };

  config = lib.mkMerge [
    {
      # This command is image-fixed. Preserve its stage-1 store path in the
      # base library so a stage-2 evaluation never calls a builder that is
      # intentionally absent from the frozen package set.
      aos.config._artifactSources.secure-boot-enroll =
        if config.aos.config.frozenArtifacts ? "secure-boot-enroll"
        then null
        else enrollScriptSource;
    }

    (lib.mkIf cfg.enable {
      aos.config._artifactSources = lib.mkIf externalFinalization {
        secure-boot-db-public =
          if frozenArtifacts ? "secure-boot-db-public"
          then null
          else dbCertificateSource;
        secure-boot-enrollment-public =
          if frozenArtifacts ? "secure-boot-enrollment-public"
          then null
          else enrollmentSource;
        module-signing-certificate-public =
          if frozenArtifacts ? "module-signing-certificate-public"
          then null
          else moduleCertificateSource;
      };
      aos.boot.secureBoot = {
        _effectiveDbCert =
          if externalFinalization
          then "${configArtifacts.secure-boot-db-public}/certificate.pem"
          else cfg.dbCert;
        _effectiveEnrollAuthDir =
          if externalFinalization
          then "${configArtifacts.secure-boot-enrollment-public}"
          else cfg.enrollAuthDir;
        lockdown._effectiveModuleSigningCert =
          if externalFinalization
          then "${configArtifacts.module-signing-certificate-public}/certificate.pem"
          else cfg.lockdown.moduleSigningCert;
      };
      assertions = [
        {
          assertion = cfg.dbCert != null;
          message = "aos.boot.secureBoot.enable requires dbCert.";
        }
        {
          assertion = externalFinalization || cfg.dbKey != null;
          message = "local Secure Boot finalization requires dbKey.";
        }
        {
          assertion = !externalFinalization || cfg.dbKey == null;
          message = "external Secure Boot finalization forbids dbKey in the Nix evaluation.";
        }
        {
          assertion =
            !externalFinalization
            || (cfg.lockdown.enable
              && cfg.measuredBoot.enable
              && config.aos.boot.recovery.enable
              && config.aos.security.verity.enable);
          message = "external image finalization requires lockdown, measured boot, recovery, and dm-verity.";
        }
        {
          assertion = cfg.enrollAuthDir != null;
          message = "aos.boot.secureBoot.enable requires enrollAuthDir (db/KEK/PK .auth).";
        }
      ];

      environment.systemPackages = [pkgs.efitools enrollScript];

      # Keep the public firmware db authority available to stage 2 through
      # /etc. The initrd recovery-retention check references cfg.dbCert
      # directly, which retains that immutable store object in the initrd
      # closure without creating a toplevel/initrd dependency cycle.
      environment.etc."aos/trust/secure-boot-db.crt".source = cfg._effectiveDbCert;

      # First-boot recovery seeding authenticates the ESP copy before it
      # records any retention evidence. The initrd copies an explicit package
      # closure, so the focused PE inspection and signature tools belong here.
      aos.boot.initrd.packageRoots = lib.mkIf config.aos.boot.recovery.enable [
        pkgs.pe-tools
        pkgs.sbsigntools
      ];
    })

    (lib.mkIf cfg.lockdown.enable {
      assertions = [
        {
          assertion = cfg.enable;
          message = "aos.boot.secureBoot.lockdown requires aos.boot.secureBoot.enable.";
        }
        {
          assertion = externalFinalization || cfg.lockdown.moduleSigningKey != null;
          message = "local lockdown builds require lockdown.moduleSigningKey.";
        }
        {
          assertion = !externalFinalization || cfg.lockdown.moduleSigningKey == null;
          message = "external lockdown finalization forbids lockdown.moduleSigningKey.";
        }
        {
          assertion = !externalFinalization || cfg.lockdown.moduleSigningCert != null;
          message = "external lockdown finalization requires lockdown.moduleSigningCert.";
        }
      ];

      # Select the package variant through the same kernel-provider input as
      # every other system. Its native module then projects the exact artifact
      # into the checked ability fixed point used by the initrd and image.
      aos.kernel.packageRoot = lib.mkForce lockdownKernel;

      # Belt-and-suspenders cmdline: lockdown auto-engages under SB but
      # this pins the mode; module.sig_enforce reinforces MODULE_SIG_FORCE.
      aos.boot.kernelParams = [
        "lockdown=${cfg.lockdown.mode}"
        "module.sig_enforce=1"
      ];
    })

    (lib.mkIf cfg.measuredBoot.enable {
      aos.config._artifactSources.pcr-public-key = pcrKeyForInitrd;
      aos.activation.stages.host.configurationBuilders = [retainPcrPolicy];
      aos.activation.stages.initrd.configurationBuilders = [retainPcrPolicy];
      # Selection exposes the public path to image-only builders. Final stages
      # obtain the declaration solely from the selected native key module.
      aos.boot.secureBoot.measuredBoot._effectivePcrPublicKey = lib.mkIf (!packageModulesAvailable) "${pcrKeyForInitrd}/pcr.pem";

      assertions = [
        {
          assertion = cfg.enable;
          message = "aos.boot.secureBoot.measuredBoot requires aos.boot.secureBoot.enable.";
        }
        {
          assertion = cfg.measuredBoot.pcrPublicKey != null;
          message = "aos.boot.secureBoot.measuredBoot requires pcrPublicKey.";
        }
        {
          assertion = externalFinalization || cfg.measuredBoot.pcrPrivateKey != null;
          message = "local measured-boot finalization requires pcrPrivateKey.";
        }
        {
          assertion = !externalFinalization || cfg.measuredBoot.pcrPrivateKey == null;
          message = "external measured-boot finalization forbids pcrPrivateKey.";
        }
      ];

      # Ship the PCR public key into the initrd for first-boot sealing.
      aos.boot.initrd.nonPackageRuntimeArtifacts = [
        (builtins.toString pcrKeyForInitrd)
      ];
      environment.etc."aos/pcr-sign.pem".source = "${pcrKeyForInitrd}/pcr.pem";
    })
  ];
}
