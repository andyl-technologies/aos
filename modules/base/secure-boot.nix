##! modules/base/secure-boot.nix — UEFI Secure Boot signing + enrollment
##!
##! Declares `aos.boot.secureBoot`. When enabled it does two things:
##!
##!  1. Exposes the db signing key/cert that the image builder
##!     (`modules/image/_builder.nix`) reads to Authenticode-sign the UKI
##!     and sd-boot. Signing is OFF by default, so the base image stays
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
  ...
}: let
  cfg = config.aos.boot.secureBoot;

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
    CONFIG_MODULE_SIG_ALL=y
    CONFIG_MODULE_SIG_FORCE=y
    CONFIG_MODULE_SIG_SHA256=y
    CONFIG_MODULE_SIG_KEY="${toString cfg.lockdown.moduleSigningKey}"
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
  enrollScript = pkgs.writeShellScriptBin "aos-sb-enroll" ''
    set -eu
    export PATH=${pkgs.util-linux}/bin:${pkgs.coreutils}/bin:$PATH
    if [ ! -d /sys/firmware/efi/efivars ]; then
      echo "aos-sb-enroll: efivarfs not mounted — not a UEFI boot?" >&2
      exit 1
    fi
    uv=${pkgs.efitools}/bin/efi-updatevar
    "$uv" -f ${cfg.enrollAuthDir}/db.auth  db
    "$uv" -f ${cfg.enrollAuthDir}/KEK.auth KEK
    "$uv" -f ${cfg.enrollAuthDir}/PK.auth  PK
    echo "aos-sb-enroll: enrolled db, KEK, PK (now in User Mode)"
  '';
in {
  options.aos.boot.secureBoot = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Sign the UKI and sd-boot for UEFI Secure Boot and ship the
        guest-side enrollment tooling. Off by default: the reproducible
        base owns no signing key.
      '';
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
    };
  };

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.dbKey != null && cfg.dbCert != null;
          message = "aos.boot.secureBoot.enable requires dbKey and dbCert.";
        }
        {
          assertion = cfg.enrollAuthDir != null;
          message = "aos.boot.secureBoot.enable requires enrollAuthDir (db/KEK/PK .auth).";
        }
      ];

      environment.systemPackages = [pkgs.efitools enrollScript];
    })

    (lib.mkIf cfg.lockdown.enable {
      assertions = [
        {
          assertion = cfg.enable;
          message = "aos.boot.secureBoot.lockdown requires aos.boot.secureBoot.enable.";
        }
        {
          assertion = cfg.lockdown.moduleSigningKey != null;
          message = "aos.boot.secureBoot.lockdown requires lockdown.moduleSigningKey.";
        }
      ];

      # Swap in the lockdown kernel. The base sets system.build.kernel
      # with normal priority, so mkForce is required to replace it. The
      # initrd and UKI are built from this kernel's (signed) modules.
      system.build.kernel = lib.mkForce lockdownKernel;

      # Belt-and-suspenders cmdline: lockdown auto-engages under SB but
      # this pins the mode; module.sig_enforce reinforces MODULE_SIG_FORCE.
      aos.boot.kernelParams = [
        "lockdown=${cfg.lockdown.mode}"
        "module.sig_enforce=1"
      ];
    })
  ];
}
