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
  enrollAuthDir =
    if cfg.enrollAuthDir == null
    then "/nonexistent/aos-secure-boot-auth"
    else cfg.enrollAuthDir;

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
  # registers a minimal image-fixed artifact and adds it via
  # aos.boot.initrd.extraPackages. The frozen artifact path keeps this module
  # evaluable on-host without exposing a derivation builder.
  pcrKeyForInitrd = config.aos.config.artifacts.pcr-public-key;
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

    measuredBoot = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Measure boot into the TPM and seal `/var` encryption to a
          *signed PCR policy* (RFC-0006 phase 3). The UKI gets a signed
          PCR policy (`.pcrsig`/`.pcrpkey`), and first boot LUKS2-formats
          `/var` and enrolls a TPM2 token sealed to that policy plus a
          recovery key. Because the seal tracks the policy key — not a
          fixed PCR hash — any db-signed UKI unseals `/var` across OTA
          upgrades, while a tampered/unsigned UKI or an SB-state change
          does not. Requires `aos.boot.secureBoot.enable`.
        '';
      };

      pcrPrivateKey = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Path to the PCR-policy private key (PEM). ukify signs the UKI's
          PCR policy with it at build time. A release-time offline key,
          distinct from the db key and the module-signing key.
        '';
      };

      pcrPublicKey = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = ''
          Path to the PCR-policy public key (PEM). Embedded in the UKI's
          `.pcrpkey` section and used by `systemd-cryptenroll
          --tpm2-public-key` to seal `/var`. Required with pcrPrivateKey.
        '';
      };

      signedPcrs = lib.mkOption {
        type = lib.types.str;
        default = "11";
        description = ''
          PCRs covered by the *signed* policy (flexible across UKIs that
          share the policy key). PCR 11 is the UKI/boot-phase measurement
          — the one that changes per UKI and that the signature blesses.
        '';
      };

      pinnedPcrs = lib.mkOption {
        type = lib.types.str;
        default = "7+12";
        description = ''
          PCRs bound by *value* (not the signature), in systemd's
          plus-separated PCR syntax. PCR 7 records Secure Boot state and PCR
          12 records boot inputs outside the embedded UKI command line.
          Changing either denies unattended `/var` unlock and requires the
          recovery key to replace the TPM enrollment.
        '';
      };

      recoveryKeyPath = lib.mkOption {
        type = lib.types.str;
        default = "/run/aos-var-recovery.key";
        description = ''
          Where the first-boot sealing writes the generated LUKS recovery
          passphrase. MUST be off the encrypted volume it unlocks; the
          default is the `/run` tmpfs. A deployment is expected to escrow
          this off-machine (e.g. report it back through the provisioning
          metadata channel) — "escrowed somewhere recoverable, never on
          /var" is the hard requirement (RFC-0006 measured-boot.md).
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

      # Keep the public firmware db authority available to stage 2 through
      # /etc. The initrd recovery-retention check references cfg.dbCert
      # directly, which retains that immutable store object in the initrd
      # closure without creating a toplevel/initrd dependency cycle.
      environment.etc."aos/trust/secure-boot-db.crt".source = cfg.dbCert;

      # First-boot recovery seeding authenticates the ESP copy before it
      # records any retention evidence. The initrd copies an explicit package
      # closure, so both PE verification tools must be named here.
      aos.boot.initrd.extraPackages = lib.mkIf config.aos.boot.recovery.enable [
        pkgs.binutils
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

    (lib.mkIf cfg.measuredBoot.enable {
      # This is an image-fixed input, not a host-config build. Capture its
      # stage-1 store path in the base library so the on-host evaluator can
      # reuse it without requiring mkDerivation in the frozen package set.
      aos.config._artifactSources.pcr-public-key =
        if config.aos.config.frozenArtifacts ? "pcr-public-key"
        then null
        else
          pkgs.mkDerivation {
            pname = "aos-pcr-pubkey";
            version = "1";
            src = null;
            phases = [
              {
                name = "install";
                script = ''
                  mkdir -p $out
                  cp ${toString cfg.measuredBoot.pcrPublicKey} $out/pcr.pem
                '';
              }
            ];
          };

      assertions = [
        {
          assertion = cfg.enable;
          message = "aos.boot.secureBoot.measuredBoot requires aos.boot.secureBoot.enable.";
        }
        {
          assertion =
            cfg.measuredBoot.pcrPrivateKey
            != null
            && cfg.measuredBoot.pcrPublicKey != null;
          message = "aos.boot.secureBoot.measuredBoot requires pcrPrivateKey and pcrPublicKey.";
        }
      ];

      # Ship the PCR public key into the initrd for first-boot sealing.
      aos.boot.initrd.extraPackages = [pcrKeyForInitrd];
      environment.systemPackages = [pkgs.aos-var-policy-migrate];
      environment.etc."aos/pcr-sign.pem".source = "${pcrKeyForInitrd}/pcr.pem";

      # First boot: LUKS2-format /var and enroll a TPM2 token sealed to
      # the signed PCR policy (PCR 11, signature-flexible) plus PCRs 7 and
      # 12 pinned by value, and a recovery key escrowed off the volume.
      # Later boots: unlock via the TPM2 token, no passphrase. Ordered
      # after aos-repart (which creates the partition) and before
      # mount-var (which mounts /dev/mapper/var).
      boot.initrd.systemd.services."aos-var-crypt" = {
        description = "Encrypt and TPM2-seal /var (measured boot)";
        requiredBy = ["initrd-fs.target"];
        requires = ["aos-boot-identity-guard.service"];
        before = ["mount-var.service" "initrd-fs.target"];
        # Only ORDER after the disk carver (aos-repart), don't Require it: on a
        # reboot (var already provisioned) repart is a no-op. No
        # ConditionPathExists on the var device either — for a crypto_LUKS
        # partition udev surfaces /dev/disk/by-partlabel/var late, which would
        # condition-skip this whole unit on the unlock boot; the script waits
        # for it instead.
        after = [
          "aos-boot-identity-guard.service"
          "aos-repart.service"
          "systemd-udev-settle.service"
        ];
        unitConfig.ConditionKernelCommandLine = "!aos.recovery=1";
        environment.PATH = lib.mkForce (lib.concatStringsSep ":" [
          "${pkgs.coreutils}/bin"
          "${pkgs.util-linux}/bin"
          "${pkgs.util-linux}/sbin"
          "${pkgs.cryptsetup}/bin"
          "${pkgs.cryptsetup}/sbin"
        ]);
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          # Surface the script's diagnostics on the console/journal — the
          # TPM2 unlock path is subtle and a silent failure would only show
          # up as an initrd emergency drop.
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        script = ''
          set -euo pipefail
          dev=/dev/disk/by-partlabel/var
          pub=${pcrKeyForInitrd}/pcr.pem
          enroll=${pkgs.systemd}/bin/systemd-cryptenroll
          csetup=${pkgs.systemd}/lib/systemd/systemd-cryptsetup
          cs=${pkgs.cryptsetup}/sbin/cryptsetup
          mkfs=${pkgs.e2fsprogs}/sbin/mkfs.ext4
          sbvar=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
          # Log to /dev/kmsg — the console (ttyS0) is contended by the
          # initrd debug shell whose escape sequences corrupt the serial.
          klog() { echo "aos-var-crypt: $*" > /dev/kmsg 2>/dev/null || echo "aos-var-crypt: $*" >&2; }

          # Make the systemd-tpm2 LUKS2 token plugin findable. cryptsetup
          # dlopens external token plugins by absolute path from its
          # configured tokens dir (/run/cryptsetup/tokens — see
          # cryptsetup.nix), but the systemd-tpm2 plugin ships in systemd's
          # store path. Symlink systemd's plugin dir into that search path
          # so systemd-cryptsetup can use the TPM2 token to unlock /var.
          mkdir -p /run/cryptsetup
          ln -sfn ${pkgs.systemd}/lib/cryptsetup /run/cryptsetup/tokens

          # Wait for the var partition to surface — udev is slow to process a
          # crypto_LUKS partition on the unlock boot, and there is no
          # ConditionPathExists guarding this unit, so poll (up to ~30s).
          i=0
          while [ ! -e "$dev" ] && [ "$i" -lt 60 ]; do i=$((i + 1)); sleep 0.5; done
          if [ ! -e "$dev" ]; then
            klog "$dev absent after wait; skipping"
            exit 0
          fi
          klog "device ready: isLuks=$("$cs" isLuks "$dev" && echo Y || echo N)"

          if "$cs" isLuks "$dev"; then
            # Already sealed: unlock via the signed TPM2 policy. A signed
            # (public-key) policy needs the PCR *signature* at unlock time;
            # sd-stub materializes the UKI's .pcrsig at
            # /run/systemd/tpm2-pcr-signature.json — pass it explicitly. If
            # the unseal fails (SB-state or appended-input PCR mismatch, or
            # an unsigned UKI), /var stays locked and recovery is required —
            # the intended security property. `headless` makes
            # systemd-cryptsetup FAIL rather than fall back to an
            # interactive passphrase prompt (which would wedge the boot);
            # `timeout` bounds it either way.
            if [ ! -e /dev/mapper/var ]; then
              sig=""
              for p in /run/systemd/tpm2-pcr-signature.json \
                       /.extra/tpm2-pcr-signature.json \
                       /run/credentials/@system/tpm2-pcr-signature.json; do
                if [ -r "$p" ]; then sig="$p"; break; fi
              done
              klog "unlocking /var via TPM2 (signature=''${sig:-<none>})"
              opts="tpm2-device=auto,headless"
              [ -n "$sig" ] && opts="tpm2-device=auto,tpm2-signature=$sig,headless"
              rc=0
              timeout 60 "$csetup" attach var "$dev" - "$opts" || rc=$?
              if [ "$rc" -ne 0 ]; then
                klog "TPM2 unlock failed (rc=$rc) — /var stays sealed, recovery key required"
              fi
            fi
            exit 0
          fi

          # Not yet LUKS. Sealing binds PCR 7 (Secure Boot state) and PCR 12
          # (boot inputs) by value, so it must happen during a clean boot with
          # SB *enforcing* — otherwise the seal captures an unusable state.
          # Read SecureBoot from efivarfs (mount it if the initrd has not yet).
          mount -t efivarfs none /sys/firmware/efi/efivars 2>/dev/null || true
          sb=0
          if [ -r "$sbvar" ]; then
            sb=$(od -An -tu1 -j4 -N1 "$sbvar" | tr -d ' ' || echo 0)
          fi

          if [ "$sb" != "1" ]; then
            # Pre-enrollment boot (Setup Mode): SB not enforcing yet. Bring
            # up a temporary PLAIN ext4 /var so the system reaches
            # multi-user and an operator/test can enroll PK/KEK/db; the
            # first enforcing boot below replaces it with the sealed volume.
            # The measured-boot repart plan initially leaves /var raw. Format
            # it once and preserve it across further Setup Mode boots so key
            # enrollment can complete without repeated formatting. This
            # plaintext state remains disposable: the first enforcing boot
            # replaces it with the sealed volume below.
            fs_type=$(${pkgs.util-linux}/sbin/blkid -p -s TYPE -o value "$dev" 2>/dev/null || true)
            case "$fs_type" in
              "")
                klog "SB not enforcing yet — formatting plain ext4 /var (sealed once enforcing)"
                "$mkfs" -q -L var "$dev"
                ;;
              ext4)
                klog "SB not enforcing yet — preserving existing plain ext4 /var"
                ;;
              *)
                klog "SB not enforcing yet — refusing unexpected /var filesystem type: $fs_type"
                exit 1
                ;;
            esac
            exit 0
          fi

          # First enforcing boot: format with a throwaway key, seal to the
          # signed PCR policy (PCR 11) + pinned PCRs 7 and 12, add a recovery
          # key, then drop the bootstrap keyslot so only the TPM/recovery paths
          # remain.
          keyf=$(mktemp)
          dd if=/dev/urandom of="$keyf" bs=512 count=1 status=none
          "$cs" luksFormat --type luks2 --batch-mode "$dev" "$keyf"
          "$cs" open "$dev" var --key-file "$keyf"
          "$mkfs" -q -L var /dev/mapper/var
          "$enroll" --unlock-key-file="$keyf" \
            --tpm2-device=auto \
            --tpm2-public-key="$pub" \
            --tpm2-public-key-pcrs=${cfg.measuredBoot.signedPcrs} \
            --tpm2-pcrs=${cfg.measuredBoot.pinnedPcrs} \
            "$dev"
          # Recovery key — MUST be escrowed off-machine (deployment
          # decision); written to the /run tmpfs, never to /var. This is
          # NOT masked: if recovery enrollment fails we must abort BEFORE
          # wiping the bootstrap slot, otherwise a later TPM unseal failure
          # (legit firmware/SB or boot-input change → pinned PCR mismatch) would brick /var
          # with no way in. `set -e` propagates a failure here.
          "$enroll" --unlock-key-file="$keyf" --recovery-key "$dev" \
            > ${cfg.measuredBoot.recoveryKeyPath}
          chmod 600 ${cfg.measuredBoot.recoveryKeyPath}
          # Drop the throwaway bootstrap keyslot by TYPE (a plain
          # passphrase/keyfile slot), not by a guessed slot number — the
          # TPM2 and recovery slots carry their own systemd token types and
          # are left intact.
          "$enroll" --unlock-key-file="$keyf" --wipe-slot=password "$dev"
          shred -u "$keyf" 2>/dev/null || rm -f "$keyf"
        '';
      };
    })
  ];
}
