##! modules/image/_builder.nix — AOS disk image builder (sandbox-compatible)
##!
##! Produces a UEFI-bootable GPT disk image from an evaluated AOS system
##! configuration. The image contains:
##!
##!   Partition 1 (ESP)    — vfat, sized by the image artifact contract
##!                          EFI/BOOT/BOOT<ARCH>.EFI           (UEFI fallback)
##!                          EFI/systemd/systemd-boot<arch>.efi (sd-boot canonical)
##!                          EFI/Linux/aos-<version>.efi       (UKI)
##!                          loader/loader.conf                (sd-boot config)
##!   Partition 2 (root-a) — rootFsType (erofs/ext4), fixed slot capacity
##!
##! systemd-repart creates swap and /var partitions on first boot
##! in the unallocated space after root-a.
##!
##! Build strategy (no losetup/mount — fully sandbox-compatible):
##!   1. lib/build/rootfs.nix builds root.img (erofs or ext4, root-owned)
##!   2. aos-uki assembles vmlinuz + initrd + cmdline + os-release into a UKI
##!   3. Populate ESP tree (sd-boot + UKI + loader.conf)
##!   4. mkfs.vfat + mcopy → creates FAT32 ESP image
##!   5. sfdisk + dd → assembles partitions into final GPT image
##!
##! Arguments:
##!   pkgs   — AOS package set
##!   lib    — AOS library
##!   system — evaluated system configuration (from evalModules)
##!   name   — image name slug
##!
##! Output: zstd-compressed disk bytes + portable public image-info.json
{
  pkgs,
  lib,
  system,
  name,
  runtimeClosureAudit,
}: let
  # Kernel command line parameters from the evaluated config.
  kernelParams = lib.concatStringsSep " " system.config.aos.boot.kernelParams;
  # Each UKI names its own immutable root slot. The root hash bytes are shared
  # because both slots receive the exact same reproducible root image; only the
  # DPS data/hash device hints differ.
  kernelParamsB =
    builtins.replaceStrings
    [
      system.config.aos.boot.storage.resolvedDevices.rootAHash
      system.config.aos.boot.storage.resolvedDevices.rootA
    ]
    [
      system.config.aos.boot.storage.resolvedDevices.rootBHash
      system.config.aos.boot.storage.resolvedDevices.rootB
    ]
    kernelParams;

  version = system.config.aos.system.version;

  budgets = system.config.aos.image.budgets;
  espStartSector = 2048; # 1 MiB GPT + alignment

  # UEFI ESP partition GUID.
  espGuid = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
  guidFrom = seed: let
    digest = builtins.hashString "sha256" seed;
  in "${builtins.substring 0 8 digest}-${builtins.substring 8 4 digest}-${builtins.substring 12 4 digest}-${builtins.substring 16 4 digest}-${builtins.substring 20 12 digest}";
  identitySeed = "aos-image:${version}:${lib.system}:${name}";
  rootfsPname = "aos-image-${name}-rootfs";
  verityDigest = builtins.hashString "sha256" "aos-rootfs:verity:${rootfsPname}:aos-root";
  verityUuid = "${builtins.substring 0 8 verityDigest}-${builtins.substring 8 4 verityDigest}-4${builtins.substring 13 3 verityDigest}-8${builtins.substring 17 3 verityDigest}-${builtins.substring 20 12 verityDigest}";
  veritySalt = builtins.substring 0 64 (builtins.hashString "sha256" "aos-rootfs:salt:${rootfsPname}:aos-root");
  diskGuid = guidFrom "${identitySeed}:disk";
  espPartitionGuid = guidFrom "${identitySeed}:esp";
  rootAPartitionGuid = guidFrom "${identitySeed}:root-a";
  rootAHashPartitionGuid = guidFrom "${identitySeed}:root-a-hash";
  rootBPartitionGuid = guidFrom "${identitySeed}:root-b";
  rootBHashPartitionGuid = guidFrom "${identitySeed}:root-b-hash";
  fatVolumeId = lib.toUpper (builtins.substring 0 8 (builtins.hashString "sha256" "${identitySeed}:fat"));
  # Architecture-specific Discoverable Partitions Specification types keep
  # immutable root slots in a separate matching domain from operator-created
  # linux-generic data partitions. Discovery remains disabled; AOS still
  # selects slots explicitly by partlabel.
  dpsTypes = {
    x86_64 = {
      root = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709";
      verity = "2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5";
    };
    aarch64 = {
      root = "B921B045-1DF0-41C3-AF44-4C6F280D3FAE";
      verity = "DF3300CE-D69F-4C92-978C-9BFB0F38D820";
    };
    i686 = {
      root = "44479540-F297-41B2-9AF7-D131D5F0458A";
      verity = "D13C5D3B-B5D1-422A-B29F-9454FDC89D76";
    };
    riscv64 = {
      root = "72EC70A6-CF74-40E6-BD49-4BDA08E8F224";
      verity = "B6ED5582-440B-4209-B8DA-5FF7C419EA3D";
    };
  };
  dpsType =
    dpsTypes.${lib.platform.constraints.cpu}
    or (throw "no DPS root partition types for ${lib.system}");
  rootGuid = dpsType.root;
  verityGuid = dpsType.verity;
  efiNames = {
    x86_64 = {
      fallback = "BOOTX64.EFI";
      systemd = "systemd-bootx64.efi";
    };
    aarch64 = {
      fallback = "BOOTAA64.EFI";
      systemd = "systemd-bootaa64.efi";
    };
    i686 = {
      fallback = "BOOTIA32.EFI";
      systemd = "systemd-bootia32.efi";
    };
    riscv64 = {
      fallback = "BOOTRISCV64.EFI";
      systemd = "systemd-bootriscv64.efi";
    };
  };
  efiName =
    efiNames.${lib.platform.constraints.cpu}
    or (throw "no UEFI executable names for ${lib.system}");

  mkRootfs = import ../../lib/build/rootfs.nix;
  # The image's root filesystem matches the system's declared root fstype, so
  # the fstab/mount and the on-disk image agree. Production systems set this to
  # "erofs" (compressed, read-only) for a much smaller bootable image.
  rootFsType = system.config.aos.filesystems.rootFsType;

  # Secure Boot signing (RFC-0006). When enabled, the UKI and sd-boot
  # are Authenticode-signed with the deployment db key; otherwise the
  # image is the byte-reproducible unsigned artifact.
  sb = system.config.aos.boot.secureBoot;
  externalFinalization = sb.externalFinalization.enable;
  localSecureBootSigning = sb.enable && !externalFinalization;
  dbCertificate = sb._effectiveDbCert;
  moduleCertificate = sb.lockdown._effectiveModuleSigningCert;
  pcrPublicKey = sb.measuredBoot._effectivePcrPublicKey;
  enrollmentDirectory = sb._effectiveEnrollAuthDir;

  # dm-verity root anchoring, enabled by aos.security.verity.enable.
  # (modules/security/verity.nix, auto-loaded so the option always exists; false
  # for every ext4/VM-test system). When false, every verity branch below is
  # gated off and the image build is unchanged.
  verityEnabled = system.config.aos.security.verity.enable;
  recovery = system.config.aos.boot.recovery;
  recoveryEnabled = recovery.enable;
  activeRegistryDbCerts = lib.concatLists (
    map
    (registry: registry.sbDbCerts)
    (builtins.attrValues system.config.aos.apm.registries)
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

  rootfs = mkRootfs ({
      inherit pkgs lib system;
      pname = "aos-image-${name}-rootfs";
      label = "aos-root";
      fsType = rootFsType;
      erofsCompressionLevel = system.config.aos.image.erofsCompressionLevel;
      extraClosures = system.config.aos.image.hostConfigClosures;
      kernelModulePackages = system.config.aos.kernel.modulePackages;
      firmwarePackages = system.config.aos.kernel.firmwarePackages;
      # Preserve the image-owned Secure Boot authority outside /nix/store.
      # The baked toplevel ceases to be a GC root after host configuration is
      # activated, while this copy remains protected by the immutable root.
      postPopulate = ''
        ${lib.optionalString sb.enable ''
          mkdir -p rootfs/usr/lib/aos/image-trust
          cp ${activeImageDbCerts}/active-db-certs.pem \
            rootfs/usr/lib/aos/image-trust/active-db-certs.pem
        ''}
        ${lib.optionalString (system.config.aos.apm.drainScript != null) ''
          # Draining belongs to the system that is currently serving
          # workloads, not the image selected as the next boot. Keep the hook
          # in the immutable root so host re-evaluation and store GC cannot
          # replace or remove that image-owned transition policy.
          mkdir -p rootfs/usr/lib/aos
          cp ${system.config.aos.apm.drainScript} rootfs/usr/lib/aos/drain
          chmod 0555 rootfs/usr/lib/aos/drain
        ''}
      '';
      shrinkToFit = true;
      headroomMiB = 64;
    }
    // lib.optionalAttrs verityEnabled {
      verity = true;
      # Sign the ASCII-hex roothash with the SB db key when SB is enabled (for
      # the optional in-kernel roothash-signature enforcement path). The
      # roothash-on-cmdline anchoring itself is key-independent.
      secureBootKey =
        if localSecureBootSigning
        then sb.dbKey
        else null;
      secureBootCert =
        if sb.enable
        then dbCertificate
        else null;
    });

  mkUki = slotName: cmdline:
    pkgs.aos-uki {
      name = "${name}-slot-${slotName}";
      inherit version cmdline;
      kernel = system.config.system.build.kernel;
      initrd = system.config.system.build.initrd;
      osRelease = "${ukiOsRelease}/os-release";
      secureBootKey =
        if localSecureBootSigning
        then sb.dbKey
        else null;
      secureBootCert =
        if sb.enable
        then dbCertificate
        else null;
      # PCR-policy signing (RFC-0006 phase 3): when measured boot is on, the
      # UKI carries a signed PCR policy so TPM-sealed /var unseals across OTA.
      pcrPrivateKey =
        if sb.measuredBoot.enable && !externalFinalization
        then sb.measuredBoot.pcrPrivateKey
        else null;
      pcrPublicKey =
        if sb.measuredBoot.enable && !externalFinalization
        then pcrPublicKey
        else null;
      # Bake `roothash=<hex>` (a build output) into the measured
      # .cmdline. `null` when verity is off, so non-verity UKIs are unchanged.
      rootHashFile =
        if verityEnabled
        then "${rootfs}/root.roothash"
        else null;
    };

  ukiA = mkUki "a" kernelParams;
  ukiB = mkUki "b" kernelParamsB;
  ukiAStoreFilename = "aos-${name}-slot-a-${version}.efi";
  ukiBStoreFilename = "aos-${name}-slot-b-${version}.efi";

  recoveryCmdline = "console=ttyS0,115200 rd.systemd.unit=aos-recovery.target aos.recovery=1 rd.luks=0";
  recoverySlotManifest =
    if recoveryEnabled && localSecureBootSigning
    then
      pkgs.mkDerivation {
        pname = "aos-recovery-slot-manifest";
        inherit version;
        src = null;
        buildDeps = [pkgs.coreutils pkgs.jq pkgs.openssl];
        runtimeDeps = [];
        propagatedDeps = [];
        phases = [
          {
            name = "install";
            script = ''
              mkdir -p $out
              root_hash=$(cat ${rootfs}/root.roothash)
              uki_a_sha256=$(sha256sum ${ukiA}/${ukiAStoreFilename} | cut -d ' ' -f1)
              uki_b_sha256=$(sha256sum ${ukiB}/${ukiBStoreFilename} | cut -d ' ' -f1)
              ${pkgs.jq}/bin/jq -S -n \
                --arg schema "aos.recovery-slot-manifest/v1" \
                --arg release "${version}" \
                --argjson recoveryAbi ${toString recovery.abi} \
                --arg rootHash "$root_hash" \
                --arg ukiASha256 "$uki_a_sha256" \
                --arg ukiBSha256 "$uki_b_sha256" \
                '{
                  schema: $schema,
                  release: $release,
                  recoveryAbi: $recoveryAbi,
                  slots: {
                    A: {
                      rootData: "/dev/disk/by-partlabel/root-a",
                      rootHashDevice: "/dev/disk/by-partlabel/root-a-hash",
                      rootHash: $rootHash,
                      ukiSha256: $ukiASha256
                    },
                    B: {
                      rootData: "/dev/disk/by-partlabel/root-b",
                      rootHashDevice: "/dev/disk/by-partlabel/root-b-hash",
                      rootHash: $rootHash,
                      ukiSha256: $ukiBSha256
                    }
                  }
                }' > $out/slot-manifest.json
              ${pkgs.openssl}/bin/openssl dgst -sha256 \
                -sign ${sb.dbKey} \
                -out $out/slot-manifest.json.sig \
                $out/slot-manifest.json
              ${pkgs.openssl}/bin/openssl x509 -pubkey -noout \
                -in ${dbCertificate} > db-public.pem
              ${pkgs.openssl}/bin/openssl dgst -sha256 \
                -verify db-public.pem \
                -signature $out/slot-manifest.json.sig \
                $out/slot-manifest.json
            '';
          }
        ];
      }
    else null;
  mkRecoveryInitrd = copy:
    import ../base/_recovery-initrd-builder.nix {
      inherit pkgs lib;
      kernel = system.config.system.build.kernel;
      loadModules = system.config.aos.boot.initrd.loadModules;
      dbCert = dbCertificate;
      authorizedDbCerts = "${activeImageDbCerts}/active-db-certs.pem";
      slotManifest = recoverySlotManifest;
      recoveryCopy = lib.toUpper copy;
      recoveryAbi = recovery.abi;
      platform = lib.system;
      moduleAbi = system.config.aos.system.moduleAbi;
    };
  recoveryInitrdA =
    if recoveryEnabled
    then mkRecoveryInitrd "a"
    else null;
  recoveryInitrdB =
    if recoveryEnabled
    then mkRecoveryInitrd "b"
    else null;
  mkRecoveryOsRelease = copy:
    pkgs.writeTextFile {
      name = "aos-recovery-${copy}-os-release";
      destination = "/os-release";
      text = ''
        NAME="AOS Recovery"
        ID=aos-recovery
        VERSION="${version}"
        VERSION_ID="${version}"
        PRETTY_NAME="AOS Recovery ${lib.toUpper copy} (${version})"
        AOS_RELEASE_ID="${version}"
        AOS_RECOVERY_ABI=${toString recovery.abi}
        AOS_RECOVERY_COPY=${lib.toUpper copy}
      '';
    };
  mkRecoveryUki = copy:
    pkgs.aos-uki {
      name = "${name}-recovery-${copy}";
      inherit version;
      cmdline = recoveryCmdline;
      kernel = system.config.system.build.kernel;
      initrd =
        if copy == "a"
        then recoveryInitrdA
        else recoveryInitrdB;
      osRelease = "${mkRecoveryOsRelease copy}/os-release";
      secureBootKey =
        if localSecureBootSigning
        then sb.dbKey
        else null;
      secureBootCert =
        if localSecureBootSigning
        then dbCertificate
        else null;
      # Recovery is db-signed code, not an authorization to unseal normal
      # persistent state. It therefore carries neither a PCR-policy signature
      # nor a normal root hash.
      pcrPrivateKey = null;
      pcrPublicKey = null;
      rootHashFile = null;
    };
  recoveryUkiA =
    if recoveryEnabled
    then mkRecoveryUki "a"
    else null;
  recoveryUkiB =
    if recoveryEnabled
    then mkRecoveryUki "b"
    else null;
  # Preserve the public passthru as the slot-A/first-install UKI.
  uki = ukiA;

  ukiFilename = "aos-generation-0000000001.efi";

  # Type-2 boot entries normally derive their sort key and version from ID and
  # VERSION_ID in the embedded .osrel section. Package versions are display
  # identifiers, not a reliable ordering for a machine's local A/B history.
  # Keep the measured AOS identity fields while omitting those two sort inputs;
  # sd-boot then orders live entries by the monotonic installed filename below.
  # The root filesystem's /etc/os-release remains the complete user-facing
  # document and is unaffected.
  ukiOsRelease = pkgs.writeTextFile {
    name = "aos-uki-os-release";
    destination = "/os-release";
    text = ''
      NAME="${name}"
      VERSION="${version}"
      PRETTY_NAME="${name} ${version}"
      HOME_URL="https://aos.dev"
      BUG_REPORT_URL="https://aos.dev/issues"
      AOS_RELEASE_ID="${version}"
      AOS_STATE_VERSION=${system.config.aos.system.stateVersion}
      AOS_MODULE_ABI=${toString system.config.aos.system.moduleAbi}
      AOS_BASELIB_DIGEST=sha256:${builtins.hashString "sha256" (toString system.config.aos.config.evalAtBoot.baseLib)}
    '';
  };

  # sd-boot boot-counting tries suffix for durable image
  # rollback. When `aos.boot.bootCountingTries` is set, the UKI staged into the
  # ESP is named `aos-generation-0000000001+<tries>.efi`; sd-boot decrements the
  # counter on each boot attempt and auto-demotes a UKI that fails to boot, so a
  # bad new image falls back to the other A/B slot without operator action.
  # Runtime staging replaces the generation component with the persistent
  # image-generation number. This makes a new candidate sort ahead of the
  # previous slot regardless of the package's human version string, while an
  # exhausted candidate still sorts behind every live entry. Durable rollback
  # to an older slot uses `bootctl set-default`; the image-owned
  # `default aos-*.efi` pattern provides automatic fallback.
  bootCountingTries = system.config.aos.boot.bootCountingTries;
  espUkiFilename =
    if bootCountingTries == null
    then ukiFilename
    else "aos-generation-0000000001+${toString bootCountingTries}.efi";

  # Production releases stop at a deterministic, public-only assembly. The
  # coordinator copies these inputs to a new directory, signs through
  # role-bound external providers, and constructs the final disk bytes there.
  # Private material is intentionally neither an argument nor an environment
  # value of this derivation.
  unsignedAssembly = pkgs.mkDerivation {
    pname = "aos-image-${name}-unsigned-assembly";
    inherit version;
    src = null;
    buildDeps = [pkgs.coreutils pkgs.findutils pkgs.jq pkgs.tar];
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "assemble";
        script = ''
          set -eu
          mkdir -p "$out/inputs" "$out/trust" "$out/enrollment"
          cp ${rootfs}/root.img "$out/inputs/root.img"
          cp ${rootfs}/root.verity "$out/inputs/root.verity"
          cp ${rootfs}/root.roothash "$out/inputs/root.roothash"
          cp ${system.config.system.build.initrd}/initrd.img "$out/inputs/initrd.img"
          ${lib.optionalString recoveryEnabled ''
            cp ${recoveryInitrdA}/initrd.img "$out/inputs/recovery-initrd-a.img"
            cp ${recoveryInitrdB}/initrd.img "$out/inputs/recovery-initrd-b.img"
            cp ${mkRecoveryOsRelease "a"}/os-release "$out/inputs/recovery-os-release-a"
            cp ${mkRecoveryOsRelease "b"}/os-release "$out/inputs/recovery-os-release-b"
          ''}
          kernel=$(find ${system.config.system.build.kernel}/boot -maxdepth 1 -type f -name 'vmlinuz-*' -print)
          [ "$(printf '%s\n' "$kernel" | wc -l)" -eq 1 ]
          cp "$kernel" "$out/inputs/vmlinuz"
          cp ${pkgs.systemd}/lib/systemd/boot/efi/${efiName.systemd} "$out/inputs/systemd-boot.efi"
          cp ${pkgs.systemd}/lib/systemd/boot/efi/linux${
            if lib.platform.constraints.cpu == "x86_64"
            then "x64"
            else "aa64"
          }.efi.stub "$out/inputs/uki-stub.efi"
          cp ${ukiOsRelease}/os-release "$out/inputs/os-release"
          cp ${dbCertificate} "$out/trust/secure-boot-db.crt"
          cp ${moduleCertificate} "$out/trust/module-signing.crt"
          cp ${pcrPublicKey} "$out/trust/pcr-public.pem"
          for file in db.auth KEK.auth PK.auth; do
            cp ${enrollmentDirectory}/"$file" "$out/enrollment/$file"
          done
          tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
            -cf "$out/inputs/firmware-enrollment.tar" -C "$out/enrollment" .
          rm -rf "$out/enrollment"

          root_bytes=$(stat -c %s "$out/inputs/root.img")
          initrd_bytes=$(stat -c %s "$out/inputs/initrd.img")
          recovery_a_bytes=$(stat -c %s "$out/inputs/recovery-initrd-a.img")
          recovery_b_bytes=$(stat -c %s "$out/inputs/recovery-initrd-b.img")
          verity_bytes=$(stat -c %s "$out/inputs/root.verity")
          [ "$root_bytes" -le $((${toString budgets.maxRootMiB} * 1048576)) ] || {
            echo "unsigned root exceeds its ${toString budgets.maxRootMiB} MiB release budget" >&2
            exit 1
          }
          for bytes in "$initrd_bytes" "$recovery_a_bytes" "$recovery_b_bytes"; do
            [ "$bytes" -le $((${toString budgets.maxInitrdMiB} * 1048576)) ] || {
              echo "unsigned initrd exceeds its ${toString budgets.maxInitrdMiB} MiB release budget" >&2
              exit 1
            }
          done
          [ "$verity_bytes" -le $((${toString budgets.maxVerityMiB} * 1048576)) ] || {
            echo "verity tree exceeds its ${toString budgets.maxVerityMiB} MiB partition" >&2
            exit 1
          }

          ${pkgs.jq}/bin/jq -cS -n \
            --arg schema aos.image.assembly-recipe/v1 \
            --arg release ${lib.escapeShellArg version} \
            --arg platform ${lib.escapeShellArg lib.system} \
            --arg variant ${lib.escapeShellArg name} \
            --arg kernelRelease ${lib.escapeShellArg system.config.system.build.kernel.version} \
            --arg kernelParams ${lib.escapeShellArg kernelParams} \
            --arg kernelParamsB ${lib.escapeShellArg kernelParamsB} \
            --arg recoveryCmdline ${lib.escapeShellArg recoveryCmdline} \
            --argjson moduleAbi ${toString system.config.aos.system.moduleAbi} \
            --argjson recoveryAbi ${toString recovery.abi} \
            --argjson sbatGeneration ${toString system.config.aos.system.stateVersion} \
            --arg secureBootRole ${lib.escapeShellArg sb.externalFinalization.secureBootRole} \
            --arg moduleRole ${lib.escapeShellArg sb.externalFinalization.moduleRole} \
            --arg pcrRole ${lib.escapeShellArg sb.externalFinalization.pcrRole} \
            --arg ukify ${lib.escapeShellArg "${pkgs.systemd.tools}/bin/ukify"} \
            --arg measure ${lib.escapeShellArg "${pkgs.systemd}/lib/systemd/systemd-measure"} \
            --arg objcopy ${lib.escapeShellArg "${pkgs.binutils}/bin/objcopy"} \
            --arg signFile ${lib.escapeShellArg "${system.config.system.build.kernel.dev}/lib/modules/${system.config.system.build.kernel.version}/build/scripts/sign-file"} \
            --arg mkfsErofs ${lib.escapeShellArg "${pkgs.erofs-utils}/bin/mkfs.erofs"} \
            --arg gccLib ${lib.escapeShellArg "${pkgs.gcc-libs}/lib"} \
            --arg fsckErofs ${lib.escapeShellArg "${pkgs.erofs-utils}/bin/fsck.erofs"} \
            --arg veritysetup ${lib.escapeShellArg "${pkgs.cryptsetup}/bin/veritysetup"} \
            --arg qemuImg ${lib.escapeShellArg "${pkgs.qemu}/bin/qemu-img"} \
            --arg sfdisk ${lib.escapeShellArg "${pkgs.util-linux}/sbin/sfdisk"} \
            --arg mkfsVfat ${lib.escapeShellArg "${pkgs.dosfstools}/sbin/mkfs.vfat"} \
            --arg mcopy ${lib.escapeShellArg "${pkgs.mtools}/bin/mcopy"} \
            --arg zstd ${lib.escapeShellArg "${pkgs.zstd}/bin/zstd"} \
            --arg cpio ${lib.escapeShellArg "${pkgs.cpio}/bin/cpio"} \
            --arg tar ${lib.escapeShellArg "${pkgs.tar}/bin/tar"} \
            --arg find ${lib.escapeShellArg "${pkgs.findutils}/bin/find"} \
            --arg openssl ${lib.escapeShellArg "${pkgs.openssl}/bin/openssl"} \
            --arg sbverify ${lib.escapeShellArg "${pkgs.sbsigntools}/bin/sbverify"} \
            --arg modinfo ${lib.escapeShellArg "${pkgs.kmod}/bin/modinfo"} \
            --arg diskGuid ${lib.escapeShellArg diskGuid} \
            --arg espGuid ${lib.escapeShellArg espGuid} \
            --arg rootGuid ${lib.escapeShellArg rootGuid} \
            --arg verityGuid ${lib.escapeShellArg verityGuid} \
            --arg espPartitionGuid ${lib.escapeShellArg espPartitionGuid} \
            --arg rootAPartitionGuid ${lib.escapeShellArg rootAPartitionGuid} \
            --arg rootAHashPartitionGuid ${lib.escapeShellArg rootAHashPartitionGuid} \
            --arg rootBPartitionGuid ${lib.escapeShellArg rootBPartitionGuid} \
            --arg rootBHashPartitionGuid ${lib.escapeShellArg rootBHashPartitionGuid} \
            --arg fatVolumeId ${lib.escapeShellArg fatVolumeId} \
            --arg fallbackFilename ${lib.escapeShellArg efiName.fallback} \
            --arg systemdFilename ${lib.escapeShellArg efiName.systemd} \
            --arg ukiFilename ${lib.escapeShellArg espUkiFilename} \
            --arg rootFsType ${lib.escapeShellArg rootFsType} \
            --arg rootFsUuid bdfb6fc9-0000-4000-8000-000000000001 \
            --arg rootFsLabel aos-root \
            --argjson erofsCompressionLevel ${toString system.config.aos.image.erofsCompressionLevel} \
            --arg verityUuid ${lib.escapeShellArg verityUuid} \
            --arg veritySalt ${lib.escapeShellArg veritySalt} \
            --argjson espExtraFreeMiB ${toString system.config.aos.image.espExtraFreeMiB} \
            --argjson sectorSize 512 \
            --argjson alignmentSectors 2048 \
            --argjson espStartSector ${toString espStartSector} \
            --argjson espMiB ${toString budgets.maxEspMiB} \
            --argjson rootMiB ${toString system.config.aos.image.rootPartitionMiB} \
            --argjson verityMiB ${toString budgets.maxVerityMiB} \
            --argjson maxRootMiB ${toString budgets.maxRootMiB} \
            --argjson maxInitrdMiB ${toString budgets.maxInitrdMiB} \
            --argjson maxUkiMiB ${toString budgets.maxUkiMiB} \
            --argjson maxDownloadMiB ${toString budgets.maxDownloadMiB} \
            '{schema_version:$schema, release:$release, platform:$platform,
              system_variant:$variant, kernel_release:$kernelRelease, module_abi:$moduleAbi,
              recovery_abi:$recoveryAbi, sbat_generation:$sbatGeneration,
              command_lines:{slot_a:$kernelParams,slot_b:$kernelParamsB,recovery:$recoveryCmdline},
              signer_roles:{secure_boot:$secureBootRole,module:$moduleRole,pcr:$pcrRole},
              layout:{sector_size:$sectorSize,alignment_sectors:$alignmentSectors,
                esp_start_sector:$espStartSector,esp_size_mib:$espMiB,
                root_partition_mib:$rootMiB,verity_partition_mib:$verityMiB,
                root_filesystem_type:$rootFsType,root_filesystem_uuid:$rootFsUuid,
                root_filesystem_label:$rootFsLabel,
                erofs_compression_level:$erofsCompressionLevel,
                verity_uuid:$verityUuid,verity_salt:$veritySalt,
                esp_extra_free_mib:$espExtraFreeMiB,disk_guid:$diskGuid,
                partition_type_guids:{esp:$espGuid,root:$rootGuid,verity:$verityGuid},
                partition_guids:{esp:$espPartitionGuid,root_a:$rootAPartitionGuid,
                  root_a_hash:$rootAHashPartitionGuid,root_b:$rootBPartitionGuid,
                  root_b_hash:$rootBHashPartitionGuid},fat_volume_id:$fatVolumeId,
                efi_filenames:{fallback:$fallbackFilename,systemd_boot:$systemdFilename,
                  normal_uki:$ukiFilename}},
              budgets:{root_mib:$maxRootMiB,initrd_mib:$maxInitrdMiB,
                uki_mib:$maxUkiMiB,download_mib:$maxDownloadMiB},
              tools:{
                ukify:{executable:$ukify,environment:{}},
                systemd_measure:{executable:$measure,environment:{}},
                objcopy:{executable:$objcopy,environment:{}},
                sign_file:{executable:$signFile,environment:{}},
                mkfs_erofs:{executable:$mkfsErofs,environment:{LD_LIBRARY_PATH:$gccLib}},
                fsck_erofs:{executable:$fsckErofs,environment:{}},
                veritysetup:{executable:$veritysetup,environment:{}},
                qemu_img:{executable:$qemuImg,environment:{}},
                sfdisk:{executable:$sfdisk,environment:{}},
                mkfs_vfat:{executable:$mkfsVfat,environment:{}},
                mcopy:{executable:$mcopy,environment:{MTOOLS_SKIP_CHECK:"1"}},
                zstd:{executable:$zstd,environment:{}},
                cpio:{executable:$cpio,environment:{}},
                tar:{executable:$tar,environment:{}},
                find:{executable:$find,environment:{}},
                openssl:{executable:$openssl,environment:{}},
                sbverify:{executable:$sbverify,environment:{}},
                modinfo:{executable:$modinfo,environment:{}}}}' \
            > "$out/assembly-recipe.json.tmp"
          recipe_size=$(stat -c %s "$out/assembly-recipe.json.tmp")
          [ "$recipe_size" -gt 1 ]
          truncate -s $((recipe_size - 1)) "$out/assembly-recipe.json.tmp"
          mv "$out/assembly-recipe.json.tmp" "$out/assembly-recipe.json"
        '';
      }
    ];
    meta.description = "Public-only unsigned AOS image assembly for ${lib.system}";
  };

  imageDrv = pkgs.mkDerivation ({
      name = "aos-image-${name}";
      src = null;

      # Make the runtime closure available to the builder itself. The raw
      # image is the publication root, so it independently enforces every
      # release budget even when callers do not build the focused check.
      buildDeps =
        [
          pkgs.util-linux # sfdisk
          pkgs.e2fsprogs
          pkgs.dosfstools # mkfs.vfat
          pkgs.mtools # mcopy
          pkgs.coreutils
          pkgs.jq
          pkgs.zstd
          runtimeClosureAudit
        ]
        ++ lib.optional localSecureBootSigning pkgs.sbsigntools
        ++ lib.optionals recoveryEnabled [pkgs.binutils pkgs.openssl]; # recovery audit + bundle signature

      ROOT_IMG = "${rootfs}/root.img";
      ROOT_SIZE_FILE = "${rootfs}/rootfs-size-bytes";
      INITRD = "${system.config.system.build.initrd}/initrd.img";
      UKI_PATH = "${ukiA}/${ukiAStoreFilename}";
      UKI_B_PATH = "${ukiB}/${ukiBStoreFilename}";
      RECOVERY_A_PATH =
        if recoveryEnabled
        then "${recoveryUkiA}/aos-${name}-recovery-a-${version}.efi"
        else "";
      RECOVERY_B_PATH =
        if recoveryEnabled
        then "${recoveryUkiB}/aos-${name}-recovery-b-${version}.efi"
        else "";
      UKI_MEASUREMENT_PATH = "${ukiA}/${ukiAStoreFilename}.measurement";
      UKI_MEASUREMENT_SIG_PATH = "${ukiA}/${ukiAStoreFilename}.measurement.sig";
      SDBOOT_DIR = "${pkgs.systemd}/lib/systemd/boot/efi";
      IMAGE_NAME = name;
      IMAGE_FILENAME = "aos-${name}.img.zst";
      IMAGE_VERSION = version;
      IMAGE_ARCHITECTURE = lib.platform.constraints.cpu;
      IMAGE_PLATFORM = lib.system;
      IMAGE_KERNEL_PARAMS = kernelParams;
      IMAGE_ROOT_FS_TYPE = rootFsType;
      MAX_ROOT_MIB = toString budgets.maxRootMiB;
      ROOT_PARTITION_MIB = toString system.config.aos.image.rootPartitionMiB;
      MAX_VERITY_MIB = toString budgets.maxVerityMiB;
      MAX_INITRD_MIB = toString budgets.maxInitrdMiB;
      MAX_UKI_MIB = toString budgets.maxUkiMiB;
      MAX_ESP_MIB = toString budgets.maxEspMiB;
      MAX_RUNTIME_CLOSURE_MIB = toString budgets.maxRuntimeClosureMiB;
      MAX_DOWNLOAD_MIB = toString budgets.maxDownloadMiB;
      RUNTIME_CLOSURE_REPORT = "${runtimeClosureAudit}/report.json";
      IMAGE_MODULE_ABI = toString system.config.aos.system.moduleAbi;
      RECOVERY_ENABLE = lib.optionalString recoveryEnabled "1";
      RECOVERY_ABI = toString recovery.abi;
      RECOVERY_CMDLINE = recoveryCmdline;
      IMAGE_UKI_PATH = "EFI/Linux/${espUkiFilename}";
      IMAGE_UKI_FILENAME = espUkiFilename;
      IMAGE_SDBOOT_PATH = "EFI/systemd/${efiName.systemd}";
      SDBOOT_FILENAME = efiName.systemd;
      UEFI_FALLBACK_FILENAME = efiName.fallback;
      UKI_MEASURED =
        if sb.measuredBoot.enable
        then "1"
        else "";

      # Secure Boot signing inputs (empty unless enabled). The UKI is
      # already signed by aos-uki; sd-boot is signed here, in place.
      SB_ENABLE =
        if localSecureBootSigning
        then "1"
        else "";
      SB_KEY =
        if localSecureBootSigning
        then sb.dbKey
        else "";
      SB_CERT =
        if sb.enable
        then dbCertificate
        else "";

      phases = [
        {
          name = "build-image";
          script = ''
            set -eu
            echo "==> Building UEFI-bootable disk image for AOS ${name}"

            # ── 1. Root image from the shared rootfs helper ─────────────
            cp "$ROOT_IMG" root.img
            chmod u+w root.img
            root_bytes=$(cat "$ROOT_SIZE_FILE")
            if [ $(( root_bytes % 512 )) -ne 0 ]; then
              echo "root image size must be sector-aligned" >&2
              exit 1
            fi
            if [ "$root_bytes" -gt $(( MAX_ROOT_MIB * 1048576 )) ]; then
              echo "root image exceeds its $MAX_ROOT_MIB MiB artifact contract" >&2
              exit 1
            fi
            initrd_bytes=$(stat -c %s "$INITRD")
            if [ "$initrd_bytes" -gt $(( MAX_INITRD_MIB * 1048576 )) ]; then
              echo "initrd exceeds its $MAX_INITRD_MIB MiB artifact contract" >&2
              exit 1
            fi
            runtime_closure_bytes=$(jq -er '.actual.closureBytes' "$RUNTIME_CLOSURE_REPORT")
            echo "    root image: $(( root_bytes / 1048576 )) MiB"

            # ── 2. ESP tree ─────────────────────────────────────────────
            echo "==> Populating ESP tree"
            mkdir -p esp/EFI/BOOT
            mkdir -p esp/EFI/AOS
            mkdir -p esp/EFI/systemd
            mkdir -p esp/EFI/Linux
            mkdir -p esp/loader/entries

            # sd-boot at both canonical and UEFI fallback paths. Firmware
            # that isn't told about a specific EFI application falls back
            # to the architecture's /EFI/BOOT/BOOT<ARCH>.EFI removable-media
            # path; the canonical sd-boot filename is architecture-specific. Under
            # Secure Boot both copies are db-signed (RFC-0006); the UKI is
            # already signed by aos-uki.
            if [ -n "$SB_ENABLE" ]; then
              echo "==> Signing sd-boot for Secure Boot"
              sbsign --key "$SB_KEY" --cert "$SB_CERT" \
                --output "esp/EFI/BOOT/$UEFI_FALLBACK_FILENAME" "$SDBOOT_DIR/$SDBOOT_FILENAME"
              cp "esp/EFI/BOOT/$UEFI_FALLBACK_FILENAME" "esp/EFI/systemd/$SDBOOT_FILENAME"
            else
              cp "$SDBOOT_DIR/$SDBOOT_FILENAME" "esp/EFI/BOOT/$UEFI_FALLBACK_FILENAME"
              cp "$SDBOOT_DIR/$SDBOOT_FILENAME" "esp/EFI/systemd/$SDBOOT_FILENAME"
            fi

            # UKI auto-discovered by sd-boot from /EFI/Linux/. The ESP filename
            # carries the boot-counting tries suffix when enabled.
            cp "$UKI_PATH" esp/EFI/Linux/${espUkiFilename}
            ${lib.optionalString sb.measuredBoot.enable ''
              cp "$UKI_MEASUREMENT_PATH" \
                esp/EFI/Linux/${espUkiFilename}.measurement
              cp "$UKI_MEASUREMENT_SIG_PATH" \
                esp/EFI/Linux/${espUkiFilename}.measurement.sig
            ''}

            ${lib.optionalString recoveryEnabled ''
              # Recovery entries are explicit Type-1 entries. Their filenames
              # never match the normal `aos-*.efi` default selector and carry
              # no sd-boot tries suffix, so entering recovery cannot consume
              # or reset a normal candidate's attempt counter.
              cp "$RECOVERY_A_PATH" esp/EFI/AOS/recovery-a.efi
              cp "$RECOVERY_B_PATH" esp/EFI/AOS/recovery-b.efi
              for recovery_uki in "$RECOVERY_A_PATH" "$RECOVERY_B_PATH"; do
                objcopy -O binary --only-section=.cmdline "$recovery_uki" recovery.cmdline
                recovery_cmdline=$(tr -d '\000' < recovery.cmdline)
                if [ "$recovery_cmdline" != "$RECOVERY_CMDLINE" ]; then
                  echo "recovery UKI carries a noncanonical command line" >&2
                  exit 1
                fi
                rm -f recovery.pcrsig
                objcopy -O binary --only-section=.pcrsig "$recovery_uki" recovery.pcrsig 2>/dev/null || true
                if [ -s recovery.pcrsig ]; then
                  echo "recovery UKI must not carry normal PCR authorization" >&2
                  exit 1
                fi
              done
              cat > esp/loader/entries/recovery-a.conf <<RECOVERY_A_ENTRY
              title AOS Recovery A ($IMAGE_VERSION)
              efi /EFI/AOS/recovery-a.efi
              RECOVERY_A_ENTRY
              cat > esp/loader/entries/recovery-b.conf <<RECOVERY_B_ENTRY
              title AOS Recovery B ($IMAGE_VERSION)
              efi /EFI/AOS/recovery-b.efi
              RECOVERY_B_ENTRY
            ''}

            # sd-boot configuration. The `default aos-*.efi` pattern selects
            # the newest live counted image while sorting an exhausted image
            # behind the known-good slot. Staging clears any exact persistent
            # default so this fallback ordering remains effective; explicit
            # rollback pins a known-good entry with `bootctl set-default`.
            cat > esp/loader/loader.conf <<LOADER
            default aos-*.efi
            timeout 3
            console-mode max
            editor no
            LOADER

            # ── 3. Create vfat ESP image ────────────────────────────────
            # FAT32 is what UEFI reads. mkfs.vfat has no -d flag, so we
            # create an empty image, then use mtools mcopy -s to populate
            # it from the esp/ directory — sandbox-compatible, no loopback
            # mount needed. MTOOLS_SKIP_CHECK=1 is required because mcopy
            # otherwise refuses to write to a plain file with no
            # ~/.mtoolsrc entry.
            # Size the ESP from the installed set plus one complete inactive
            # publication transaction. At peak that transaction retains the
            # known-good normal UKI and both recovery copies while temporary
            # bytes hold the new normal UKI, inactive recovery copy, loader
            # entry, and measured-boot sidecars. Add 32 MiB for FAT metadata,
            # round up to MiB, and keep a 128 MiB FAT32 comfort floor.
            # Use apparent bytes rather than allocated blocks. UKIs may contain
            # sparse padding between PE sections, but FAT must store every
            # logical byte when the file is copied onto the ESP.
            esp_content_bytes=$(du -sb esp | cut -f1)
            transaction_bytes=$(stat -c %s "$UKI_B_PATH")
            ${lib.optionalString sb.measuredBoot.enable ''
              transaction_bytes=$(( transaction_bytes + $(stat -c %s "$UKI_MEASUREMENT_PATH") ))
              transaction_bytes=$(( transaction_bytes + $(stat -c %s "$UKI_MEASUREMENT_SIG_PATH") ))
            ''}
            ${lib.optionalString recoveryEnabled ''
              transaction_bytes=$(( transaction_bytes + $(stat -c %s "$RECOVERY_B_PATH") ))
              transaction_bytes=$(( transaction_bytes + $(stat -c %s esp/loader/entries/recovery-b.conf) ))
            ''}
            esp_required_bytes=$(( esp_content_bytes + transaction_bytes + 33554432 + ${toString system.config.aos.image.espExtraFreeMiB} * 1048576 ))
            echo "$esp_content_bytes" > esp-content-bytes
            echo "$transaction_bytes" > esp-transaction-bytes
            echo "$esp_required_bytes" > esp-required-bytes
            uki_bytes=$(stat -c %s "$UKI_PATH")
            if [ "$esp_required_bytes" -gt $(( MAX_ESP_MIB * 1048576 )) ]; then
              echo "ESP payload exceeds its $MAX_ESP_MIB MiB artifact contract" >&2
              exit 1
            fi
            if [ "$uki_bytes" -gt $(( MAX_UKI_MIB * 1048576 )) ]; then
              echo "UKI exceeds its $MAX_UKI_MIB MiB artifact contract" >&2
              exit 1
            fi
            # Preserve stable partition geometry while recording the observed
            # peak transaction requirement in image-info.json.
            esp_mib=$MAX_ESP_MIB
            esp_bytes=$(( esp_mib * 1048576 ))
            esp_sectors=$(( esp_bytes / 512 ))
            root_start_sector=$(( ${toString espStartSector} + esp_sectors ))

            echo "==> Creating vfat ESP image ($esp_mib MiB)"
            truncate -s "$esp_bytes" esp.img
            mkfs.vfat -F 32 -n ESP esp.img
            export MTOOLS_SKIP_CHECK=1
            for entry in esp/*; do
              mcopy -s -i esp.img "$entry" "::"
            done

            # ── 4. Assemble final GPT image ─────────────────────────────
            root_sectors=$(( ROOT_PARTITION_MIB * 2048 ))
            # The dm-verity hash tree rides in a `root-a-hash`
            # partition immediately after root-a, sized from the build-time
            # root-verity-size-bytes and rounded up to a 1 MiB (2048-sector)
            # boundary. hash_sectors stays 0 (and the whole block is gated off)
            # on the non-verity path.
            # sfdisk aligns implicit partition starts independently. Compute
            # every start here instead so the partition table, image writes,
            # and final disk size agree even when root.img is not MiB-sized.
            hash_start_sector=$(( (root_start_sector + root_sectors + 2047) / 2048 * 2048 ))
            hash_sectors=0
            ${lib.optionalString verityEnabled ''
              verity_bytes=$(cat "$VERITY_SIZE_FILE")
              if [ "$verity_bytes" -gt $(( MAX_VERITY_MIB * 1048576 )) ]; then
                echo "verity tree exceeds its $MAX_VERITY_MIB MiB artifact contract" >&2
                exit 1
              fi
              hash_sectors=$(( MAX_VERITY_MIB * 2048 ))
              echo "    root-a-hash: $(( hash_sectors / 2048 )) MiB verity tree"
            ''}
            # 1 MiB (2048 sectors) at the start for GPT header + alignment,
            # plus 1 MiB at the end for the backup GPT header.
            root_b_start_sector=$(( (hash_start_sector + hash_sectors + 2047) / 2048 * 2048 ))
            hash_b_start_sector=$(( (root_b_start_sector + root_sectors + 2047) / 2048 * 2048 ))
            disk_sectors=$(( hash_b_start_sector + hash_sectors + 2048 ))
            disk_bytes=$(( disk_sectors * 512 ))
            echo "==> Assembling $(( disk_bytes / 1048576 )) MiB GPT image"
            truncate -s "$disk_bytes" image.raw

            # Partition 1 is the ESP (type GUID C12A7328-…); partition 2
            # is the root A slot, followed by its optional verity tree, then an
            # equally-sized empty root B slot and optional B verity tree. Swap
            # and /var are carved from the trailing unallocated space by
            # systemd-repart on first boot.
            sfdisk image.raw <<PTABLE
            label: gpt
            start=${toString espStartSector}, size=$esp_sectors, type=${espGuid}, name="ESP"
            start=$root_start_sector, size=$root_sectors, type=${rootGuid}, name="root-a"${lib.optionalString verityEnabled ''

              start=$hash_start_sector, size=$hash_sectors, type=${verityGuid}, name="root-a-hash"''}
            start=$root_b_start_sector, size=$root_sectors, type=${rootGuid}, name="root-b"${lib.optionalString verityEnabled ''

              start=$hash_b_start_sector, size=$hash_sectors, type=${verityGuid}, name="root-b-hash"''}
            PTABLE

            echo "    Writing ESP at sector ${toString espStartSector}"
            dd if=esp.img of=image.raw bs=512 seek=${toString espStartSector} conv=notrunc status=none
            echo "    Writing root at sector $root_start_sector"
            dd if=root.img of=image.raw bs=512 seek=$root_start_sector conv=notrunc status=none
            ${lib.optionalString verityEnabled ''
              echo "    Writing root-a-hash at sector $hash_start_sector"
              dd if="$VERITY_IMG" of=image.raw bs=512 seek=$hash_start_sector conv=notrunc status=none
              echo "$(( hash_sectors / 2048 ))" > hash-size-mib
            ''}

            echo "$root_bytes" > root-size-bytes
            echo "$esp_mib" > esp-size-mib
            echo "$(( ${toString espStartSector} * 512 ))" > esp-offset-bytes
            echo "$(( esp_sectors * 512 ))" > esp-partition-size-bytes
            echo "$(( root_start_sector * 512 ))" > root-offset-bytes
            echo "$(( root_sectors * 512 ))" > root-partition-size-bytes
            echo "$(( root_b_start_sector * 512 ))" > root-b-offset-bytes
            echo "$(( root_sectors * 512 ))" > root-b-partition-size-bytes
            ${lib.optionalString verityEnabled ''
              echo "$(( hash_start_sector * 512 ))" > hash-offset-bytes
              echo "$(( hash_sectors * 512 ))" > hash-partition-size-bytes
              echo "$(( hash_b_start_sector * 512 ))" > hash-b-offset-bytes
              echo "$(( hash_sectors * 512 ))" > hash-b-partition-size-bytes
            ''}
            echo "==> Image assembly complete"
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p $out
            # OTA payloads: the imported raw-image store path is also the
            # authenticated source for inactive-slot staging. These files are
            # copied to block devices/ESP without parsing the enclosing GPT.
            mv root.img $out/root.img
            cp "$UKI_PATH" $out/uki-a.efi
            cp "$UKI_B_PATH" $out/uki-b.efi
            ${lib.optionalString recoveryEnabled ''
              cp "$RECOVERY_A_PATH" $out/recovery-a.efi
              cp "$RECOVERY_B_PATH" $out/recovery-b.efi
              cp esp/loader/entries/recovery-a.conf $out/recovery-a.conf
              cp esp/loader/entries/recovery-b.conf $out/recovery-b.conf
            ''}
            ${lib.optionalString verityEnabled ''
              cp "$VERITY_IMG" $out/root.verity
              cp "$ROOT_HASH_FILE" $out/root.roothash
              cp "$ROOT_HASH_SIG_FILE" $out/root.roothash.p7s
            ''}

            # Image metadata is part of the signed sysroot image catalog's
            # publication input. Keep it next to the exact disk bytes so apr
            # can validate both before committing the catalog entry.
            root_size_bytes=$(cat root-size-bytes)
            root_size_mib=$(( root_size_bytes / 1048576 ))
            virtual_size_bytes=$(stat -c %s image.raw)
            disk_size_mib=$(( virtual_size_bytes / 1048576 ))
            logical_disk_sha256=$(sha256sum image.raw | cut -d ' ' -f1)
            uki_size_bytes=$(stat -c %s "$UKI_PATH")
            uki_sha256=$(sha256sum "$UKI_PATH" | cut -d ' ' -f1)
            ${lib.optionalString recoveryEnabled ''
              recovery_a_size_bytes=$(stat -c %s "$RECOVERY_A_PATH")
              recovery_b_size_bytes=$(stat -c %s "$RECOVERY_B_PATH")
              recovery_a_sha256=$(sha256sum "$RECOVERY_A_PATH" | cut -d ' ' -f1)
              recovery_b_sha256=$(sha256sum "$RECOVERY_B_PATH" | cut -d ' ' -f1)
            ''}
            if [ -n "$SB_ENABLE" ]; then uki_signed=true; else uki_signed=false; fi
            if [ -n "$UKI_MEASURED" ]; then uki_measured=true; else uki_measured=false; fi
            esp_size_mib=$(cat esp-size-mib)
            esp_content_bytes=$(cat esp-content-bytes)
            esp_transaction_bytes=$(cat esp-transaction-bytes)
            esp_required_bytes=$(cat esp-required-bytes)
            esp_offset_bytes=$(cat esp-offset-bytes)
            esp_partition_size_bytes=$(cat esp-partition-size-bytes)
            root_offset_bytes=$(cat root-offset-bytes)
            root_partition_size_bytes=$(cat root-partition-size-bytes)
            rootfs_sha256=$(dd if=image.raw \
              iflag=skip_bytes,count_bytes \
              skip="$root_offset_bytes" count="$root_partition_size_bytes" \
              status=none | sha256sum | cut -d ' ' -f1)
            root_b_offset_bytes=$(cat root-b-offset-bytes)
            root_b_partition_size_bytes=$(cat root-b-partition-size-bytes)
            ${lib.optionalString verityEnabled ''hash_size_mib=$(cat hash-size-mib)''}
            ${lib.optionalString verityEnabled ''hash_offset_bytes=$(cat hash-offset-bytes)''}
            ${lib.optionalString verityEnabled ''hash_partition_size_bytes=$(cat hash-partition-size-bytes)''}
            ${lib.optionalString verityEnabled ''hash_b_offset_bytes=$(cat hash-b-offset-bytes)''}
            ${lib.optionalString verityEnabled ''hash_b_partition_size_bytes=$(cat hash-b-partition-size-bytes)''}

            # The direct-delivery object is compressed as a whole so empty
            # inactive slots and fixed partition headroom cost almost nothing
            # on the wire. The logical disk digest below still authenticates
            # the exact bytes reconstructed before writing physical media.
            zstd --ultra -22 --long=27 -T1 --no-progress \
              image.raw -o "$out/$IMAGE_FILENAME"
            disk_size_bytes=$(stat -c %s "$out/$IMAGE_FILENAME")
            if [ "$disk_size_bytes" -gt $(( MAX_DOWNLOAD_MIB * 1048576 )) ]; then
              echo "compressed raw image exceeds its $MAX_DOWNLOAD_MIB MiB download contract" >&2
              exit 1
            fi
            disk_sha256=$(sha256sum "$out/$IMAGE_FILENAME" | cut -d ' ' -f1)
            ${pkgs.jq}/bin/jq -S -n \
              --arg name "$IMAGE_NAME" \
              --arg version "$IMAGE_VERSION" \
              --arg architecture "$IMAGE_ARCHITECTURE" \
              --arg platform "$IMAGE_PLATFORM" \
              --arg filename "$IMAGE_FILENAME" \
              --arg mediaType 'application/vnd.aos.disk-image.raw+zstd' \
              --arg sha256 "$disk_sha256" \
              --arg logicalDiskSha256 "$logical_disk_sha256" \
              --arg rootfsSha256 "$rootfs_sha256" \
              --arg ukiFilename "$IMAGE_UKI_FILENAME" \
              --arg ukiEspPath "$IMAGE_UKI_PATH" \
              --arg ukiSha256 "$uki_sha256" \
              --arg kernelParams "$IMAGE_KERNEL_PARAMS" \
              --arg rootFsType "$IMAGE_ROOT_FS_TYPE" \
              --arg recoveryRelease "$IMAGE_VERSION" \
              --arg recoveryCmdline "$RECOVERY_CMDLINE" \
              --arg uki "$IMAGE_UKI_PATH" \
              --arg sdBoot "$IMAGE_SDBOOT_PATH" \
              --argjson diskSizeMiB "$disk_size_mib" \
              --argjson diskSizeBytes "$virtual_size_bytes" \
              --argjson byteSize "$disk_size_bytes" \
              --argjson espSizeMiB "$esp_size_mib" \
              --argjson espContentBytes "$esp_content_bytes" \
              --argjson espTransactionBytes "$esp_transaction_bytes" \
              --argjson espRequiredBytes "$esp_required_bytes" \
              --argjson rootSizeMiB "$root_size_mib" \
              --argjson rootPartitionSizeMiB "$ROOT_PARTITION_MIB" \
              --argjson espOffsetBytes "$esp_offset_bytes" \
              --argjson espPartitionSizeBytes "$esp_partition_size_bytes" \
              --argjson rootOffsetBytes "$root_offset_bytes" \
              --argjson rootPartitionSizeBytes "$root_partition_size_bytes" \
              --argjson rootBOffsetBytes "$root_b_offset_bytes" \
              --argjson rootBPartitionSizeBytes "$root_b_partition_size_bytes" \
              --argjson ukiSizeBytes "$uki_size_bytes" \
              --argjson ukiSigned "$uki_signed" \
              --argjson ukiMeasured "$uki_measured" \
              --argjson maxRootMiB "$MAX_ROOT_MIB" \
              --argjson maxVerityMiB "$MAX_VERITY_MIB" \
              --argjson maxInitrdMiB "$MAX_INITRD_MIB" \
              --argjson maxUkiMiB "$MAX_UKI_MIB" \
              --argjson maxEspMiB "$MAX_ESP_MIB" \
              --argjson maxRuntimeClosureMiB "$MAX_RUNTIME_CLOSURE_MIB" \
              --argjson maxDownloadMiB "$MAX_DOWNLOAD_MIB" \
              --argjson moduleAbi "$IMAGE_MODULE_ABI" \
              ${lib.optionalString recoveryEnabled ''              --argjson recoveryAbi "$RECOVERY_ABI" \
                            --argjson recoveryASizeBytes "$recovery_a_size_bytes" \
                            --argjson recoveryBSizeBytes "$recovery_b_size_bytes" \
                            --arg recoveryASha256 "$recovery_a_sha256" \
                            --arg recoveryBSha256 "$recovery_b_sha256" \
            ''}${lib.optionalString verityEnabled ''              --argjson hashSizeMiB "$hash_size_mib" \
                            --argjson hashOffsetBytes "$hash_offset_bytes" \
                            --argjson hashPartitionSizeBytes "$hash_partition_size_bytes" \
                            --argjson hashBOffsetBytes "$hash_b_offset_bytes" \
                            --argjson hashBPartitionSizeBytes "$hash_b_partition_size_bytes" \
            ''}'{
                schemaVersion: 2,
                name: $name,
                version: $version,
                architecture: $architecture,
                platform: $platform,
                format: "raw",
                filename: $filename,
                mediaType: $mediaType,
                compression: "zstd",
                byteSize: $byteSize,
                virtualSizeBytes: $diskSizeBytes,
                sha256: $sha256,
                logicalDiskSha256: $logicalDiskSha256,
                rootfsSha256: $rootfsSha256,
                artifactBudgetsMiB: {
                  root: $maxRootMiB,
                  verity: $maxVerityMiB,
                  initrd: $maxInitrdMiB,
                  uki: $maxUkiMiB,
                  esp: $maxEspMiB,
                  runtimeClosure: $maxRuntimeClosureMiB,
                  download: $maxDownloadMiB
                },
                moduleAbi: $moduleAbi,
                compatibleTargets: ["bare-metal"],
                uki: {
                  filename: $ukiFilename,
                  espPath: $ukiEspPath,
                  byteSize: $ukiSizeBytes,
                  sha256: $ukiSha256,
                  signed: $ukiSigned,
                  measured: $ukiMeasured
                },
                diskSizeMiB: $diskSizeMiB,
                espSizeMiB: $espSizeMiB,
                espBudget: {
                  installedBytes: $espContentBytes,
                  transactionBytes: $espTransactionBytes,
                  requiredBytes: $espRequiredBytes,
                  partitionBytes: $espPartitionSizeBytes
                },
                rootSizeMiB: $rootSizeMiB,
                partitionTable: "gpt",
                kernelParams: $kernelParams,
                partitions: [
                  {number: 1, label: "ESP", type: "esp", filesystem: "vfat", sizeMiB: $espSizeMiB, offsetBytes: $espOffsetBytes, sizeBytes: $espPartitionSizeBytes},
                  {number: 2, label: "root-a", type: "root", filesystem: $rootFsType, sizeMiB: $rootPartitionSizeMiB, offsetBytes: $rootOffsetBytes, sizeBytes: $rootPartitionSizeBytes},
                  {number: ${
              if verityEnabled
              then "4"
              else "3"
            }, label: "root-b", type: "root", filesystem: $rootFsType, sizeMiB: $rootPartitionSizeMiB, offsetBytes: $rootBOffsetBytes, sizeBytes: $rootBPartitionSizeBytes}
                ],
                esp: {uki: $uki, sdBoot: $sdBoot}
              }${lib.optionalString recoveryEnabled ''
              | .recovery = {
                  abi: $recoveryAbi,
                  release: $recoveryRelease,
                  commandLine: $recoveryCmdline,
                  copies: {
                    A: {espPath: "EFI/AOS/recovery-a.efi", byteSize: $recoveryASizeBytes, sha256: $recoveryASha256},
                    B: {espPath: "EFI/AOS/recovery-b.efi", byteSize: $recoveryBSizeBytes, sha256: $recoveryBSha256}
                  },
                  entries: {
                    A: "loader/entries/recovery-a.conf",
                    B: "loader/entries/recovery-b.conf"
                  }
                }''}${lib.optionalString verityEnabled ''
              | .partitions += [
                  {number: 3, label: "root-a-hash", type: "verity", filesystem: "dm-verity", sizeMiB: $hashSizeMiB, offsetBytes: $hashOffsetBytes, sizeBytes: $hashPartitionSizeBytes},
                  {number: 5, label: "root-b-hash", type: "verity", filesystem: "dm-verity", sizeMiB: $hashSizeMiB, offsetBytes: $hashBOffsetBytes, sizeBytes: $hashBPartitionSizeBytes}
                ]''}' \
              > $out/image-info.json

            ${lib.optionalString recoveryEnabled ''
              component() {
                id=$1
                path=$2
                size=$(stat -c %s "$out/$path")
                digest=$(sha256sum "$out/$path" | cut -d ' ' -f1)
                ${pkgs.jq}/bin/jq -n \
                  --arg id "$id" --arg path "$path" \
                  --argjson byteSize "$size" --arg sha256 "$digest" \
                  '{id: $id, path: $path, byte_size: $byteSize, sha256: $sha256}'
              }
              components=$(
                {
                  component root-image root.img
                  component root-verity root.verity
                  component root-hash root.roothash
                  component normal-uki-a uki-a.efi
                  component normal-uki-b uki-b.efi
                  component recovery-uki-a recovery-a.efi
                  component recovery-uki-b recovery-b.efi
                  component recovery-entry-a recovery-a.conf
                  component recovery-entry-b recovery-b.conf
                  component image-metadata image-info.json
                } | ${pkgs.jq}/bin/jq -s .
              )
              ${pkgs.jq}/bin/jq -S -n \
                --arg schema aos.recovery-bundle/v1 \
                --arg release "$IMAGE_VERSION" \
                --arg architecture "$IMAGE_ARCHITECTURE" \
                --arg platform "$IMAGE_PLATFORM" \
                --argjson module_abi "$IMAGE_MODULE_ABI" \
                --argjson recovery_abi "$RECOVERY_ABI" \
                --argjson components "$components" \
                '{schema: $schema, release: $release, architecture: $architecture,
                  platform: $platform, module_abi: $module_abi,
                  recovery_abi: $recovery_abi, components: $components}' \
                > $out/recovery-bundle.json
              ${pkgs.openssl}/bin/openssl dgst -sha256 \
                -sign ${sb.dbKey} \
                -out $out/recovery-bundle.json.sig \
                $out/recovery-bundle.json
              ${pkgs.openssl}/bin/openssl x509 -pubkey -noout \
                -in ${dbCertificate} > recovery-bundle-public.pem
              ${pkgs.openssl}/bin/openssl dgst -sha256 \
                -verify recovery-bundle-public.pem \
                -signature $out/recovery-bundle.json.sig \
                $out/recovery-bundle.json
            ''}
          '';
        }
      ];
    }
    // lib.optionalAttrs verityEnabled {
      # Verity inputs are present only when verity is on, so the
      # non-verity image derivation's environment — and hash — is unchanged.
      VERITY_IMG = "${rootfs}/root.verity";
      VERITY_SIZE_FILE = "${rootfs}/root-verity-size-bytes";
      ROOT_HASH_FILE = "${rootfs}/root.roothash";
      ROOT_HASH_SIG_FILE = "${rootfs}/root.roothash.p7s";
    });
  recoveryBundle =
    if recoveryEnabled
    then
      pkgs.mkDerivation {
        pname = "aos-recovery-bundle";
        inherit version;
        src = null;
        buildDeps = [pkgs.coreutils];
        runtimeDeps = [];
        propagatedDeps = [];
        phases = [
          {
            name = "install";
            script = ''
              destination=$out/aos/recovery
              mkdir -p "$destination"
              for component in \
                root.img root.verity root.roothash \
                uki-a.efi uki-b.efi \
                recovery-a.efi recovery-b.efi \
                recovery-a.conf recovery-b.conf \
                image-info.json recovery-bundle.json recovery-bundle.json.sig; do
                cp "${imageDrv}/$component" "$destination/$component"
              done
            '';
          }
        ];
      }
    else null;
in
  # Expose the assembled UKI (the exact `.efi` written to the ESP) as a
  # passthru attribute so callers can publish or measure it directly
  # (RFC-0006 phase 4: `apr publish --image <uki>` derives Secure Boot
  # facts from this signed binary).
  (
    if externalFinalization
    then unsignedAssembly
    else imageDrv
  )
  // {
    inherit unsignedAssembly;
    inherit rootfs uki ukiA ukiB ukiAStoreFilename ukiBStoreFilename;
    recoveryInitrdA = recoveryInitrdA;
    recoveryInitrdB = recoveryInitrdB;
    recoverySlotManifest = recoverySlotManifest;
    recoveryUkiA = recoveryUkiA;
    recoveryUkiB = recoveryUkiB;
    recoveryBundle = recoveryBundle;
  }
