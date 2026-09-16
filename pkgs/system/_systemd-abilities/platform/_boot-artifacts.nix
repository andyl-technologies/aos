##! Package-owned systemd boot artifacts.
##!
##! Owns systemd-boot executable naming, UKI construction, recovery initrds,
##! Type-1 recovery entries, loader policy, and boot-counting filenames. The
##! generic image assembler consumes the resulting closed artifact record.
{
  pkgs,
  lib,
  system,
  name,
  kernel,
  rootfs,
  activeImageDbCerts,
  normalArtifactPath,
  targetPlatform,
}: let
  config = system.config;
  version = config.aos.system.version;
  kernelParams = lib.concatStringsSep " " config.aos.boot.kernelParams;
  kernelParamsB =
    builtins.replaceStrings
    [
      config.aos.boot.storage.resolvedDevices.rootAHash
      config.aos.boot.storage.resolvedDevices.rootA
    ]
    [
      config.aos.boot.storage.resolvedDevices.rootBHash
      config.aos.boot.storage.resolvedDevices.rootB
    ]
    kernelParams;

  sb = config.aos.boot.secureBoot;
  externalFinalization = sb.externalFinalization.enable;
  localSecureBootSigning = sb.enable && !externalFinalization;
  dbCertificate = sb._effectiveDbCert;
  pcrPublicKey = sb.measuredBoot._effectivePcrPublicKey;
  verityEnabled = config.aos.security.verity.enable;
  recovery = config.aos.boot.recovery;
  recoveryEnabled = recovery.enable;

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
    efiNames.${targetPlatform.cpu}
    or (throw "systemd-boot has no UEFI executable names for ${targetPlatform.system}");

  espUkiFilename = builtins.baseNameOf normalArtifactPath;

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
      AOS_STATE_VERSION=${config.aos.system.stateVersion}
      AOS_MODULE_ABI=${toString config.aos.system.moduleAbi}
      AOS_BASELIB_ABI_HASH=${config.aos.config.evalAtBoot.baseLibAbiHash}
    '';
  };

  mkUki = slotName: cmdline:
    pkgs.aos-uki {
      name = "${name}-slot-${slotName}";
      inherit version cmdline;
      kernel = kernel.package;
      initrd = config.system.build.initrd;
      osRelease = "${ukiOsRelease}/os-release";
      secureBootKey =
        if localSecureBootSigning
        then sb.dbKey
        else null;
      secureBootCert =
        if sb.enable
        then dbCertificate
        else null;
      pcrPrivateKey =
        if sb.measuredBoot.enable && !externalFinalization
        then sb.measuredBoot.pcrPrivateKey
        else null;
      pcrPublicKey =
        if sb.measuredBoot.enable && !externalFinalization
        then pcrPublicKey
        else null;
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
                '{schema: $schema, release: $release, recoveryAbi: $recoveryAbi,
                  slots: {
                    A: {rootData: "/dev/disk/by-partlabel/root-a",
                      rootHashDevice: "/dev/disk/by-partlabel/root-a-hash",
                      rootHash: $rootHash, ukiSha256: $ukiASha256},
                    B: {rootData: "/dev/disk/by-partlabel/root-b",
                      rootHashDevice: "/dev/disk/by-partlabel/root-b-hash",
                      rootHash: $rootHash, ukiSha256: $ukiBSha256}}}' \
                > $out/slot-manifest.json
              ${pkgs.openssl}/bin/openssl dgst -sha256 \
                -sign ${sb.dbKey} -out $out/slot-manifest.json.sig \
                $out/slot-manifest.json
              ${pkgs.openssl}/bin/openssl x509 -pubkey -noout \
                -in ${dbCertificate} > db-public.pem
              ${pkgs.openssl}/bin/openssl dgst -sha256 \
                -verify db-public.pem -signature $out/slot-manifest.json.sig \
                $out/slot-manifest.json
            '';
          }
        ];
      }
    else null;

  mkRecoveryInitrd = copy:
    import ./_recovery-initrd-builder.nix {
      inherit pkgs lib;
      kernel = kernel.package;
      loadModules = config.aos.boot.initrd.loadModules;
      dbCert = dbCertificate;
      authorizedDbCerts = "${activeImageDbCerts}/active-db-certs.pem";
      slotManifest = recoverySlotManifest;
      recoveryCopy = lib.toUpper copy;
      recoveryAbi = recovery.abi;
      platform = targetPlatform.system;
      moduleAbi = config.aos.system.moduleAbi;
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
  recoveryOsReleaseA = mkRecoveryOsRelease "a";
  recoveryOsReleaseB = mkRecoveryOsRelease "b";
  mkRecoveryUki = copy:
    pkgs.aos-uki {
      name = "${name}-recovery-${copy}";
      inherit version;
      cmdline = recoveryCmdline;
      kernel = kernel.package;
      initrd =
        if copy == "a"
        then recoveryInitrdA
        else recoveryInitrdB;
      osRelease = "${if copy == "a" then recoveryOsReleaseA else recoveryOsReleaseB}/os-release";
      secureBootKey =
        if localSecureBootSigning
        then sb.dbKey
        else null;
      secureBootCert =
        if localSecureBootSigning
        then dbCertificate
        else null;
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

  espTree = pkgs.mkDerivation {
    pname = "aos-systemd-boot-artifacts-${name}";
    inherit version;
    src = null;
    buildDeps =
      [pkgs.coreutils]
      ++ lib.optional localSecureBootSigning pkgs.sbsigntools
      ++ lib.optional recoveryEnabled pkgs.binutils;
    runtimeDeps = [];
    propagatedDeps = [];
    phases = [
      {
        name = "install";
        script = ''
          set -eu
          mkdir -p $out/esp/EFI/BOOT $out/esp/EFI/AOS
          mkdir -p $out/esp/EFI/systemd $out/esp/EFI/Linux
          mkdir -p $out/esp/loader/entries

          ${
            if localSecureBootSigning
            then ''
              sbsign --key ${sb.dbKey} --cert ${dbCertificate} \
                --output $out/esp/EFI/BOOT/${efiName.fallback} \
                ${pkgs.systemd}/lib/systemd/boot/efi/${efiName.systemd}
              cp $out/esp/EFI/BOOT/${efiName.fallback} \
                $out/esp/EFI/systemd/${efiName.systemd}
            ''
            else ''
              cp ${pkgs.systemd}/lib/systemd/boot/efi/${efiName.systemd} \
                $out/esp/EFI/BOOT/${efiName.fallback}
              cp ${pkgs.systemd}/lib/systemd/boot/efi/${efiName.systemd} \
                $out/esp/EFI/systemd/${efiName.systemd}
            ''
          }
          cp ${ukiA}/${ukiAStoreFilename} $out/esp/EFI/Linux/${espUkiFilename}
          ${lib.optionalString sb.measuredBoot.enable ''
            cp ${ukiA}/${ukiAStoreFilename}.measurement \
              $out/esp/EFI/Linux/${espUkiFilename}.measurement
            cp ${ukiA}/${ukiAStoreFilename}.measurement.sig \
              $out/esp/EFI/Linux/${espUkiFilename}.measurement.sig
          ''}

          ${lib.optionalString recoveryEnabled ''
            cp ${recoveryUkiA}/aos-${name}-recovery-a-${version}.efi \
              $out/esp/EFI/AOS/recovery-a.efi
            cp ${recoveryUkiB}/aos-${name}-recovery-b-${version}.efi \
              $out/esp/EFI/AOS/recovery-b.efi
            for recovery_uki in \
              ${recoveryUkiA}/aos-${name}-recovery-a-${version}.efi \
              ${recoveryUkiB}/aos-${name}-recovery-b-${version}.efi; do
              objcopy -O binary --only-section=.cmdline "$recovery_uki" recovery.cmdline
              recovery_cmdline=$(tr -d '\000' < recovery.cmdline)
              if [ "$recovery_cmdline" != ${lib.escapeShellArg recoveryCmdline} ]; then
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
            cat > $out/esp/loader/entries/recovery-a.conf <<ENTRY
            title AOS Recovery A (${version})
            efi /EFI/AOS/recovery-a.efi
            ENTRY
            cat > $out/esp/loader/entries/recovery-b.conf <<ENTRY
            title AOS Recovery B (${version})
            efi /EFI/AOS/recovery-b.efi
            ENTRY
          ''}

          cat > $out/esp/loader/loader.conf <<LOADER
          default aos-*.efi
          timeout 3
          console-mode max
          editor no
          LOADER

          transaction_bytes=$(stat -c %s ${ukiB}/${ukiBStoreFilename})
          ${lib.optionalString sb.measuredBoot.enable ''
            transaction_bytes=$((transaction_bytes + $(stat -c %s ${ukiA}/${ukiAStoreFilename}.measurement)))
            transaction_bytes=$((transaction_bytes + $(stat -c %s ${ukiA}/${ukiAStoreFilename}.measurement.sig)))
          ''}
          ${lib.optionalString recoveryEnabled ''
            transaction_bytes=$((transaction_bytes + $(stat -c %s ${recoveryUkiB}/aos-${name}-recovery-b-${version}.efi)))
            transaction_bytes=$((transaction_bytes + $(stat -c %s $out/esp/loader/entries/recovery-b.conf)))
          ''}
          printf '%s\n' "$transaction_bytes" > $out/transaction-size-bytes
        '';
      }
    ];
  };
in {
  inherit
    dbCertificate
    espTree
    espUkiFilename
    kernelParams
    kernelParamsB
    localSecureBootSigning
    pcrPublicKey
    recoveryCmdline
    recoveryEnabled
    recoveryInitrdA
    recoveryInitrdB
    recoveryOsReleaseA
    recoveryOsReleaseB
    recoverySlotManifest
    recoveryUkiA
    recoveryUkiB
    ukiA
    ukiB
    ukiAStoreFilename
    ukiBStoreFilename
    ukiOsRelease
    ;
  bootManagerExecutable = "${pkgs.systemd}/lib/systemd/boot/efi/${efiName.systemd}";
  bootManagerExecutableName = efiName.systemd;
  bootManagerEspPath = "EFI/systemd/${efiName.systemd}";
  fallbackExecutableName = efiName.fallback;
  measureExecutable = "${pkgs.systemd}/lib/systemd/systemd-measure";
  normalUkiEspPath = normalArtifactPath;
  recoveryEntryAPath = "loader/entries/recovery-a.conf";
  recoveryEntryBPath = "loader/entries/recovery-b.conf";
  recoveryUkiAEspPath = "EFI/AOS/recovery-a.efi";
  recoveryUkiBEspPath = "EFI/AOS/recovery-b.efi";
  ukiStubExecutable = "${pkgs.systemd}/lib/systemd/boot/efi/linux${
    if targetPlatform.cpu == "x86_64"
    then "x64"
    else "aa64"
  }.efi.stub";
  ukifyExecutable = "${pkgs.systemd.tools}/bin/ukify";
}
