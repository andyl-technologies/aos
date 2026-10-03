##! Fixed prepare-approved paired TPM producer using the sole private C engine.
{
  mkDerivation,
  tpm2-tss,
  openssl,
  coreutils,
  stdenv,
}: let
  contract = builtins.toJSON {
    version = 5;
    nativeNamespace = 76;
    nativeValueBytes = 8356;
    nativeBodyBytes = 8192;
    carrierHeaderBytes = 152;
    carrierBodyBytes = 2208;
    helloBodyBytes = 80;
    currentBodyBytes = 2320;
    originalSeconds = 300;
    contactSeconds = 30;
    cumulativeContacts = 20;
    recoveryAdmissions = 1;
    nativeTransactions = 42;
    descriptorLimit = 4096;
    childDescriptorLimit = 64;
    addressSpaceLimit = 1073741824;
    secureBits = 12;
    noNewPrivileges = true;
    rsaBits = 2048;
    rsaAttributes = 196722;
    nvAttributes = 262212;
    nvBytes = 32;
    controllerNv = 25206872;
    controllerSalt = 2164301912;
    ownerNv = 25206873;
    ownerSalt = 2164301913;
    journalLimits = {
      bytes = 4194304;
      recordBytes = 16384;
      keyBytes = 26;
      recordsPerTransaction = 2;
      transactionBytes = 33792;
      transactions = 256;
      materializedBytes = 262144;
      materializedRecords = 32;
    };
    sources = {
      entry = builtins.hashFile "sha256" ./aos-method46-tpm-helper/offline_nix.c;
      engine = builtins.hashFile "sha256" ./aos-method46-tpm-helper/nv_esys.c;
      header = builtins.hashFile "sha256" ./aos-method46-tpm-helper/nv_esys.h;
    };
  };
in
  assert tpm2-tss.version == "4.2.0";
  assert openssl.version == "4.0.2";
    mkDerivation {
      pname = "aos-nix-offline-tpm-helper";
      version = "5";
      src = ./aos-method46-tpm-helper;
      dontStrip = true;

      buildDeps = [coreutils];
      runtimeDeps = [tpm2-tss openssl];
      propagatedDeps = [];
      offlineContract = contract;
      passAsFile = ["offlineContract"];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R "$src" source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "build";
          script = ''
            $CC -std=c17 -O2 -Wall -Wextra -Werror \
              '-DAOS_NIX_OFFLINE_COMPILED_CONTRACT="${builtins.hashString "sha256" contract}"' \
              -I${tpm2-tss}/include/tss2 \
              offline_nix.c nv_esys.c -L${tpm2-tss}/lib \
              -ltss2-esys -ltss2-sys -ltss2-tcti-device -ltss2-mu -lcrypto \
              -Wl,-rpath,${tpm2-tss}/lib -o aos-nix-offline-tpm-helper
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/libexec"
            cp aos-nix-offline-tpm-helper "$out/libexec/"
            $STRIP -s "$out/libexec/aos-nix-offline-tpm-helper"
            chmod 0555 "$out/libexec/aos-nix-offline-tpm-helper"
            sha256sum "$out/libexec/aos-nix-offline-tpm-helper" | cut -d ' ' -f 1 \
              > "$out/libexec/aos-nix-offline-tpm-helper.sha256"

            loader=$(cat ${stdenv.cc}/nix-support/dynamic-linker)
            loader=$(readlink -f "$loader")
            printf '%s\n' "$loader" > "$out/libexec/aos-nix-offline-tpm-helper.loader"
            sha256sum "$loader" | cut -d ' ' -f 1 \
              >> "$out/libexec/aos-nix-offline-tpm-helper.loader"
            cp "$offlineContractPath" "$out/libexec/aos-nix-offline-tpm-helper.contract"
            sha256sum "$out/libexec/aos-nix-offline-tpm-helper.contract" | cut -d ' ' -f 1 \
              > "$out/libexec/aos-nix-offline-tpm-helper.contract.sha256"
            chmod 0444 "$out/libexec/"*.sha256 "$out/libexec/"*.loader "$out/libexec/"*.contract
          '';
        }
      ];

      passthru = {
        inherit contract;
        contractSha256 = builtins.hashString "sha256" contract;
        evidenceSources = [
          ./aos-nix-offline-tpm-helper.nix
          ./aos-method46-tpm-helper/offline_nix.c
          ./aos-method46-tpm-helper/nv_esys.c
          ./aos-method46-tpm-helper/nv_esys.h
        ];
      };
    }
