##! Fixed existing-only consumers of independently provisioned ONLINE058/059.
{
  mkDerivation,
  tpm2-tss,
  openssl,
  coreutils,
  stdenv,
}: let
  helperSource = ./aos-method46-tpm-helper;
  roles = ["controller" "owner"];
in
  assert tpm2-tss.version == "4.2.0";
    mkDerivation {
      pname = "aos-nix-runtime-tpm-helpers";
      version = "1";
      src = helperSource;
      buildDeps = [coreutils];
      runtimeDeps = [tpm2-tss openssl];
      propagatedDeps = [];

      phases = [
        {
          name = "build";
          script = ''
            set -eu
            for role in controller owner; do
              case "$role" in
                controller) selection=AOS_NIX_CONTROLLER_HELPER ;;
                owner) selection=AOS_NIX_OWNER_HELPER ;;
              esac
              $CC -std=c17 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
                -D"$selection" -I"$src" -I${tpm2-tss}/include/tss2 \
                "$src/runtime_nix.c" "$src/nv_esys.c" \
                -L${tpm2-tss}/lib -ltss2-esys -ltss2-sys -ltss2-tcti-device -ltss2-mu -lcrypto \
                -Wl,-rpath,${tpm2-tss}/lib -o "aos-nix-$role-tpm-helper"
            done
          '';
        }
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out/libexec"
            for role in controller owner; do
              install -m 0555 "aos-nix-$role-tpm-helper" "$out/libexec/"
            done
          '';
        }
      ];

      # Pins cover the real final stripped/scrubbed images, not build products.
      postFinalize = ''
        set -eu
        loader=$(cat ${stdenv.cc}/nix-support/dynamic-linker)
        loader=$(readlink -f "$loader")
        for role in controller owner; do
          helper="$out/libexec/aos-nix-$role-tpm-helper"
          sha256sum "$helper" | cut -d ' ' -f 1 > "$helper.sha256"
          printf '%s\n' "$loader" > "$helper.loader"
          sha256sum "$loader" | cut -d ' ' -f 1 >> "$helper.loader"
          chmod 0444 "$helper.sha256" "$helper.loader"
        done
      '';

      passthru = {
        inherit roles;
        evidenceSources = [
          ./aos-nix-runtime-tpm-helpers.nix
          (helperSource + "/runtime_nix.c")
          (helperSource + "/nv_esys.c")
          (helperSource + "/nv_esys.h")
        ];
      };
      meta = {
        description = "Fixed ONLINE Nix TPM consumers; external provisioning required";
        license = "Apache-2.0";
        platforms = ["x86_64-linux" "aarch64-linux"];
      };
    }
