##! Fixed manual METHOD46 helper images with root-owned initializer custody.
{
  mkDerivation,
  tpm2-tss,
  openssl,
  coreutils,
  stdenv,
}: let
  helperSource = ./aos-method46-tpm-helper;
  roles = ["controller" "storage"];
in
  assert tpm2-tss.version == "4.2.0";
    mkDerivation {
      platformSupport = {
        build = [
          {
            abi = ["gnu"];
            os = ["linux"];
          }
        ];
        host = [
          {
            abi = ["gnu"];
            cpu = ["x86_64" "aarch64"];
            os = ["linux"];
          }
        ];
        target = [];
        role = "public-package";
      };
      pname = "aos-method46-initial-tpm-helpers";
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
            for role in controller storage; do
              case "$role" in
                controller) selection=AOS_METHOD46_INITIAL_CONTROLLER_HELPER ;;
                storage) selection=AOS_METHOD46_INITIAL_STORAGE_HELPER ;;
              esac
              $CC -std=c17 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
                -D"$selection" -I"$src" -I${tpm2-tss}/include/tss2 \
                "$src/initial_method46.c" "$src/nv_esys.c" \
                -L${tpm2-tss}/lib -ltss2-esys -ltss2-sys -ltss2-tcti-device -ltss2-mu -lcrypto \
                -Wl,-rpath,${tpm2-tss}/lib -o "aos-method46-initial-$role-tpm-helper"

              # The real private validator runs without device access. Root UID
              # transfer has a separate required-root QEMU check.
              $CC -std=c17 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror \
                -D"$selection" -I"$src" -I${tpm2-tss}/include/tss2 \
                "$src/initial-lock-owner-test.c" \
                -L${tpm2-tss}/lib -ltss2-esys -ltss2-sys -ltss2-mu -lcrypto \
                -Wl,-rpath,${tpm2-tss}/lib -o "initial-$role-lock-owner-test"
            done
          '';
        }
        {
          name = "check";
          script =
            if stdenv.isCross
            then ''
              printf '%s\n' 'Initial lock-owner regression: NOT RUN (cross-built; target execution required)' \
                > lock-owner-regression.txt
            ''
            else ''
              set -eu
              : > lock-owner-regression.txt
              for role in controller storage; do
                ./initial-$role-lock-owner-test >> lock-owner-regression.txt
              done
              cat lock-owner-regression.txt
            '';
        }
        {
          name = "install";
          script = ''
            set -eu
            mkdir -p "$out/libexec" "$out/share/aos-method46-initial-tpm-helpers"
            for role in controller storage; do
              install -m 0555 "aos-method46-initial-$role-tpm-helper" "$out/libexec/"
            done
            install -m 0444 lock-owner-regression.txt "$out/share/aos-method46-initial-tpm-helpers/"
          '';
        }
      ];

      # The parent must pin the final stripped and scrubbed executable bytes.
      postFinalize = ''
        set -eu
        loader=$(cat ${stdenv.cc}/nix-support/dynamic-linker)
        loader=$(readlink -f "$loader")
        for role in controller storage; do
          helper="$out/libexec/aos-method46-initial-$role-tpm-helper"
          sha256sum "$helper" | cut -d ' ' -f 1 > "$helper.sha256"
          printf '%s\n' "$loader" > "$helper.loader"
          sha256sum "$loader" | cut -d ' ' -f 1 >> "$helper.loader"
          chmod 0444 "$helper.sha256" "$helper.loader"
        done
      '';

      passthru = {
        inherit roles;
        evidenceSources = [
          ./aos-method46-initial-tpm-helpers.nix
          (helperSource + "/initial_method46.c")
          (helperSource + "/initial-lock-owner-test.c")
          (helperSource + "/nv_esys.c")
          (helperSource + "/nv_esys.h")
        ];
      };
      meta = {
        description = "Fixed manual initial METHOD46 TPM helpers; admission remains closed";
        license = "Apache-2.0";
        platforms = ["x86_64-linux" "aarch64-linux"];
      };
    }
