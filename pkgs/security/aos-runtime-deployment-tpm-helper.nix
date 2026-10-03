##! Fixed deployment-only ESYS carrier over the shared private NV mechanics.
{
  mkDerivation,
  tpm2-tss,
  openssl,
  coreutils,
  stdenv,
}: let
  pinnedTssVersion = "4.2.0";
in
  assert tpm2-tss.version == pinnedTssVersion;
    mkDerivation {
      pname = "aos-runtime-deployment-tpm-helper";
      version = "0.1.0";
      src = ./aos-method46-tpm-helper;
      dontStrip = true;

      buildDeps = [coreutils];
      runtimeDeps = [tpm2-tss openssl];
      propagatedDeps = [];

      phases = [
        {
          name = "unpack";
          script = ''
            cp -R $src source
            chmod -R u+w source
            cd source
          '';
        }
        {
          name = "build";
          script = ''
            $CC -std=c17 -O2 -Wall -Wextra -Werror \
              -I${tpm2-tss}/include/tss2 \
              runtime_deployment.c nv_esys.c \
              -L${tpm2-tss}/lib -ltss2-esys -ltss2-sys -ltss2-tcti-device -ltss2-mu -lcrypto \
              -Wl,-rpath,${tpm2-tss}/lib -o aos-runtime-deployment-tpm-helper
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p $out/libexec
            cp aos-runtime-deployment-tpm-helper $out/libexec/
            $STRIP -s $out/libexec/aos-runtime-deployment-tpm-helper
            chmod 0555 $out/libexec/aos-runtime-deployment-tpm-helper
            sha256sum $out/libexec/aos-runtime-deployment-tpm-helper | cut -d ' ' -f 1 \
              > $out/libexec/aos-runtime-deployment-tpm-helper.sha256
            chmod 0444 $out/libexec/aos-runtime-deployment-tpm-helper.sha256

            loader=$(cat ${stdenv.cc}/nix-support/dynamic-linker)
            loader=$(readlink -f "$loader")
            printf '%s\n' "$loader" > $out/libexec/aos-runtime-deployment-tpm-helper.loader
            sha256sum "$loader" | cut -d ' ' -f 1 \
              >> $out/libexec/aos-runtime-deployment-tpm-helper.loader
            chmod 0444 $out/libexec/aos-runtime-deployment-tpm-helper.loader
          '';
        }
      ];

      passthru.evidenceSources = [
        ./aos-runtime-deployment-tpm-helper.nix
        ./aos-method46-tpm-helper/runtime_deployment.c
        ./aos-method46-tpm-helper/nv_esys.c
        ./aos-method46-tpm-helper/nv_esys.h
      ];
    }
