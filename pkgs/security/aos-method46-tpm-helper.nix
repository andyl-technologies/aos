##! Persistent, private TPM ESYS child for the two broker-session floor owners.
{
  mkDerivation,
  tpm2-tss,
  openssl,
  coreutils,
  stdenv,
}: let
  pinnedTssVersion = "4.2.0";
in
  # The initial-salt response-cache contract is intentionally release-specific.
  # A TSS upgrade requires reviewing and running the mock-TCTI regression first.
  assert tpm2-tss.version == pinnedTssVersion;
    mkDerivation {
      pname = "aos-method46-tpm-helper";
      version = "0.1.0";
      src = ./aos-method46-tpm-helper;
      # The pin must cover the final stripped executable, not a pre-fixup image.
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
              helper.c nv_esys.c -L${tpm2-tss}/lib -ltss2-esys -ltss2-sys -ltss2-tcti-device -ltss2-mu -lcrypto \
              -Wl,-rpath,${tpm2-tss}/lib -o aos-method46-tpm-helper

            # Includes the actual private validator; only an in-memory TCTI runs.
            $CC -std=c17 -O2 -Wall -Wextra -Werror \
              -I${tpm2-tss}/include/tss2 \
              readpublic-cache-test.c -L${tpm2-tss}/lib -ltss2-esys -ltss2-sys -ltss2-mu -lcrypto \
              -Wl,-rpath,${tpm2-tss}/lib -o readpublic-cache-test
          '';
        }
        {
          name = "check";
          script =
            if stdenv.isCross
            then ''
              printf '%s\n' 'tpm2-tss 4.2.0 ReadPublic cache regression: NOT RUN (cross-built; target execution required)' \
                > readpublic-cache-regression.txt
              cat readpublic-cache-regression.txt
            ''
            else ''
              ./readpublic-cache-test > readpublic-cache-regression.txt
              cat readpublic-cache-regression.txt
            '';
        }
        {
          name = "install";
          script = ''
            mkdir -p $out/libexec
            cp aos-method46-tpm-helper $out/libexec/
            $STRIP -s $out/libexec/aos-method46-tpm-helper
            chmod 0555 $out/libexec/aos-method46-tpm-helper
            sha256sum $out/libexec/aos-method46-tpm-helper | cut -d ' ' -f 1 \
              > $out/libexec/aos-method46-tpm-helper.sha256
            chmod 0444 $out/libexec/aos-method46-tpm-helper.sha256
            loader=$(cat ${stdenv.cc}/nix-support/dynamic-linker)
            loader=$(readlink -f "$loader")
            printf '%s\n' "$loader" > $out/libexec/aos-method46-tpm-helper.loader
            sha256sum "$loader" | cut -d ' ' -f 1 \
              >> $out/libexec/aos-method46-tpm-helper.loader
            chmod 0444 $out/libexec/aos-method46-tpm-helper.loader

            mkdir -p $out/share/aos-method46-tpm-helper
            cp readpublic-cache-regression.txt $out/share/aos-method46-tpm-helper/
            chmod 0444 $out/share/aos-method46-tpm-helper/readpublic-cache-regression.txt
          '';
        }
      ];

      passthru.evidenceSources = [
        (builtins.path {
          path = ./aos-method46-tpm-helper.nix;
          name = "aos-method46-tpm-helper.nix";
        })
        (builtins.path {
          path = ./aos-method46-tpm-helper/helper.c;
          name = "aos-method46-tpm-helper.c";
        })
        (builtins.path {
          path = ./aos-method46-tpm-helper/nv_esys.c;
          name = "aos-private-tpm-nv-esys.c";
        })
        (builtins.path {
          path = ./aos-method46-tpm-helper/nv_esys.h;
          name = "aos-private-tpm-nv-esys.h";
        })
        (builtins.path {
          path = ./aos-method46-tpm-helper/readpublic-cache-test.c;
          name = "aos-method46-tpm-readpublic-cache-test.c";
        })
      ];
    }
