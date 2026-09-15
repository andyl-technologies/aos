{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  openssl,
}: let
  version = "4.2.0";
in
  mkDerivation {
    pname = "tpm2-tss";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdint.h>\n#include <stdio.h>\n#include <tss2/tss2_mu.h>\n\nint main(void) {\n    uint8_t buffer[4];\n    size_t offset = 0;\n    UINT32 output = 0;\n\n    if (Tss2_MU_UINT32_Marshal(0x12345678U, buffer, sizeof(buffer), &offset) != TSS2_RC_SUCCESS ||\n        offset != sizeof(buffer)) {\n        return 2;\n    }\n    offset = 0;\n    if (Tss2_MU_UINT32_Unmarshal(buffer, sizeof(buffer), &offset, &output) != TSS2_RC_SUCCESS ||\n        output != 0x12345678U) {\n        return 2;\n    }\n    return puts(\"tpm2-tss api passed\") == EOF;\n}\n";
        };
        "input" = "The 32-bit value 0x12345678.";
        "operation" = "Marshal the value into TPM wire order, then unmarshal it through the TSS MU API.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ltss2-mu"
              "-o"
              "primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "tpm2-tss api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API reports rejection and the consumer exits with the fixed rejection status and diagnostic.";
        "files" = {
          "bad-input.c" = "#include <stdint.h>\n#include <stdio.h>\n#include <tss2/tss2_mu.h>\n\nint main(void) {\n    uint8_t buffer[3];\n    size_t offset = 0;\n    if (Tss2_MU_UINT32_Marshal(42U, buffer, sizeof(buffer), &offset) !=\n        TSS2_MU_RC_INSUFFICIENT_BUFFER) {\n        return 2;\n    }\n    fputs(\"tpm2-tss rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A three-byte destination buffer for a four-byte TPM UINT32.";
        "operation" = "Attempt to marshal the value into the undersized buffer.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-ltss2-mu"
              "-o"
              "bad-input-consumer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-consumer"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "tpm2-tss rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/tpm2-software/tpm2-tss/releases/download/${version}/tpm2-tss-${version}.tar.gz"
      ];
      hash = "sha256-tT8MXIxM4X8FcBpBDKloj3Jco4DJvEZA6s0OrbH+oSQ=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [openssl];
    propagatedDeps = [openssl];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd tpm2-tss-${version}
        '';
      }
      {
        # systemd links the ESYS/SYS/MU/TCTI layers only — FAPI and the
        # policy engine pull in json-c/curl and a runtime keystore we do
        # not need, so disable them. localstatedir under $out keeps
        # `make install` from writing to the host /var.
        name = "configure";
        script = ''
          # tpm2-tss's configure insists on groupadd/useradd so a distro
          # build can create the `tss` service account. We never create
          # that account (no abrmd; systemd talks to /dev/tpm directly),
          # so satisfy the check with no-op shims — `make install` does not
          # invoke them.
          mkdir -p $TMPDIR/fakebin
          for t in groupadd useradd addgroup adduser; do
            printf '#!%s\nexit 0\n' "$CONFIG_SHELL" > $TMPDIR/fakebin/$t
            chmod +x $TMPDIR/fakebin/$t
          done
          export PATH=$TMPDIR/fakebin:$PATH

          ./configure \
            $configureFlags \
            --prefix=$out \
            --localstatedir=$out/var \
            --disable-static \
            --disable-fapi \
            --disable-policy \
            --disable-doc \
            --disable-integration \
            --disable-tcti-cmd \
            --with-crypto=ossl \
            --disable-defaultflags
        '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "TPM2 Software Stack (TSS2) — ESYS/SYS/MU/TCTI libraries";
      homepage = "https://github.com/tpm2-software/tpm2-tss";
      license = "BSD-2-Clause";
    };
  }
