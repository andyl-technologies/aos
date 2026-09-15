{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  nettle,
  gmp,
  libtasn1,
  libunistring,
  zlib,
}: let
  version = "3.8.13";
  majorMinor = "3.8";
in
  mkDerivation {
    pname = "gnutls";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <gnutls/gnutls.h>\n\nint main(void) {\n    gnutls_datum_t input = {(unsigned char *)\"3432\", 4};\n    gnutls_datum_t output = {0};\n    if (gnutls_hex_decode2(&input, &output) < 0\n        || output.size != 2 || memcmp(output.data, \"42\", 2) != 0) {\n        gnutls_free(output.data);\n        return 2;\n    }\n    gnutls_free(output.data);\n    return puts(\"gnutls api passed\") == EOF;\n}\n";
        };
        "input" = "The hexadecimal text 3432, which represents the ASCII bytes 42.";
        "operation" = "Decode the text with gnutls_hex_decode2 and compare the returned datum.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgnutls"
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
              "exact" = "gnutls api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The API reports rejection and the consumer emits the fixed diagnostic and rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <gnutls/gnutls.h>\n\nint main(void) {\n    gnutls_datum_t input = {(unsigned char *)\"34xz\", 4};\n    gnutls_datum_t output = {0};\n    if (gnutls_hex_decode2(&input, &output) >= 0) {\n        gnutls_free(output.data);\n        return 2;\n    }\n    fputs(\"gnutls rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "Hexadecimal text containing a non-hexadecimal letter.";
        "operation" = "Decode the malformed text with gnutls_hex_decode2.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lgnutls"
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
              "exact" = "gnutls rejected invalid input\n";
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
        "https://www.gnupg.org/ftp/gcrypt/gnutls/v${majorMinor}/gnutls-${version}.tar.xz"
        "https://mirrors.dotsrc.org/gcrypt/gnutls/v${majorMinor}/gnutls-${version}.tar.xz"
      ];
      hash = "sha256-/+2Owb8JwkJtTxSq43feR1O1PlN9aF5gTpmosWypyX4=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [nettle gmp libtasn1 libunistring zlib];
    propagatedDeps = [nettle libtasn1 libunistring];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd gnutls-${version}
        '';
      }
      {
        # No p11-kit or TPM provider. certtool is kept for local certificate
        # authorities, and Unicode handling uses the shared AOS library.
        name = "configure";
        script = ''
          # Default X.509 trust store: the canonical runtime path owned by the
          # aos.security.pki module (modules/security/pki.nix), NOT a store
          # path — so operators can extend the trust store without rebuilding
          # gnutls. gnutls_certificate_set_x509_system_trust() (chrony NTS,
          # etc.) reads this file at runtime.
          ./configure \
            $configureFlags \
            --prefix=$out \
            --with-default-trust-store-file=/etc/ssl/certs/ca-certificates.crt \
            --disable-static \
            --without-p11-kit \
            --without-tpm \
            --without-tpm2 \
            --disable-libdane \
            --disable-cxx \
            --disable-guile \
            --disable-doc \
            --disable-tests \
            --disable-full-test-suite \
            --disable-nls
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

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "link-gnutls";
        library = self;
        libs = ["-lgnutls"];
        testSource = ''
          #include <gnutls/gnutls.h>

          int main(void) {
              return gnutls_check_version(GNUTLS_VERSION) == NULL;
          }
        '';
      };
    };

    meta = {
      description = "GnuTLS — TLS/SSL and certificate library";
      homepage = "https://www.gnutls.org/";
      license = "LGPL-2.1-or-later";
    };
  }
