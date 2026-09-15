##! CA Certificates — Mozilla CA certificate bundle
{
  lib,
  mkDerivation,
  fetchurl,
  gawk,
}: let
  version = "2026-05-14";
in
  mkDerivation {
    pname = "ca-certificates";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "OpenSSL accepts the complete PEM stream and loads multiple trust anchors.";
        "files" = {};
        "input" = "The package's canonical Mozilla CA bundle.";
        "operation" = "Load the bundle through Python's OpenSSL certificate-store API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import ssl\ncontext = ssl.create_default_context(cafile=\"@out@/etc/ssl/certs/ca-certificates.crt\")\nassert len(context.get_ca_certs()) > 100\nprint(\"ca-certificates data passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "ca-certificates data passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "OpenSSL rejects the malformed trust bundle.";
        "files" = {
          "invalid.pem" = "-----BEGIN CERTIFICATE-----\ntruncated\n";
        };
        "input" = "A PEM file with a truncated certificate body.";
        "operation" = "Load the malformed file through the same OpenSSL certificate-store API.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import ssl, sys\ntry:\n    ssl.create_default_context(cafile=\"invalid.pem\")\nexcept ssl.SSLError:\n    sys.stderr.write(\"ca-certificates rejected invalid input\\n\")\n    raise SystemExit(7)\nraise SystemExit(2)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "ca-certificates rejected invalid input\n";
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
        "https://curl.se/ca/cacert-${version}.pem"
      ];
      hash = "sha256-hqHzNmr6x8b4rp88d5rCIRKTKMQ/CrK4gX6y82KlAlw=";
    };

    buildDeps = [gawk];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p $out/etc/ssl/certs
          # The upstream extract contains prose headers. Publish a canonical
          # certificate-only PEM stream so strict runtime bundle validation can
          # consume the package output directly.
          gawk '
            BEGIN { emit = 0; found = 0 }
            /^-----BEGIN CERTIFICATE-----$/ { emit = 1; found = 1 }
            emit { print }
            /^-----END CERTIFICATE-----$/ { emit = 0 }
            END { if (emit || !found) exit 1 }
          ' $src > $out/etc/ssl/certs/ca-certificates.crt
          # Create compatibility symlink
          ln -sf ca-certificates.crt $out/etc/ssl/certs/ca-bundle.crt
        '';
      }
    ];

    meta = {
      description = "CA certificates — Mozilla root certificate bundle";
      homepage = "https://curl.se/docs/caextract.html";
      license = "MPL-2.0";
    };
  }
