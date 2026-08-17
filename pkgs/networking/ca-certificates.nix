##! CA Certificates — Mozilla CA certificate bundle
{
  mkDerivation,
  fetchurl,
  gawk,
}: let
  version = "2026-05-14";
in
  mkDerivation {
    pname = "ca-certificates";
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
