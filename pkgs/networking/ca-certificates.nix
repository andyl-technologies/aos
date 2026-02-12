# CA Certificates — Mozilla CA certificate bundle
{ mkDerivation, fetchurl, sources, versions }:

mkDerivation {
  name = "ca-certificates-${versions.networking.ca-certificates}";
  version = versions.networking.ca-certificates;

  src = fetchurl {
    inherit (sources.ca-certificates) url hash;
  };

  buildDeps = [];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "install";
      script = ''
        mkdir -p $out/etc/ssl/certs
        cp $src $out/etc/ssl/certs/ca-certificates.crt
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
