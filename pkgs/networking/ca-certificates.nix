# CA Certificates — Mozilla CA certificate bundle
{ mkDerivation, fetchurl }:

let
  version = "2024-07-02";
in
mkDerivation {
  pname = "ca-certificates";
  inherit version;

  src = fetchurl {
    urls = [
      "https://curl.se/ca/cacert-${version}.pem"
    ];
    hash = "sha256-G/RYQSVo4TSkUU9eFwoyjREJHgcccRCVXJiE7YeXKsk=";
  };

  buildDeps = [ ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "install";
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
