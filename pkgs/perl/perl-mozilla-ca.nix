##! perl-mozilla-ca — CA certificate bundle interface for Perl
{
  mkDerivation,
  fetchurl,
  perl,
  ca-certificates,
}: let
  version = "20230821";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-mozilla-ca";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/L/LW/LWP/Mozilla-CA-${version}.tar.gz"];
      hash = "sha256-MuHQBFKZAEBFucTRbC2q5FOiFiCIc97qJED3EmCnzaE=";
    };
    sourceRoot = "Mozilla-CA-${version}";
    module = "Mozilla::CA";
    dependencies = [ca-certificates];
    postInstall = ''
      rm -f "$out/lib/perl5/Mozilla/CA/cacert.pem"
      ln -s ${ca-certificates}/etc/ssl/certs/ca-certificates.crt \
        "$out/lib/perl5/Mozilla/CA/cacert.pem"
    '';
    description = "Exposes the system CA certificate bundle to Perl";
    homepage = "https://metacpan.org/dist/Mozilla-CA";
    license = "MPL-2.0";
  }
