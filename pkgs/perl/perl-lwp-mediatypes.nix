##! perl-lwp-mediatypes — MIME type inference for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "6.04";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-lwp-mediatypes";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/O/OA/OALDERS/LWP-MediaTypes-${version}.tar.gz"];
      hash = "sha256-jxvKEtqxahwqfAOknF5YzOQab+yVGfCq37qNrZl5Gdk=";
    };
    sourceRoot = "LWP-MediaTypes-${version}";
    module = "LWP::MediaTypes";
    description = "Infers MIME types from file names and URLs";
    homepage = "https://metacpan.org/dist/LWP-MediaTypes";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
