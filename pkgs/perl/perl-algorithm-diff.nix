##! perl-algorithm-diff — Intelligent differences between Perl sequences
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.1903";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-algorithm-diff";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/T/TY/TYEMQ/Algorithm-Diff-${version}.tar.gz"];
      hash = "sha256-MOhKxLMdQLZik/exIhMxxaUFYaOdWA2FAE2cH/+ZF1E=";
    };
    sourceRoot = "Algorithm-Diff-${version}";
    module = "Algorithm::Diff";
    description = "Computes intelligent differences between Perl sequences";
    homepage = "https://metacpan.org/dist/Algorithm-Diff";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
