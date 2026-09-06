##! perl-time-duration — English expressions of time durations
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.21";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-time-duration";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/N/NE/NEILB/Time-Duration-${version}.tar.gz"];
      hash = "sha256-/jQOuodl+SY2lGdOXf8UgzRD4Zhl5f9Ce715t7X4qbg=";
    };
    sourceRoot = "Time-Duration-${version}";
    module = "Time::Duration";
    description = "Formats time durations as rounded or exact English text";
    homepage = "https://metacpan.org/dist/Time-Duration";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
