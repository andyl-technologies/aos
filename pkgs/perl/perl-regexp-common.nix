##! perl-regexp-common — Common regular expression patterns for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "2017060201";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-regexp-common";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/A/AB/ABIGAIL/Regexp-Common-${version}.tar.gz"];
      hash = "sha256-7geFOu4G8xDgQLa/GgGZoY2BiW0yGbmzXJYw0OtpCJs=";
    };
    sourceRoot = "Regexp-Common-${version}";
    module = "Regexp::Common";
    description = "Provides commonly requested regular expression patterns";
    homepage = "https://metacpan.org/dist/Regexp-Common";
    license = "MIT";
  }
