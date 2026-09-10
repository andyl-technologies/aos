##! perl-parse-yapp — LALR parser generator for Perl
{
  mkDerivation,
  fetchurl,
  perl,
}: let
  version = "1.21";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-parse-yapp";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/W/WB/WBRASWELL/Parse-Yapp-${version}.tar.gz"];
      hash = "sha256-OBDpmDCPui4PTyYEMDUDKwJ85RzlyKUqi440DKZfE+U=";
    };
    sourceRoot = "Parse-Yapp-${version}";
    module = "Parse::Yapp::Driver";
    postInstall = ''
      mkdir -p "$out/bin"
      cp yapp "$out/bin/yapp"
      sed -i '1s|.*|#!${perl}/bin/perl -w|' "$out/bin/yapp"
      chmod 0755 "$out/bin/yapp"
    '';
    description = "Generates object-oriented LALR parsers for Perl";
    homepage = "https://metacpan.org/dist/Parse-Yapp";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
