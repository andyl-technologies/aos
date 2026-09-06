##! perl-parallel-forkmanager — Simple parallel processing for Perl
{
  mkDerivation,
  fetchurl,
  perl,
  perl-class-method-modifiers,
  perl-module-runtime,
  perl-moo,
  perl-role-tiny,
  perl-sub-quote,
}: let
  version = "2.02";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-parallel-forkmanager";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/Y/YA/YANICK/Parallel-ForkManager-${version}.tar.gz"];
      hash = "sha256-wbKXCou2ZsPefKrEqPTbzAQ6uBm7wzdpLse/J62uRAQ=";
    };
    sourceRoot = "Parallel-ForkManager-${version}";
    module = "Parallel::ForkManager";
    # Perl does not discover propagated module directories on its own, so the
    # complete Moo module closure is explicit in PERL5LIB and the output graph.
    dependencies = [
      perl-class-method-modifiers
      perl-module-runtime
      perl-moo
      perl-role-tiny
      perl-sub-quote
    ];
    description = "Manages simple parallel processing with forked Perl processes";
    homepage = "https://metacpan.org/dist/Parallel-ForkManager";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
