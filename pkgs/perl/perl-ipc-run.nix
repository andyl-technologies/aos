##! perl-ipc-run — Subprocess and pipeline management for Perl
{
  mkDerivation,
  fetchurl,
  perl,
  perl-io-tty,
  perl-readonly,
}: let
  version = "20231003.0";
in
  import ../build-support/_perl-module.nix {inherit mkDerivation perl;} {
    pname = "perl-ipc-run";
    inherit version;
    src = fetchurl {
      urls = ["https://cpan.metacpan.org/authors/id/T/TO/TODDR/IPC-Run-${version}.tar.gz"];
      hash = "sha256-6yW731kT0pF5fvG/6ZjxUTC0VdPtAqrN5oVvCyXk/lc=";
    };
    sourceRoot = "IPC-Run-${version}";
    module = "IPC::Run";
    dependencies = [perl-io-tty perl-readonly];
    description = "Runs subprocesses and pipelines with redirection and pseudo-terminals";
    homepage = "https://metacpan.org/dist/IPC-Run";
    license = "Artistic-1.0-Perl OR GPL-1.0-or-later";
  }
