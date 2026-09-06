##! bash-completion — Programmable completion functions for Bash
{
  mkDerivation,
  fetchurl,
  autoconf,
  automake,
  gnumake,
}: let
  version = "2.17.0";
in
  mkDerivation {
    pname = "bash-completion";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/scop/bash-completion/releases/download/${version}/bash-completion-${version}.tar.xz"
      ];
      hash = "sha256-3Z2CXklkNfs766Oue+qfd+gh6JRmfQdDHR1MjFcLnlg=";
    };

    buildDeps = [autoconf automake gnumake];
    runtimeDeps = [];
    propagatedDeps = [];

    configureFlags = "--without-cowsay --without-gnuplot";

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-bash-completion";
        tool = self;
        command = "test -r ${self}/share/bash-completion/bash_completion";
      };
    };

    meta = {
      description = "Programmable completion functions for Bash";
      homepage = "https://github.com/scop/bash-completion";
      license = "GPL-2.0-or-later";
    };
  }
