##! Perl-based converter for LaTeX manual sources.
{
  mkDerivation,
  fetchurl,
  buildPackages,
  perl,
}: let
  version = "1.30";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "latex2man";
    inherit version;
    src = fetchurl {
      urls = ["https://mirrors.ctan.org/support/latex2man.zip"];
      hash = "0rcyckhnh51zcy506ya889gxdi8zqplh4w0fly07g06w6bj124xc";
    };
    buildDeps = [buildPackages.python3 buildPackages.perl];
    runtimeDeps = [perl];
    phases = [
      {
        name = "unpack";
        script = ''
          ${buildPackages.python3}/bin/python3 -m zipfile -e "$src" .
          cd latex2man
          sed -i '1c#!${perl}/bin/perl' latex2man
          # Honor reproducible-build timestamps without changing interactive use.
          sed -i 's/localtime();/localtime($ENV{SOURCE_DATE_EPOCH} \/\/ time());/' latex2man
        '';
      }
      {
        name = "build";
        script = ''
          export SOURCE_DATE_EPOCH=1768521600 TZ=UTC
          ${buildPackages.perl}/bin/perl latex2man -t ./latex2man.trans latex2man.tex built.1
          ${buildPackages.perl}/bin/perl latex2man -H -t ./latex2man.trans latex2man.tex built.html
          ${buildPackages.perl}/bin/perl latex2man -T -t ./latex2man.trans latex2man.tex built.texi
          test -s built.1
          test -s built.html
          test -s built.texi
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin" "$out/share/man/man1" "$out/share/doc/latex2man" \
            "$out/share/texmf/tex/latex/latex2man" "$out/share/licenses/latex2man"
          install -m 755 latex2man "$out/bin/latex2man"
          cp built.1 "$out/share/man/man1/latex2man.1"
          cp built.html "$out/share/doc/latex2man/latex2man.html"
          cp built.texi "$out/share/doc/latex2man/latex2man.texi"
          cp latex2man.css latex2man.trans README CHANGES "$out/share/doc/latex2man/"
          cp latex2man.sty "$out/share/texmf/tex/latex/latex2man/"
          cp README "$out/share/licenses/latex2man/"
        '';
      }
    ];
    meta = {
      description = "Convert LaTeX manual sources to troff, HTML, and Texinfo";
      homepage = "https://ctan.org/pkg/latex2man";
      license = "LPPL-1.0-or-later";
      mainProgram = "latex2man";
    };
  }
