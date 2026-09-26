##! Perl-based converter for LaTeX manual sources.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  perl,
}: let
  version = "1.30";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "latex2man";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A small LaTeX manual source with a title and description.";
        operation = "Convert the source to a troff manual page.";
        expected = "The page contains the requested title and description.";
        files."probe.tex" = ''
          \begin{Name}{1}{aosprobe}{AOS}{probe}{AOS Probe}
          \section{Description}
          The answer is 42.
          \end{Name}
        '';
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/latex2man" "probe.tex" "probe.1"];
            exit_code = 0;
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                manual = Path("probe.1").read_text()
                assert '.TH "AOSPROBE" "1"' in manual
                assert "The answer is 42." in manual
                print("latex2man converted manual page")
              ''
            ];
            exit_code = 0;
            stdout.exact = "latex2man converted manual page\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A nonexistent LaTeX manual source.";
        operation = "Request conversion of the missing source.";
        expected = "Latex2man reports that the source cannot be opened.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/latex2man" "qualification-missing.tex" "probe.1"];
            exit_code = 2;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
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
