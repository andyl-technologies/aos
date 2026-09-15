##! less — terminal pager
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
}: let
  version = "704";
in
  mkDerivation {
    pname = "less";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "less copies the line to standard output unchanged.";
        "files" = {};
        "input" = "A short line supplied on standard input in noninteractive mode.";
        "operation" = "Page the stream without terminal initialization or screen clearing.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/less"
              "-F"
              "-X"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "answer=42\n";
            "stdout" = {
              "exact" = "answer=42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "less rejects the option with a non-success status.";
        "files" = {};
        "input" = "An option name outside less's command-line grammar.";
        "operation" = "Invoke less with the unknown option.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/less"
              "--definitely-not-a-less-option"
            ];
            "exit_code" = 0;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "There is no definitely-not-a-less-option option (\"less --help\" for help)\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://www.greenwoodsoftware.com/less/less-${version}.tar.gz"
        "https://mirrors.kernel.org/gentoo/distfiles/less-${version}.tar.gz"
      ];
      hash = "sha256-IKCworslJfpTx+7pvrhUtMnPFy6rsgmvcCB0NUe/6fs=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [ncurses];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd less-${version}
        '';
      }
      {
        name = "build";
        script = ''
          $CONFIG_SHELL ./configure $configureFlags --prefix=$out --sysconfdir=/etc
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script = ''
          make install
        '';
      }
    ];

    meta = {
      description = "less — terminal pager";
      homepage = "https://www.greenwoodsoftware.com/less/";
      license = "GPL-3.0-or-later";
    };
  }
