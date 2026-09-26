##! ripgrep — Recursive regular-expression search
{
  lib,
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
  pkg-config,
  pcre2,
}: let
  version = "15.2.0";
  src = fetchurl {
    urls = ["https://github.com/BurntSushi/ripgrep/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-dgUknT6w1fFw40FEmOM0Tiax56FHrsUYtXCQuAA2pWI=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-Dn+cJ9eqr5HfMsMqtSyOF1PwBVabKrDqTBNu4NA6HO0=";
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];}];
      target = [];
      role = "public-package";
    };
    pname = "ripgrep";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Ripgrep emits only the matching line and its line number.";
        "files" = {
          "values.txt" = "answer=41\nanswer=42\n";
        };
        "input" = "Two lines containing one anchored answer assignment.";
        "operation" = "Search the file with an anchored regular expression and line numbers.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/rg"
              "--line-number"
              "^answer=42$"
              "values.txt"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "2:answer=42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Ripgrep reports no match with status 1 and no output.";
        "files" = {
          "values.txt" = "answer=41\n";
        };
        "input" = "A text file containing no requested answer.";
        "operation" = "Search for an absent anchored value.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/rg"
              "^answer=42$"
              "values.txt"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src cargoDeps;

    buildDeps = [pkg-config];
    runtimeDeps = [pcre2];
    buildFeatures = ["pcre2"];
    doCheck = false;

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-ripgrep";
        tool = self;
        command = "printf 'alpha\\nbeta\\n' | rg --pcre2 '^beta$' >/dev/null";
      };
    };

    meta = {
      description = "Fast recursive regular-expression search tool";
      homepage = "https://github.com/BurntSushi/ripgrep";
      license = "Unlicense OR MIT";
      mainProgram = "rg";
    };
  }
