##! just — A handy way to save and run project-specific commands
{
  lib,
  mkCargoPackage,
  mkGithubUpstream,
  fetchCargoDeps,
}: let
  upstream = mkGithubUpstream {
    unitId = "just-1";
    family = "just";
    stream = "1";
    owner = "pkgs/tools/just.nix";
    version = "1.58.0";
    upstreamId = "1.58.0";
    repository = "casey/just";
    provider = "github-releases";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "casey"
        "just"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-yKNubpOX8v38sMwkb823kLUqeE88jKvA2LrrAxhSoUg=";
    };
    artifacts.cargoDeps = {
      inputs = [
        {
          kind = "source";
          component = "main";
          slot = "source";
        }
      ];
      hash = "sha256-ADCjggkHVPGm/kX2RpSH1oETg5lcspfZhTZGMhFvORw=";
      materializer = {
        kind = "cargo-deps";
        sourceRoot = ".";
        patches = [];
        builder = "fetchCargoDeps/v1";
      };
    };
  };
  inherit (upstream) version;
  src = upstream.components.main.sources.source;
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = upstream.artifacts.cargoDeps.hash;
  };
in
  mkCargoPackage {
    pname = "just";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "just emits the exact variable value 42.";
        "files" = {
          "justfile" = "answer := \"42\"\n";
        };
        "input" = "A justfile defining the variable answer as 42.";
        "operation" = "Evaluate the named variable through just's recipe parser.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/just"
              "--evaluate"
              "answer"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "42";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "just rejects the file with its parse-error status.";
        "files" = {
          "justfile" = "answer :=\n";
        };
        "input" = "A justfile assignment with no value expression.";
        "operation" = "Parse and evaluate the malformed justfile.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/just"
              "--evaluate"
              "answer"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
          }
        ];
      };
    };

    inherit version src;

    inherit cargoDeps;
    update = upstream.updateWithArtifacts {inherit cargoDeps;};

    doCheck = false;

    meta = {
      description = "just — a handy way to save and run project-specific commands";
      homepage = "https://github.com/casey/just";
      license = "CC0-1.0";
      mainProgram = "just";
    };
  }
