##! just — A handy way to save and run project-specific commands
{
  mkCargoPackage,
  mkGithubUpstream,
  fetchCargoDeps,
}: let
  upstream = mkGithubUpstream {
    unitId = "just-1";
    family = "just";
    stream = "1";
    owner = "pkgs/tools/just.nix";
    version = "1.46.0";
    upstreamId = "1.46.0";
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
      hash = "sha256-9gpXhQLQsp6qKnLFsNkTkLIGTf2NGhKRw7JSXVh/05U=";
    };
    artifacts.cargoDeps = {
      inputs = [
        {
          kind = "source";
          component = "main";
          slot = "source";
        }
      ];
      hash = "sha256-NDqWrsIBL+fWS0cLrf2iZuKfyXC5xSj4JfD/QLlsdgA=";
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
