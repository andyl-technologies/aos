##! actionlint — Static checker for GitHub Actions workflow files
{
  lib,
  mkGoPackage,
  mkGithubUpstream,
  fetchGoModules,
}: let
  upstream = mkGithubUpstream {
    unitId = "actionlint-1";
    family = "actionlint";
    stream = "1";
    owner = "pkgs/tools/actionlint.nix";
    version = "1.7.12";
    upstreamId = "v1.7.12";
    repository = "rhysd/actionlint";
    provider = "github-releases";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "rhysd"
        "actionlint"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "v";}
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
      hash = "sha256-RUgAvU+FRZK8/nmxYfcdVuNZQOtwFuSKJt01atydQAo=";
    };
    artifacts.goModules = {
      inputs = [
        {
          kind = "source";
          component = "main";
          slot = "source";
        }
      ];
      hash = "sha256-XJprETDrPpG/fiap63fMru592P1YQJCIJg0mBVKPeaA=";
      materializer = {
        kind = "go-modules";
        sourceRoot = ".";
        moduleRoots = ["."];
        builder = "fetchGoModules/v1";
      };
    };
  };
  inherit (upstream) version;
  src = upstream.components.main.sources.source;
  goModules = fetchGoModules {
    inherit src;
    hash = upstream.artifacts.goModules.hash;
  };
in
  mkGoPackage {
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
      target = [
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
      role = "public-package";
    };

    pname = "actionlint";
    inherit version src goModules;
    update = upstream.updateWithArtifacts {inherit goModules;};

    goPackage = "./cmd/actionlint";
    goOutput = "actionlint";
    # Embed Go's timezone database so cron schedule timezone validation works
    # without host /usr/share/zoneinfo in minimal environments and sandboxes.
    tags = ["timetzdata"];
    ldflags = "-s -w -X github.com/rhysd/actionlint.version=${version}";
    # ./scripts/... contains maintainer code generators that fetch GitHub URLs.
    goTestFlags = ". ./cmd/actionlint";

    postInstall = ''
      mkdir -p "$out/share/licenses/actionlint"
      cp LICENSE.txt "$out/share/licenses/actionlint/"
    '';

    smokeTest = lib.qualification.commandProbe {
      primary = {
        input = "A valid GitHub Actions workflow file.";
        operation = "Lint the workflow file with external shellcheck and pyflakes integrations disabled.";
        expected = "actionlint accepts the valid workflow with no diagnostics.";
        files = {
          "workflow.yml" = ''
            name: CI
            on: [push]
            jobs:
              test:
                runs-on: ubuntu-latest
                steps:
                  - run: echo ok
          '';
        };
        steps = [
          {
            argv = [
              "@out@/bin/actionlint"
              "-no-color"
              "-shellcheck="
              "-pyflakes="
              "workflow.yml"
            ];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A GitHub Actions workflow referencing an undefined job in needs.";
        operation = "Lint the broken workflow with actionlint.";
        expected = "actionlint reports the error and exits with status 1.";
        files = {
          "broken.yml" = ''
            name: Broken
            on: [push]
            jobs:
              deploy:
                runs-on: ubuntu-latest
                needs: nonexistent
                steps:
                  - run: echo nope
          '';
        };
        steps = [
          {
            argv = [
              "@out@/bin/actionlint"
              "-no-color"
              "-shellcheck="
              "-pyflakes="
              "broken.yml"
            ];
            exit_code = 1;
            observes_rejection = true;
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
    };

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-actionlint";
        tool = self;
        command = ''
          actionlint -version | head -n 1 | grep -qx "${version}"
        '';
      };
    };

    meta = {
      description = "Static checker for GitHub Actions workflow files";
      homepage = "https://github.com/rhysd/actionlint";
      license = "MIT";
      mainProgram = "actionlint";
    };
  }
