##! treefmt — One command to run every formatter in a project tree
{
  lib,
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}: let
  version = "2.6.0";
  src = fetchurl {
    urls = ["https://github.com/numtide/treefmt/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-kJk/hYs3bAoMpJkguWedx3QQepb62P/DgIgJxqgvTs4=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-D8dP9V0Qh4U9aEY+AHvzWsb1k2iuLnfhW3jcw8MtESY=";
  };

  # treefmt reports these through `--version`; upstream's own build sets the
  # same variables, and the default is a "+dev" placeholder.
  buildInfo = "github.com/numtide/treefmt/v2/build";
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
    pname = "treefmt";
    inherit version src goModules;
    goOutput = "treefmt";
    ldflags = "-s -w -X ${buildInfo}.Name=treefmt -X ${buildInfo}.Version=v${version}";

    # The upstream suite drives real formatters, git, and jujutsu from its
    # test fixtures; the smoke test below exercises the formatter pipeline.
    doCheck = false;

    smokeTest = lib.qualification.commandProbe {
      primary = {
        input = "A tree with one matching file and a formatter that rewrites it.";
        operation = "Run treefmt over the tree with caching disabled.";
        expected = "treefmt invokes the formatter on the matching file only.";
        files = {
          "treefmt.toml" = ''
            [formatter.stamp]
            command = "@bash@"
            options = ["-c", "for f; do printf 'formatted\\n' > \"$f\"; done", "stamp"]
            includes = ["*.txt"]
          '';
          "input.txt" = "unformatted\n";
          "ignored.md" = "untouched\n";
        };
        steps = [
          {
            argv = [
              "@out@/bin/treefmt"
              "--config-file"
              "@work@/primary/treefmt.toml"
              "--tree-root"
              "@work@/primary"
              "--walk"
              "filesystem"
              "--no-cache"
            ];
            exit_code = 0;
          }
        ];
        artifacts = [
          {
            path = "input.txt";
            text = "formatted\n";
          }
          {
            path = "ignored.md";
            text = "untouched\n";
          }
        ];
      };
      badInput = {
        input = "A configuration file that is not valid TOML.";
        operation = "Run treefmt with the malformed configuration.";
        expected = "treefmt rejects the configuration before formatting anything.";
        files = {
          "treefmt.toml" = "[formatter.broken\n";
        };
        steps = [
          {
            argv = [
              "@out@/bin/treefmt"
              "--config-file"
              "@work@/bad-input/treefmt.toml"
              "--tree-root"
              "@work@/bad-input"
              "--walk"
              "filesystem"
              "--no-cache"
            ];
            exit_code = 1;
            observes_rejection = true;
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
        pname = "tool-treefmt";
        tool = self;
        command = "treefmt --version";
      };
    };

    meta = {
      description = "Formatter multiplexer that runs every configured formatter over a project tree";
      homepage = "https://treefmt.com/";
      license = "MIT";
      mainProgram = "treefmt";
    };
  }
