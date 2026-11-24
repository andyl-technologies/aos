##! shfmt — Shell parser and formatter supporting POSIX Shell, Bash, and mksh
{
  lib,
  mkGoPackage,
  mkGithubUpstream,
  fetchGoModules,
}: let
  upstream = mkGithubUpstream {
    unitId = "shfmt-3";
    family = "shfmt";
    stream = "3";
    owner = "pkgs/tools/shfmt.nix";
    version = "3.14.1";
    upstreamId = "v3.14.1";
    repository = "mvdan/sh";
    provider = "github-releases";
    tagPrefix = "v";
    major = 3;
    source = {
      authority = "github.com";
      path = [
        "mvdan"
        "sh"
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
      hash = "sha256-7EvbiKtslWhr46TutK130rSdM9LtewplA1zVLS2HxEM=";
    };
    artifacts.goModules = {
      inputs = [
        {
          kind = "source";
          component = "main";
          slot = "source";
        }
      ];
      hash = "sha256-KPkfzEVYcHeBj+Zex7XFOjE6vcz5d+IxdypTp3/78Cs=";
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

    pname = "shfmt";
    inherit version src goModules;
    update = upstream.updateWithArtifacts {inherit goModules;};

    goPackage = "./cmd/shfmt";
    goOutput = "shfmt";
    ldflags = "-s -w";
    # ./syntax's FuzzQuote spawns bash with LC_ALL=en_US.UTF-8, which is absent
    # in the sandbox; ./cmd/shfmt runs the full CLI formatting testscript suite.
    goTestFlags = "./cmd/shfmt ./fileutil";

    postPatch = ''
      # Tarball builds have no VCS metadata, so debug.ReadBuildInfo reports
      # "(devel)". Substitute the packaged release tag as the fallback.
      sed -i 's|version = mod.Version|if mod.Version != "" \&\& mod.Version != "(devel)" { version = mod.Version } else { version = "v${version}" }|' cmd/shfmt/main.go
    '';

    postInstall = ''
      mkdir -p "$out/share/licenses/shfmt"
      cp LICENSE "$out/share/licenses/shfmt/"
    '';

    smokeTest = lib.qualification.commandProbe {
      primary = {
        input = "An unindented POSIX shell conditional.";
        operation = "Format the script with two-space indentation via shfmt.";
        expected = "shfmt emits the canonically formatted and indented script.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/shfmt" "-i" "2"];
            stdin = "if [ \"$a\" = 1 ]; then\necho hi\nfi\n";
            exit_code = 0;
            stdout.exact = ''
              if [ "$a" = 1 ]; then
                echo hi
              fi
            '';
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A shell script with an unclosed if statement.";
        operation = "Format the malformed script with shfmt.";
        expected = "shfmt rejects the syntax error with status 1.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/shfmt"];
            stdin = "if [ \"$a\" = 1 ]; then\n";
            exit_code = 1;
            observes_rejection = true;
            stdout.exact = "";
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
        pname = "tool-shfmt";
        tool = self;
        command = ''
          shfmt --version | grep -qx "v${version}"
        '';
      };
    };

    meta = {
      description = "Shell parser and formatter supporting POSIX Shell, Bash, and mksh";
      homepage = "https://github.com/mvdan/sh";
      license = "BSD-3-Clause";
      mainProgram = "shfmt";
    };
  }
