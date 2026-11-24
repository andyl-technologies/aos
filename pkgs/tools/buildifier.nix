##! buildifier — Formatter and linter for Bazel BUILD, WORKSPACE, and Starlark files
{
  lib,
  mkGoPackage,
  mkGithubUpstream,
  fetchGoModules,
}: let
  upstream = mkGithubUpstream {
    unitId = "buildifier-10";
    family = "buildifier";
    stream = "10";
    owner = "pkgs/tools/buildifier.nix";
    version = "10.2.0";
    upstreamId = "v10.2.0";
    repository = "bazel-contrib/buildtools";
    provider = "github-releases";
    tagPrefix = "v";
    major = 10;
    source = {
      authority = "github.com";
      path = [
        "bazel-contrib"
        "buildtools"
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
      hash = "sha256-WvkAaOnogSq9xFWtBMxHRHC8zIu6vItXHj9YpmeZaA8=";
    };
    artifacts.goModules = {
      inputs = [
        {
          kind = "source";
          component = "main";
          slot = "source";
        }
      ];
      hash = "sha256-gcCqkXW9bSHGM7SiHb+6ZMFBOlcSHoBevy7m+hNyUH0=";
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

    pname = "buildifier";
    inherit version src goModules;
    update = upstream.updateWithArtifacts {inherit goModules;};

    goPackage = "./buildifier";
    # The repository has a top-level buildifier/ directory, so output the
    # compiled binary under bin/ before install copies it into $out/bin.
    goOutput = "bin/buildifier";
    ldflags = "-s -w -X main.buildVersion=${version} -X main.buildScmRevision=v${version}";
    # ./build/... expects Bazel runfiles paths and ./warn/docs fails Go 1.27 vet.
    goTestFlags = "./buildifier/... ./warn";

    postInstall = ''
      mkdir -p "$out/share/licenses/buildifier"
      cp LICENSE "$out/share/licenses/buildifier/"
    '';

    smokeTest = lib.qualification.commandProbe {
      primary = {
        input = "An unformatted BUILD.bazel file with unsorted sources.";
        operation = "Format the file in place with buildifier.";
        expected = "buildifier rewrites the target into canonical Starlark layout with sorted sources.";
        files = {
          "BUILD.bazel" = ''
            cc_library(name="demo",srcs=["b.cc","a.cc"])
          '';
        };
        steps = [
          {
            argv = ["@out@/bin/buildifier" "BUILD.bazel"];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
        ];
        artifacts = [
          {
            path = "BUILD.bazel";
            text = ''
              cc_library(
                  name = "demo",
                  srcs = [
                      "a.cc",
                      "b.cc",
                  ],
              )
            '';
          }
        ];
      };
      badInput = {
        input = "A BUILD.bazel file with a Starlark syntax error.";
        operation = "Check the malformed file with buildifier.";
        expected = "buildifier rejects the syntax error with a non-zero status.";
        files = {
          "BUILD.bazel" = "cc_library(name = \n";
        };
        steps = [
          {
            argv = ["@out@/bin/buildifier" "-mode=check" "BUILD.bazel"];
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
        pname = "tool-buildifier";
        tool = self;
        command = ''
          buildifier -version | grep -Fq "buildifier version: ${version}"
        '';
      };
    };

    meta = {
      description = "Formatter and linter for Bazel BUILD, WORKSPACE, and Starlark files";
      homepage = "https://github.com/bazel-contrib/buildtools";
      license = "Apache-2.0";
      mainProgram = "buildifier";
    };
  }
