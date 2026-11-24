##! buf — Protocol Buffers CLI for linting, breaking-change detection, formatting, and code generation
{
  lib,
  mkGoPackage,
  mkGithubUpstream,
  fetchGoModules,
}: let
  upstream = mkGithubUpstream {
    unitId = "buf-1";
    family = "buf";
    stream = "1";
    owner = "pkgs/tools/buf.nix";
    version = "1.75.0";
    upstreamId = "v1.75.0";
    repository = "bufbuild/buf";
    provider = "github-releases";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "bufbuild"
        "buf"
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
      hash = "sha256-4baIKDk4sZ/wcnidN/Nx6b37yGbrtxmyDB8b3EqcqP8=";
    };
    artifacts.goModules = {
      inputs = [
        {
          kind = "source";
          component = "main";
          slot = "source";
        }
      ];
      hash = "sha256-/14/tGwf2hXoSLSjaN1gJiqYr89sHtv6Vvdjdh8++3s=";
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
  companionCommands = [
    "protoc-gen-buf-breaking"
    "protoc-gen-buf-lint"
  ];
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

    pname = "buf";
    inherit version src goModules;
    update = upstream.updateWithArtifacts {inherit goModules;};

    goPackage = "./cmd/buf";
    goOutput = "buf";
    ldflags = "-s -w";

    # Upstream tests exercise git workspaces, external protoc plugins, and
    # registry clients; the smoke test below verifies offline formatting and
    # schema rejection.
    doCheck = false;

    postBuild =
      lib.concatMapStrings (command: ''
        go build -ldflags "-s -w" -o ${command} ./cmd/${command}
      '')
      companionCommands;

    postInstall = ''
      install -m 755 ${lib.concatStringsSep " " companionCommands} "$out/bin/"

      mkdir -p "$out/share/licenses/buf"
      cp LICENSE "$out/share/licenses/buf/"
    '';

    smokeTest = lib.qualification.commandProbe {
      primary = {
        input = "An unformatted Protobuf schema file.";
        operation = "Format the schema to stdout with buf format.";
        expected = "buf emits the canonically formatted Protobuf definition.";
        files = {
          "example.proto" = ''
            syntax="proto3";
            package acme.v1;
            message Ping{string msg=1;}
          '';
        };
        steps = [
          {
            argv = ["@out@/bin/buf" "format" "example.proto"];
            exit_code = 0;
            stdout.exact = ''
              syntax = "proto3";
              package acme.v1;
              message Ping {
                string msg = 1;
              }
            '';
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      badInput = {
        input = "A Protobuf schema with an unclosed message declaration.";
        operation = "Compile the malformed schema with buf build.";
        expected = "buf rejects the syntax error with a non-zero exit code.";
        files = {
          "broken.proto" = ''
            syntax = "proto3";
            message Broken {
          '';
        };
        steps = [
          {
            argv = ["@out@/bin/buf" "build" "broken.proto" "-o" "/dev/null"];
            exit_code = 100;
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
        pname = "tool-buf";
        tool = self;
        command = ''
          buf --version | grep -qx "${version}"
        '';
      };
    };

    meta = {
      description = "Protocol Buffers CLI for linting, breaking-change detection, formatting, and code generation";
      homepage = "https://buf.build/";
      license = "Apache-2.0";
      mainProgram = "buf";
    };
  }
