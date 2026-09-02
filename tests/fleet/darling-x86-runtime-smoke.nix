# tests/fleet/darling-x86-runtime-smoke.nix — Execute Darwin runtimes on Linux.
{
  mkDarlingFleetSuite,
  pkgs,
  systems,
  ...
}: let
  darwinCrossSmoke = import ../build/darwin-cross-smoke.nix {inherit pkgs;};
  darwinLanguageToolchains = import ../build/darwin-language-toolchains.nix {inherit pkgs;};
  darwinInterpreters = import ../build/darwin-interpreters.nix {inherit pkgs;};
  darwinHost = import ../.. {
    system = pkgs.stdenv.buildPlatform.system;
    crossSystem = "x86_64-darwin";
  };
  darwinAos = darwinHost.pkgs.aos;
  darwinDevShellSmoke = import ../build/darwin-dev-shell-native-smoke.nix {inherit pkgs;};
  darlingGuestSystem = systems.server.extendModules {
    modules = [
      {
        # The fleet helper adds the test agent and mount utilities to the slim
        # production server closure. Scope their additional image space to this
        # disposable qualification guest; production budgets remain unchanged.
        aos.image.budgets = {
          maxDownloadMiB = 768;
          maxRootMiB = 640;
        };
      }
    ];
  };
in
  mkDarlingFleetSuite {
    name = "darling-x86-runtime-smoke";
    # The runner needs the fleet agent, not server-test's broad CLI toolbox.
    # mkDarlingFleetSuite bundles it and carries target closures on a separate
    # immutable disk, keeping the production image unchanged.
    system = darlingGuestSystem;
    payloadSizeMiB = 2048;
    runtimeTimeout = 240;
    cases = [
      {
        name = "c";
        artifact = darwinCrossSmoke.passthru.x86.c;
        program = "bin/aos-darwin-c-smoke";
        expectedStdout = "aos Darwin C smoke\n";
        expectedStderr = "";
      }
      {
        name = "cxx";
        artifact = darwinCrossSmoke.passthru.x86.cxx;
        program = "bin/aos-darwin-cxx-smoke";
        expectedStdout = "aos Darwin C++ smoke\n";
        expectedStderr = "";
      }
      {
        name = "objective-c";
        artifact = darwinCrossSmoke.passthru.x86.c;
        program = "bin/aos-darwin-objective-c-smoke";
        expectedStdout = "";
        expectedStderr = "";
      }
      {
        name = "go";
        artifact = darwinLanguageToolchains.passthru.x86.go;
        program = "bin/aos-darwin-go-smoke";
        expectedStdout = "AOS Darwin Go smoke\n";
        expectedStderr = "";
      }
      {
        name = "python";
        artifact = darwinInterpreters.passthru.x86.python3;
        program = "bin/python3";
        args = [
          "-c"
          ''import _json; print("AOS Darwin Python smoke")''
        ];
        expectedStdout = "AOS Darwin Python smoke\n";
        expectedStderr = "";
      }
      {
        name = "aos-cli";
        artifact = darwinAos;
        program = "bin/aos";
        args = ["--help"];
        expectedStderr = "";
      }
      {
        name = "apm-cli";
        artifact = darwinAos.apm;
        program = "bin/apm";
        args = ["--help"];
        expectedStderr = "";
      }
      {
        name = "apr-cli";
        artifact = darwinAos.apr;
        program = "bin/apr";
        args = ["--help"];
        expectedStderr = "";
      }
      {
        name = "dev-shell-native-compile";
        artifact = darwinDevShellSmoke;
        program = "bin/aos-darwin-dev-shell-smoke";
        expectedStdout = ''
          AOS Darwin native Rust smoke
          AOS Darwin native C smoke
        '';
        expectedStderr = "";
      }
    ];
  }
