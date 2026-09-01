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
in
  mkDarlingFleetSuite {
    name = "darling-x86-runtime-smoke";
    # The runner needs the fleet agent, not server-test's broad CLI toolbox.
    # mkDarlingFleetSuite bundles it and carries target closures on a separate
    # immutable disk, keeping the production image unchanged.
    system = systems.server;
    payloadSizeMiB = 384;
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
    ];
  }
