##! aos-ability-boundary-observer - native fleet execution-boundary fixture
{
  lib,
  mkDerivation,
  writeTextFile,
  python3,
}: let
  settings = import ./_aos-ability-boundary-observer/settings.nix;
  controller = writeTextFile {
    name = "aos-ability-boundary-controller";
    destination = "/bin/aos-ability-boundary-controller";
    executable = true;
    text = ''
      #!${python3}/bin/python3
      import os
      import sys

      arguments = sys.argv[1:]
      if not arguments or arguments[0] != "--state-root":
          arguments = ["--state-root", ${builtins.toJSON settings.stateRoot}, *arguments]

      os.execv(
          ${builtins.toJSON "${python3}/bin/python3"},
          [
              ${builtins.toJSON "${python3}/bin/python3"},
              ${builtins.toJSON (builtins.toString ./_aos-ability-boundary-observer.py)},
              *arguments,
          ],
      )
    '';
  };
in
  mkDerivation {
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
      ];
      target = [];
      role = "build-input";
    };
    pname = "aos-ability-boundary-observer";
    version = "0.1.0";
    src = null;

    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        artifacts = [];
        expected = "The installed boundary controller reports its package protocol version.";
        files = {};
        input = "The package-owned controller executable.";
        operation = "Invoke its version command.";
        steps = [
          {
            argv = ["@out@/bin/aos-ability-boundary-controller" "--version"];
            exit_code = 0;
            stderr.exact = "";
            stdout.exact = "aos-ability-boundary-observer 1\n";
          }
        ];
      };
      badInput = {
        artifacts = [];
        expected = "The controller rejects a non-absolute state root before performing work.";
        files = {};
        input = "A relative fixture state path.";
        operation = "Attempt to start the controller with that path.";
        steps = [
          {
            argv = [
              "@out@/bin/aos-ability-boundary-controller"
              "serve"
              "--socket"
              "relative"
            ];
            exit_code = 2;
            observes_rejection = true;
            stderr.exact = "aos-ability-boundary-observer rejected invalid input: socket path must be absolute and normalized\n";
            stdout.exact = "";
          }
        ];
      };
    };

    runtimeDeps = [controller python3];

    phases = [
      {
        name = "check";
        script = ''
          ${python3}/bin/python3 \
            ${./_aos-ability-boundary-observer-tests.py} \
            ${./_aos-ability-boundary-observer.py}
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          ln -s ${controller}/bin/aos-ability-boundary-controller \
            "$out/bin/aos-ability-boundary-controller"
        '';
      }
    ];

    abilities = ./_aos-ability-boundary-observer;

    meta = {
      description = "Fleet fixture for observing native ability execution boundaries";
      license = "Apache-2.0";
      mainProgram = "aos-ability-boundary-controller";
    };
  }
