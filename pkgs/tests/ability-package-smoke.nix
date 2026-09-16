##! Native package ability projection smoke fixture.
{
  lib,
  mkDerivation,
}: let
  qualification = lib.qualification;
  operation = {
    input,
    expected,
    path,
    exitCode,
    observesRejection ? false,
  }:
    qualification.operation {
      inherit input expected;
      operation = "Check the installed provider module path.";
      files = {};
      artifacts = [];
      steps = [
        (qualification.step {
          argv = [
            (qualification.template [(qualification.harness "bash")])
            (qualification.text "-c")
            (qualification.text "test -f \"$1\"")
            (qualification.text "ability-package-smoke")
            (qualification.template [
              (qualification.artifactPath {inherit path;})
            ])
          ];
          exit_code = exitCode;
          observes_rejection = observesRejection;
        })
      ];
    };
in
  mkDerivation {
    pname = "ability-package-smoke";
    version = "1.0.0";
    src = null;
    runtimeDeps = [];

    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/ability-package-smoke"
          cp ${./_ability-package-smoke-module/share/ability-package-smoke/provider.nix} \
            "$out/share/ability-package-smoke/provider.nix"
        '';
      }
    ];

    abilities = ./_ability-package-smoke-module;
    qualification.packageProbe = qualification.packageProbe {
      primary = operation {
        input = "The installed package output.";
        expected = "The package contains its provider module.";
        path = "share/ability-package-smoke/provider.nix";
        exitCode = 0;
      };
      badInput = operation {
        input = "A missing provider module path.";
        expected = "The package rejects the missing path.";
        path = "share/ability-package-smoke/missing.nix";
        exitCode = 1;
        observesRejection = true;
      };
    };

    meta = {
      description = "Native package ability projection smoke fixture";
      license = "Apache-2.0";
    };
  }
