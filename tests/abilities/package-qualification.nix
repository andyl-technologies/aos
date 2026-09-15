##! Package-owned qualification shares the canonical package contract carrier.
{
  lib,
  pkgs,
}: let
  qualification = lib.qualification;
  operation = {
    input,
    action,
    expected,
    steps,
  }:
    qualification.operation {
      inherit input expected steps;
      operation = action;
      files = {};
      artifacts = [];
    };
  probe = qualification.packageProbe {
    primary = operation {
      input = "A fixed input document.";
      action = "Print the package version.";
      expected = "The executable reports its version successfully.";
      steps = [
        (qualification.step {
          argv = [
            (qualification.template [
              (qualification.artifactPath {path = "bin/probe";})
            ])
            (qualification.text "--version")
          ];
          exit_code = 0;
          stdout = qualification.text "probe 1\n";
        })
      ];
    };
    badInput = operation {
      input = "An unsupported option.";
      action = "Invoke the package with the unsupported option.";
      expected = "The executable rejects the option.";
      steps = [
        (qualification.step {
          argv = [
            (qualification.template [
              (qualification.artifactPath {path = "bin/probe";})
            ])
            (qualification.text "--unsupported")
          ];
          exit_code = 2;
          observes_rejection = true;
        })
      ];
    };
  };
  commandProbe = qualification.commandProbe {
    primary = {
      input = "An exact artifact and named output.";
      operation = "Run the package-owned command.";
      expected = "Typed placeholders retain their artifact authority.";
      files = {"input.txt" = "@out@ @output:dev@/include @work@/input";};
      steps = [
        {
          argv = ["@out@/bin/probe" "@python@" "@out@"];
          stdout.exact = "@output:dev@/include\n";
          exit_code = 0;
        }
      ];
      artifacts = [];
    };
    badInput = {
      input = "An unsupported option.";
      operation = "Reject the unsupported option.";
      expected = "The package reports rejection.";
      files = {};
      steps = [
        {
          argv = ["@out@/bin/probe" "--unsupported"];
          exit_code = 2;
          observes_rejection = true;
        }
      ];
      artifacts = [];
    };
  };
  commandProjection = qualification.projectPackageProbe {
    owner = "package-qualification-carrier-probe";
    probe = commandProbe;
  };
  package = pkgs.mkDerivation {
    pname = "package-qualification-carrier-probe";
    version = "1";
    src = null;
    phases = [];
    qualification.packageProbe = probe;
  };
  openProbe = probe // {
    primary = probe.primary // {unchecked = true;};
  };
  rejectsOpenProbe = !(builtins.tryEval (builtins.deepSeq (pkgs.mkDerivation {
      pname = "invalid-package-qualification-carrier-probe";
      version = "1";
      src = null;
      phases = [];
      qualification.packageProbe = openProbe;
    })
    true)).success;
in
  assert !(package ? abilities);
  assert builtins.attrNames package.contract == ["document" "selectors" "value"];
  assert builtins.isAttrs package.contract.document;
  assert package.contract.document ? outPath;
  assert !(lib.hasInfix "/nix/store/" (builtins.toJSON package.contract.value));
  assert package.contract.value.package_module == null;
  assert package.contract.selectors
  == [
    {
      package = "package-qualification-carrier-probe";
      output = "out";
    }
  ];
  assert package.contract.value.qualification.package_probe.primary.steps != [];
  assert builtins.attrNames (builtins.listToAttrs (map (selector: {
      name = "${selector.package}:${selector.output}";
      value = true;
    })
    commandProjection.selectors))
  == [
    "package-qualification-carrier-probe:dev"
    "package-qualification-carrier-probe:out"
  ];
  assert (builtins.elemAt commandProjection.value.primary.steps 0).argv == [
    {
      fragments = [
        {
          artifact = {
            package = "package-qualification-carrier-probe";
            output = "out";
          };
          kind = "artifact-path";
          path = "bin/probe";
        }
      ];
    }
    {fragments = [{kind = "harness"; tool = "python";}];}
    {
      fragments = [
        {
          artifact = {
            package = "package-qualification-carrier-probe";
            output = "out";
          };
          kind = "artifact-root";
        }
      ];
    }
  ];
  assert rejectsOpenProbe;
    true
