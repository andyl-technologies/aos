##! Package-owned qualification retains a native, authenticated companion.
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
  namedOutputs = pkgs.mkDerivation {
    pname = "package-qualification-carrier-probe";
    version = "1";
    src = null;
    phases = [];
    # Same-name bootstrap/test variants must not replace the subject's outputs.
    buildDeps = [package];
    outputs = ["out" "dev"];
    qualification.packageProbe = commandProbe;
  };
  noProbe = pkgs.mkDerivation {
    pname = "package-without-qualification";
    version = "1";
    src = null;
    phases = [];
  };
  tool = version:
    pkgs.mkDerivation {
      pname = "qualification-tool";
      inherit version;
      src = null;
      phases = [];
    };
  firstTool = tool "1";
  secondTool = tool "2";
  externalProbe = qualification.packageProbe {
    primary = operation {
      input = "The declared build dependency.";
      action = "Select the exact qualification tool artifact.";
      expected = "The selector binds only to the declared dependency root.";
      steps = [
        (qualification.step {
          argv = [
            (qualification.template [
              (qualification.artifactRoot {
                artifact = {
                  _type = "aos-package-output-selector";
                  package = "qualification-tool";
                  output = "out";
                };
              })
            ])
          ];
          exit_code = 0;
        })
      ];
    };
    badInput = probe.bad_input;
  };
  withTools = dependencies:
    pkgs.mkDerivation {
      pname = "qualification-consumer";
      version = "1";
      src = null;
      phases = [];
      buildDeps = dependencies;
      qualification.packageProbe = externalProbe;
    };
  declaredTool = withTools [firstTool];
  rejectsConflictingTools = !(builtins.tryEval (builtins.deepSeq (withTools [firstTool secondTool]).qualificationDocument true)).success;
  rejectsUndeclaredTool = !(builtins.tryEval (builtins.deepSeq (withTools []).qualificationDocument true)).success;
  openProbe =
    probe
    // {
      primary = probe.primary // {unchecked = true;};
    };
  rejectsOpenProbe =
    !(builtins.tryEval (builtins.deepSeq (pkgs.mkDerivation {
        pname = "invalid-package-qualification-carrier-probe";
        version = "1";
        src = null;
        phases = [];
        qualification.packageProbe = openProbe;
      })
      true)).success;
  rejectsMissingOutput =
    !(builtins.tryEval (builtins.deepSeq
      (pkgs.mkDerivation {
        pname = "package-qualification-carrier-probe";
        version = "1";
        src = null;
        phases = [];
        qualification.packageProbe = commandProbe;
      }).qualificationDocument
      true)).success;
  rejectsUnknownQualification =
    !(builtins.tryEval (builtins.deepSeq (pkgs.mkDerivation {
        pname = "invalid-qualification-field";
        version = "1";
        src = null;
        phases = [];
        qualification = {
          packageProbe = probe;
          unchecked = true;
        };
      })
      true)).success;
in
  assert !(package ? abilities);
  assert !(package ? contract);
  assert !(noProbe ? qualificationArtifact);
  assert package.qualificationArtifact ? outPath;
  assert package.qualificationDocument.schema == "aos.package.qualification";
  assert package.qualificationDocument.package
  == {
    name = "package-qualification-carrier-probe";
    version = "1";
  };
  assert !(lib.hasInfix "/nix/store/" (builtins.toJSON package.qualificationDocument.probe));
  assert package.qualificationDocument.selectors
  == [
    {
      package = "package-qualification-carrier-probe";
      output = "out";
    }
  ];
  assert package.qualificationDocument.probe.primary.steps != [];
  assert (builtins.head package.qualificationDocument.artifacts).path == builtins.toString package;
  assert namedOutputs.dev.qualificationArtifact == namedOutputs.qualificationArtifact;
  assert namedOutputs.dev.qualificationDocument == namedOutputs.qualificationDocument;
  assert map (artifact: artifact.path) namedOutputs.qualificationDocument.artifacts
  == [(builtins.toString namedOutputs.dev) (builtins.toString namedOutputs.out)];
  assert builtins.attrNames (builtins.listToAttrs (map (selector: {
      name = "${selector.package}:${selector.output}";
      value = true;
    })
    commandProjection.selectors))
  == [
    "package-qualification-carrier-probe:dev"
    "package-qualification-carrier-probe:out"
  ];
  assert (builtins.elemAt commandProjection.value.primary.steps 0).argv
  == [
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
    {
      fragments = [
        {
          kind = "harness";
          tool = "python";
        }
      ];
    }
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
  assert rejectsMissingOutput;
  assert rejectsUnknownQualification;
  assert (builtins.head (builtins.filter (artifact: artifact.selector.package == "qualification-tool") declaredTool.qualificationDocument.artifacts)).path == builtins.toString firstTool;
  assert rejectsConflictingTools;
  assert rejectsUndeclaredTool; true
