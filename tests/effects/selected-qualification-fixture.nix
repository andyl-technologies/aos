##! Separates native qualification evidence from selected runtime payload roots.
{
  pkgs,
  lib,
}: let
  base = import ./selected-output-fixture.nix {inherit pkgs lib;};
  qualification = lib.qualification;
  probeTool = pkgs.mkDerivation {
    pname = "selected-qualification-tool";
    version = "1";
    src = null;
    phases = [
      {
        name = "install";
        script = ''printf '%s\n' probe > "$out/probe-tool"'';
      }
    ];
  };
  toolSelector = {
    _type = "aos-package-output-selector";
    package = "selected-qualification-tool";
    output = "out";
  };
  probe = qualification.packageProbe {
    primary = qualification.operation {
      input = "Exact owning output and declared build-only tool roots.";
      operation = "Inspect the immutable probe inputs with the qualified shell harness.";
      expected = "Both declared artifacts contain their exact marker files.";
      files = {};
      artifacts = [];
      steps = [
        (qualification.step {
          argv = [
            (qualification.template [(qualification.harness "bash")])
            (qualification.text "-c")
            (qualification.text ''test -f "$1/probe-tool" && test -f "$2/marker"'')
            (qualification.text "probe")
            (qualification.template [(qualification.artifactRoot {artifact = toolSelector;})])
            (qualification.template [(qualification.artifactRoot {})])
          ];
          exit_code = 0;
        })
      ];
    };
    badInput = qualification.operation {
      input = "An incomplete shell conditional.";
      operation = "Reject the malformed probe program.";
      expected = "The shell rejects the syntax with status two.";
      files = {};
      artifacts = [];
      steps = [
        (qualification.step {
          argv = [(qualification.template [(qualification.harness "bash")]) (qualification.text "-c") (qualification.text "if")];
          exit_code = 2;
          observes_rejection = true;
        })
      ];
    };
  };
  package = base.testPackage.overrideAttrs {
    buildDeps = [probeTool];
    qualification.packageProbe = probe;
  };
  evaluated = lib.evalPackageModules {
    packages = [package.tools];
    scope = ["profile" "selected-qualification"];
  };
  artifacts = import ../../lib/packages/artifacts.nix {};
  roots = builtins.map (artifact: builtins.unsafeDiscardStringContext artifact.path) evaluated.deployment.artifacts;
  inputs = builtins.map builtins.unsafeDiscardStringContext evaluated.deployment.inputs;
  expectedBindings = [
    {
      selector = {
        package = "selected-handler";
        output = "out";
      };
      path = builtins.toString package;
    }
    {
      selector = {
        package = "selected-qualification-tool";
        output = "out";
      };
      path = builtins.toString probeTool;
    }
  ];
in
  assert roots == [(builtins.toString package.tools)];
  assert !(builtins.elem (builtins.toString package) inputs);
  assert !(builtins.elem (builtins.toString probeTool) inputs);
  assert !(builtins.elem (builtins.toString package.qualificationArtifact) inputs);
  assert package.qualificationDocument.artifacts == expectedBindings;
  assert !(builtins.hasAttr (builtins.unsafeDiscardStringContext package.drvPath) (builtins.getContext package.documentationArtifact.text));
    (pkgs.writeTextFile {
      name = "selected-qualification-fixture";
      destination = "/fixture.json";
      text = builtins.toJSON {
        available = artifacts.metadata (artifacts.reference package);
        document = evaluated.deployment;
        envelope = "${package.tools.deploymentArtifact}/deployment.json";
        documentation = "${package.documentationArtifact}/options.json";
        qualificationArtifact = builtins.unsafeDiscardStringContext (builtins.toString package.qualificationArtifact);
        qualificationTool = builtins.unsafeDiscardStringContext (builtins.toString probeTool);
      };
    })
    // {testPackage = package;}
