##! Tiny realized companions and graph roots for selected-output closure checks.
{
  pkgs,
  lib,
}: let
  interface = pkgs.mkDerivation {
    pname = "selected-interface";
    version = "1";
    module = ./package-interface;
    src = null;
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out"'';
      }
    ];
  };
  consumer = pkgs.mkDerivation {
    pname = "selected-consumer";
    version = "1";
    module = ./package-consumer;
    moduleDeps = [interface];
    src = null;
    phases = [
      {
        name = "install";
        script = ''mkdir -p "$out"'';
      }
    ];
  };
  handler = pkgs.mkDerivation {
    pname = "selected-handler";
    version = "1";
    outputs = ["out" "tools" "unused"];
    module = ./_selected-output;
    moduleDeps = [interface];
    meta.mainProgram = "handler";
    src = null;
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out" "$tools/bin" "$unused"
          printf '%s\n' selected > "$out/marker"
          printf '%s\n' used > "$tools/bin/handler"
          printf '%s\n' unused > "$unused/marker"
        '';
      }
    ];
  };
  evaluated = lib.evalPackageModules {
    packages = [consumer handler];
    scope = ["profile" "selected-output"];
    operatorModules = [
      {
        aos.packages.echo.enable = true;
        aos.abilities.catalog.operations.inspect.effects.main.input.available = "${handler.tools}";
      }
    ];
  };
  metadata = import ../../lib/packages/artifacts.nix {};
  sourceDescriptor = pkgs.writeTextFile {
    name = "selected-output-source-descriptor";
    text = "retained evaluation inputs";
  };
  graphSourceInputs = metadata.graphInputs {
    graph.nodes.descriptor = {
      input.descriptor = "${sourceDescriptor}";
      handler = {};
    };
    evaluationInputs = [sourceDescriptor];
  };
  roots = builtins.map (artifact: builtins.unsafeDiscardStringContext artifact.path) evaluated.deployment.artifacts;
  inputs = builtins.map builtins.unsafeDiscardStringContext evaluated.deployment.inputs;
  available = metadata.metadata (metadata.reference handler);
  assertSelected = assert graphSourceInputs == [(builtins.toString sourceDescriptor)];
  assert builtins.getContext (builtins.head graphSourceInputs) == builtins.getContext "${sourceDescriptor}";
  assert builtins.length evaluated.deployment.artifacts == 2;
  assert !(builtins.elem (builtins.toString interface) roots);
  assert builtins.elem (builtins.toString handler.tools) inputs;
  assert !(builtins.elem (builtins.toString handler.unused) inputs);
  assert handler.tools.deployment.package.path == builtins.toString handler.tools;
  assert handler.deployment.package.path == builtins.toString handler;
  assert (lib.getOutput "out" handler.tools).deployment.package.path == builtins.toString handler;
  assert (lib.getOutput "unused" handler.tools).deployment.package.path == builtins.toString handler.unused;
  assert (lib.getOutput "tools" (lib.getOutput "out" handler.tools)).deployment.package.path == builtins.toString handler.tools;
  assert (lib.packageModules.recordFor handler.tools).artifacts.package == (lib.packageModules.recordFor handler).artifacts.package;
  assert pkgs.gcc ? deploymentArtifact;
  assert pkgs.getent.deployment.package.outputs == {out = builtins.toString pkgs.getent;};
  assert builtins.all (binding: binding.selector.package != "getent" || binding.path == builtins.toString pkgs.getent) pkgs.getent.qualificationDocument.artifacts;
  assert (lib.getOutput "dev" pkgs.glibc).deployment.package.path == builtins.toString pkgs.glibc.dev;
  assert (lib.getOutput "out" pkgs.glibc.dev).deployment.package.path == builtins.toString pkgs.glibc;
  assert (lib.getOutput "static" pkgs.glibc.dev).deployment.package.path == builtins.toString pkgs.glibc.static;
  assert builtins.getContext (builtins.toJSON pkgs.glibc.dev.deployment) == {};
  assert builtins.getContext (builtins.toJSON handler.deployment.package) == {};
  assert !(builtins.hasAttr (builtins.unsafeDiscardStringContext handler.drvPath) (builtins.getContext handler.documentationArtifact.text));
  assert builtins.any (choice: choice.value == builtins.toString handler.unused) handler.documentation.abilities.catalog.inspect.input.available.type.values;
  assert builtins.getContext (builtins.toJSON available) == {}; true;
in
  assert assertSelected;
    (pkgs.writeTextFile {
      name = "selected-output-fixture";
      destination = "/fixture.json";
      text = builtins.toJSON {
        inherit available;
        document = evaluated.deployment;
        envelope = "${handler.tools.deploymentArtifact}/deployment.json";
        documentation = "${handler.tools.documentationArtifact}/options.json";
        interfacePayload = builtins.unsafeDiscardStringContext (builtins.toString interface);
      };
    })
    // {testPackage = handler;}
