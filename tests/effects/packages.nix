##! Native package interfaces, dependency composition, and deferred ownership.
let
  lib = import ../../lib {system = "x86_64-linux";};
  fixturePayload = import ./_fixture-payload.nix;
  modules = import ../../lib/build/package-modules.nix {};
  artifacts = import ../../lib/packages/artifacts.nix {};
  package = name: source: {
    type = "derivation";
    pname = name;
    version = "1";
    system = "x86_64-linux";
    outPath = fixturePayload name;
    module = builtins.path {
      path = source;
      name = "${name}-module";
    };
    meta.mainProgram = "handler";
  };
  interface = package "echo-interface" ./package-interface;
  consumer = package "echo-consumer" ./package-consumer // {moduleDeps = [interface];};
  handler = package "echo-handler" ./package-handler // {moduleDeps = [interface];};
  payload = builtins.removeAttrs (package "plain-payload" ./package-consumer) ["module"];
  evaluated = lib.evalPackageModules {
    scope = ["profile" "main"];
    packages = [consumer handler payload];
    operatorModules = [{aos.packages.echo.enable = true;}];
  };
  documentation =
    (lib.evalPackageModules {
      scope = ["package" "echo-consumer"];
      packageModules = modules.closure [consumer];
    }).documentation;
  extended = lib.evalPackageModules {
    packages = [consumer handler];
    scope = ["profile" "extended"];
    modules = [
      {
        aos.abilities.echo.operations.run.result.options.extra = lib.mkOption {
          type = lib.types.bool;
          description = "Result field added by a second module.";
        };
      }
    ];
  };
  multiOutput =
    consumer
    // {
      outputs = ["out" "tools"];
      out = consumer;
      tools = consumer // {outPath = fixturePayload "echo-consumer-tools";};
    };
  published = multiOutput // {deployment = artifacts.envelope multiOutput;};
  tools = published // {outPath = multiOutput.tools.outPath;};
  selectedOutputs = lib.evalPackageModules {
    scope = ["profile" "multiple-outputs"];
    packages = [published tools];
  };
  node = builtins.head (builtins.attrValues evaluated.deployment.graph.nodes);
in {
  inherit evaluated consumer handler;
  checks = {
    sharedModuleAcrossOutputs = assert builtins.length selectedOutputs.deployment.packages == 2;
    assert builtins.length selectedOutputs.deployment.artifacts == 2;
    assert builtins.length selectedOutputs.documentation.packages == 2; true;
    namedArtifactOutput = assert builtins.toString (artifacts.value published.deployment.package).tools == tools.outPath; true;
    conflictingModuleIdentity = assert !(builtins.tryEval (builtins.deepSeq (modules.closure [published (tools // {deployment = tools.deployment // {package = tools.deployment.package // {version = "2";};};})]) true)).success; true;
    mergedResultModule = assert builtins.attrNames extended.documentation.abilities.echo.run.result == ["extra" "message"]; true;
    payloadWithoutModule = assert builtins.length evaluated.deployment.artifacts == 3; true;
    closure = assert builtins.length evaluated.deployment.packages == 3; true;
    packageOwnership = assert node.owner == "echo-consumer"; true;
    stableScope = assert node.identity == ["profile" "main" "echo-consumer" "echo" "run" "main"]; true;
    handlerArtifact = assert node.handler.executable == "${handler}/bin/handler"; true;
    declarationDocs = assert documentation.abilities.echo.run.input.message.description == "Message returned by the echo operation."; true;
    resultDocs = assert documentation.abilities.echo.run.result.message.description == "Message returned by the selected handler."; true;
    unboundDocumentation = assert !documentation.abilities.echo.run.handlerAvailable; true;
    envelope = assert (artifacts.envelope consumer).moduleDependencies == [(artifacts.moduleReference interface)]; true;
  };
}
