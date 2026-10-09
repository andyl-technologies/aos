##! Real package artifacts for the Rust package-deployment integration driver.
{
  pkgs,
  lib,
}: let
  emptyPackage = name: module: moduleDeps:
    pkgs.mkDerivation {
      pname = name;
      version = "1";
      inherit module moduleDeps;
      src = null;
      phases = [
        {
          name = "install";
          script = ''mkdir -p "$out"'';
        }
      ];
    };
  interface = emptyPackage "echo-interface" ./package-interface [];
  consumer = emptyPackage "echo-consumer" ./package-consumer [interface];
  payload = emptyPackage "plain-payload" null [];
  handler =
    (pkgs.writeShellScriptBin "handler" ''
      case "$1" in
        apply) exec ${pkgs.jq}/bin/jq '{message: .input.message}' ;;
        remove) exec ${pkgs.jq}/bin/jq '{}' ;;
        observe) exec ${pkgs.jq}/bin/jq '{status: "retry-safe"}' ;;
        *) exit 1 ;;
      esac
    '').overrideAttrs (_: {
      catalogName = "echo-handler";
      version = "1";
      module = ./package-handler;
      moduleDeps = [interface];
    });
  packages = [consumer handler payload];
  configuration = builtins.path {
    path = ./package-operator;
    name = "echo-configuration";
  };
  evaluated = lib.evalPackageModules {
    scope = ["profile" "integration"];
    inherit packages;
    operatorModules = [configuration];
  };
in
  pkgs.writeTextFile {
    name = "package-deployment-fixture";
    destination = "/fixture.json";
    text = builtins.toJSON {
      library = lib.packageModuleLibrary;
      inherit configuration;
      selectedRoots = map builtins.toString packages;
      envelopes = builtins.map (package: package.deployment) (packages ++ [interface]);
      # Replay needs the module-only interface companion as well as payload envelopes.
      publications =
        builtins.map (package: {
          envelope = "${package.deploymentArtifact}/deployment.json";
          documentation = "${package.documentationArtifact}/options.json";
        })
        (packages ++ [interface]);
      document = evaluated.deployment;
    };
  }
