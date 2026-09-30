##! Focused native module and domain checks without full image builds.
{pkgs}: let
  lib = import ../../lib {system = pkgs.bash.system;};
  fixture = import ./deployment-fixture.nix {inherit pkgs lib;};
  checks = {
    modules = import ./modules.nix;
    types = import ./types.nix;
    composition = import ./composition.nix;
    dependencyBarrier = import ./native-dependency-barrier.nix;
    packages = (import ./packages.nix).checks;
    abilityVersions = import ./ability-versions.nix;
    abilityVersionRecipes = import ./ability-version-recipes.nix {inherit pkgs;};
    semver = import ./semver.nix;
    stages = import ./stages.nix;
    frozenHandler = import ./frozen-handler.nix;
    bootConsumers = import ./boot-consumers.nix;
    daemonConsumers = import ./daemon-consumers.nix;
    hubConsumer = import ./hub-consumer.nix;
    securityPolicy = import ./security-policy.nix;
    securityServices = import ./security-services.nix;
    systemdResources = import ./systemd-resources.nix;
    platformReplay = import ./platform-replay.nix;
    observerBootstrap = import ./observer-bootstrap.nix;
    nativeReleaseInventory = import ./release-native-inventory.nix {inherit pkgs;};
    releaseMaintenance = import ./release-maintenance.nix;
    fixtureConsumers = import ./fixture-consumers.nix;
    observerServices = import ./observer-services.nix;
    serviceManagement = import ./service-management.nix;
    serviceSetMerging = import ./service-set-merge.nix;
    serviceFlights = import ./native-service-flights.nix;
    filesystemFirewallFlights = import ../fleet/native-reference-filesystem-fixture-self-test.nix {inherit lib;};
    filesystemFirewallDependencies = import ../fleet/native-reference-domain-graphs.nix {inherit lib pkgs;};
    databaseConsumers = import ./database-consumers.nix;
    runtimeChecks = import ./runtime-checks.nix;
    referenceNginx = import ./reference-nginx.nix;
    platformPackages = import ./platform-packages.nix;
    nativeOperationMatrix = import ./native-operation-matrix.nix;
    configurationPolicy = import ./configuration-policy.nix;
    storageProfile = import ./storage-profile.nix;
    buildInvariants = import ./build-invariants.nix {inherit lib pkgs;};
    runtimeRoles = import ./runtime-roles.nix {inherit lib pkgs;};
    measuredVar = import ./measured-var.nix;
    imageRetirement = import ./image-retirement.nix;
    provenanceProjection = import ./provenance-projection.nix;
    selectedOutputContexts = builtins.isString (import ./selected-output-fixture.nix {inherit pkgs lib;}).drvPath;
    selectedQualificationContexts = builtins.isString (import ./selected-qualification-fixture.nix {inherit pkgs lib;}).drvPath;
    pki = import ./pki.nix {inherit lib pkgs;};
    runtimeDependencyBindings = import ./runtime-dependency-bindings.nix {inherit lib pkgs;};
    qualificationIdentity = import ./qualification-identity.nix {inherit pkgs;};
    configurationLower = import ./configuration-lower.nix {inherit lib pkgs;};
  };
  # Force truth as well as evaluation: false regression predicates must fail.
  checkAll = path: value:
    if builtins.isAttrs value
    then builtins.all (name: checkAll (path ++ [name]) value.${name}) (builtins.attrNames value)
    else if value == true
    then true
    else throw "Native check '${builtins.concatStringsSep "." path}' failed.";
in
  assert checkAll [] checks;
    pkgs.mkDerivation {
      pname = "aos-effect-module-checks";
      version = "0";
      src = null;
      buildDeps = [pkgs.python3];
      runtimeDeps = [fixture];
      phases = [
        {
          name = "check";
          script = ''
            export PYTHONDONTWRITEBYTECODE=1
            ${pkgs.python3}/bin/python3 ${../services/native-handler.py} ${../../pkgs/system/_systemd-abilities/service-handler.py}
            ${pkgs.python3}/bin/python3 ${../services/native-flight-oracle.py} ${../fleet/native-reference-service-flights.py}
            ${pkgs.python3}/bin/python3 ${../fleet/native-filesystem-firewall-oracles-self-test.py} ${../fleet/native-filesystem-firewall-oracles.py}
            ${pkgs.python3}/bin/python3 ${../fleet/native-reference-filesystem-flights-self-test.py} ${../fleet/native-reference-filesystem-flights.py}
            ${pkgs.python3}/bin/python3 ${./managed-paths-test.py} ${../../pkgs/system/_aos-host-policy/managed-paths.py}
            ${pkgs.python3}/bin/python3 ${./network-handler-test.py} ${../../pkgs/system/_systemd-abilities/network-handler.py}
            ${pkgs.python3}/bin/python3 ${../abilities/reference-nginx}/test-binding-handler.py
            ${pkgs.python3}/bin/python3 ${../abilities/native-handler-interception}/self-test.py ${../abilities/native-handler-interception}/native-handler-interception.py
            ${pkgs.python3}/bin/python3 ${../abilities/native-dependency-barrier}/self-test.py ${../abilities/native-dependency-barrier}/native-dependency-barrier.py
            mkdir -p "$out"
            echo PASS > "$out/result"
            ln -s ${fixture}/fixture.json "$out/deployment.json"
          '';
        }
      ];
    }
