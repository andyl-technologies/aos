##! Focused native module and domain checks without full image builds.
{pkgs}: let
  lib = import ../../lib {system = pkgs.bash.system;};
  fixture = import ./deployment-fixture.nix {inherit pkgs lib;};
  initrdAccountSeed = import ./initrd-account-seed.nix {inherit pkgs;};
  hostActivationNamespace = import ./host-activation-namespace.nix;
  hostActivationInput = builtins.toFile "host-activation-input.json" (builtins.toJSON hostActivationNamespace.input);
  projectedServiceInput = builtins.toFile "projected-service-input.json" (builtins.toJSON hostActivationNamespace.projectedInput);
  projectedServiceUnits = pkgs.runCommand "native-projected-service-units" {} ''
    ${pkgs.buildPackages.systemd}/bin/aos-service-handler render --output-dir "$out" < ${builtins.toFile "projected-services.json" (builtins.toJSON {"control-plane.aos-activate" = hostActivationNamespace.projectedInput;})}
  '';
  packageConvergenceInput = builtins.toFile "package-convergence-input.json" (builtins.toJSON hostActivationNamespace.convergenceRenderInput);
  checks = {
    modules = import ./modules.nix;
    sourceImports = import ./source-imports.nix;
    types = import ./types.nix;
    composition = import ./composition.nix;
    dependencyBarrier = import ./native-dependency-barrier.nix;
    packages = (import ./packages.nix).checks;
    releaseCompatibility = import ./release-compatibility.nix;
    releaseCompatibilityRecipes = import ./release-compatibility-recipes.nix {inherit pkgs;};
    versionShorthand = import ./version-shorthand.nix {inherit pkgs;};
    upstreamVersionPolicy = import ./upstream-version-policy.nix {inherit pkgs;};
    semver = import ./semver.nix;
    stages = import ./stages.nix;
    frozenHandler = import ./frozen-handler.nix;
    bootConsumers = import ./boot-consumers.nix;
    hostActivationNamespace = hostActivationNamespace.checks;
    bakedTestStorage = import ./baked-test-storage.nix {inherit lib pkgs;};
    fleetBootPolicy = import ./fleet-boot-policy.nix {inherit lib pkgs;};
    testDiskProvenance = import ./test-disk-provenance.nix;
    daemonConsumers = import ./daemon-consumers.nix;
    hubConsumer = import ./hub-consumer.nix;
    securityPolicy = import ./security-policy.nix;
    rolePackageDiscovery = import ./role-package-discovery.nix {inherit lib pkgs;};
    rolePackageSelection = import ./role-package-selection.nix;
    hostPolicyDefaults = import ./host-policy-defaults.nix;
    journalPolicy = import ./journal-policy.nix;
    securityServices = import ./security-services.nix {inherit pkgs;};
    systemdResources = import ./systemd-resources.nix;
    platformReplay = import ./platform-replay.nix;
    observerBootstrap = import ./observer-bootstrap.nix;
    bootstrapConfiguration = import ./bootstrap-configuration.nix;
    initrdAccountSeed = initrdAccountSeed.checks;
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
    configurationProvider = import ./configuration-provider.nix {inherit lib pkgs;};
    zfsHardwareMonitoring = import ./zfs-hardware-monitoring.nix {inherit lib pkgs;};
    storageProfile = import ./storage-profile.nix;
    provisioningProjection = import ./provisioning-projection.nix {inherit lib pkgs;};
    buildInvariants = import ./build-invariants.nix {inherit lib pkgs;};
    runtimeDirectoryOwnership = import ./runtime-directory-ownership.nix;
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
      buildDeps = [pkgs.python3 pkgs.systemd];
      runtimeDeps = [fixture initrdAccountSeed.serialization];
      phases = [
        {
          name = "check";
          script = ''
            export PYTHONDONTWRITEBYTECODE=1
            test -f ${initrdAccountSeed.serialization}/result
            ${pkgs.python3}/bin/python3 ${../services/native-handler.py} ${../../pkgs/system/_systemd-abilities/service-handler.py} ${../../pkgs/system/_aos-configuration-provider/aos_configuration.py} ${../../pkgs/system/_aos-configuration-provider/handler.py} ${pkgs.aos-configuration-provider}/bin/aos-configuration-provider ${pkgs.systemd}/bin/systemd-analyze ${hostActivationInput} ${packageConvergenceInput} ${projectedServiceInput} ${projectedServiceUnits}
            ${pkgs.python3}/bin/python3 ${../services/native-flight-oracle.py} ${../fleet/native-reference-service-flights.py}
            ${pkgs.python3}/bin/python3 ${../fleet/native-filesystem-firewall-oracles-self-test.py} ${../fleet/native-filesystem-firewall-oracles.py}
            ${pkgs.python3}/bin/python3 ${../fleet/native-reference-filesystem-flights-self-test.py} ${../fleet/native-reference-filesystem-flights.py}
            ${pkgs.python3}/bin/python3 ${./managed-paths-test.py} ${../../pkgs/system/_aos-host-policy/managed-paths.py}
            ${pkgs.python3}/bin/python3 ${../build/composefs-directory-source.py} ${../../pkgs/system/build-composefs-dump.py}
            ${pkgs.python3}/bin/python3 ${./host-store-seed-test.py} ${pkgs.bash}/bin/bash ${pkgs.coreutils} ${../../pkgs/boot/_aos-boot-preparations/aos-host-store-seed.sh} ${pkgs.nix}
            ${pkgs.python3}/bin/python3 ${./mount-var-test.py} ${pkgs.bash}/bin/bash ${../../pkgs/boot/_aos-boot-preparations/mount-var.sh}
            ${pkgs.python3}/bin/python3 ${./seed-profile-reconciliation.py} ${pkgs.bash}/bin/bash ${../../pkgs/boot/_aos-boot-preparations/aos-seed-profiles.sh} ${pkgs.coreutils}/bin ${pkgs.jq}/bin
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
