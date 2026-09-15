##! Production PostgreSQL ability fixture with native host-resource effects.
{
  bash,
  coreutils,
  jq,
  lib,
  mkDerivation,
  packageRuntime,
  postgresql,
  writeTextFile,
  effectQualification ? false,
  transitionTransform ? transition: transition,
}: let
  contract = import ../../../pkgs/storage/_postgresql-ability/contract.nix {inherit lib;};
  inherit
    (contract)
    aggregation
    compatibleStateFormat
    credentialEffects
    credentialMethods
    credentialObservation
    credentialRequest
    endpointEffects
    endpointMethods
    endpointObservation
    endpointRequest
    incompatibleStateFormat
    lifecycle
    loopbackIngressGuarantee
    networkPolicyEffects
    networkPolicyMethods
    networkPolicyObservation
    networkPolicyRequest
    output
    postgresqlContribution
    postgresqlEffects
    postgresqlExport
    postgresqlInterface
    postgresqlMethods
    postgresqlObservation
    postgresqlProvider
    postgresqlRequest
    providerSource
    requirement
    requirementWithGuarantees
    storageEffects
    storageMethods
    storageObservation
    storageRequest
    terminalExport
    ;

  controlStateHelpers = writeTextFile {
    name = "ability-reference-postgresql-control-state";
    destination = "/libexec/postgresql-control-state.sh";
    text = builtins.readFile ./postgresql-control-state.sh;
  };
  controlSqlHelpers = writeTextFile {
    name = "ability-reference-postgresql-control-sql";
    destination = "/libexec/postgresql-control-sql.sh";
    text = builtins.readFile ./postgresql-control-sql.sh;
  };

  mkControl = {
    name,
    distribution,
    faultPoint ? "",
  }:
    writeTextFile {
      inherit name;
      destination = "/bin/postgresql-control";
      executable = true;
      text =
        builtins.replaceStrings
        [
          "@bash@"
          "@coreutils@"
          "@jq@"
          "@postgresql@"
          "@faultPoint@"
          "@stateHelpers@"
          "@sqlHelpers@"
        ]
        [
          (builtins.toString bash)
          (builtins.toString coreutils)
          (builtins.toString jq)
          (builtins.toString distribution)
          faultPoint
          "${controlStateHelpers}/libexec/postgresql-control-state.sh"
          "${controlSqlHelpers}/libexec/postgresql-control-sql.sh"
        ]
        (builtins.readFile ./postgresql-control.sh);
      meta = {
        description = "Authenticated native ability control for PostgreSQL";
        license = "Apache-2.0";
        mainProgram = "postgresql-control";
      };
    };

  control = mkControl {
    name = "ability-reference-postgresql-control";
    distribution = postgresql;
  };
  upgradePostgresql = mkDerivation {
    pname = "ability-reference-postgresql-distribution-upgrade";
    version = "1.0.0";
    runtimeDeps = [postgresql];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          cp -R ${postgresql}/* "$out/"
          chmod -R u+w "$out"
          rm -f "$out/nix-support/aos-target-platform"
        '';
      }
    ];
    meta = {
      description = "Distinct same-major PostgreSQL artifact for upgrade qualification";
      license = "PostgreSQL";
    };
  };
  upgradeControl = mkControl {
    name = "ability-reference-postgresql-control-upgrade";
    distribution = upgradePostgresql;
  };
  adoptionInterruptedControl = mkControl {
    name = "ability-reference-postgresql-control-adoption-candidate-interrupted";
    distribution = upgradePostgresql;
    faultPoint = "hold-quarantine-after-start";
  };

  faultPoints = [
    "hold-quarantine-after-start"
    "crash-initdb-before-pg-version"
    "crash-initdb-after-pg-version"
    "crash-quarantine-config"
    "crash-quarantine-hba"
    "crash-quarantine-ident"
    "crash-publish-final-config"
    "crash-publish-final-hba"
    "crash-publish-final-ident"
  ];
  faultControls = builtins.listToAttrs (map (faultPoint: {
      name = faultPoint;
      value = mkControl {
        name = "ability-reference-postgresql-control-${faultPoint}";
        distribution = postgresql;
        inherit faultPoint;
      };
    })
    faultPoints);

  mkProviderSource = suffix:
    mkDerivation {
      pname = "ability-reference-postgresql-provider-${suffix}";
      version = "1.0.0";
      src = providerSource;
      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out"
            cp ${providerSource}/default.nix "$out/default.nix"
          '';
        }
      ];
      meta = {
        description = "Distinct pure provider artifact for PostgreSQL qualification";
        license = "Apache-2.0";
      };
    };
  upgradeProviderSource = mkProviderSource "upgrade";
  adoptionSourceProviderSource = mkProviderSource "adoption-source";
  faultProviderSources = builtins.listToAttrs (map (faultPoint: {
      name = faultPoint;
      value = mkProviderSource faultPoint;
    })
    faultPoints);
  packageRuntimeSelector = lib.abilities.packageOutput {
    package = "aos";
    output = "packageRuntime";
  };

  mkSuite = {
    pname,
    selectedControl,
    selectedPostgresql,
    selectedProviderSource,
    stateFormat ? null,
  }:
    mkDerivation {
      inherit pname;
      version = "1.0.0";
      src = selectedProviderSource;
      runtimeDeps = [packageRuntime selectedControl selectedPostgresql];
      abilities = {
        config.aos.abilities = lib.abilities.projectDefinitions {
          postgresql = {
            artifacts = [
              (lib.abilities.packageOutput {package = selectedControl.pname;})
              (lib.abilities.packageOutput {package = selectedPostgresql.pname;})
            ];
            requiredFeatures = lib.optional (stateFormat != null) "provider-state-format-v1";
            definition = let
              base = postgresqlExport stateFormat;
            in
              base
              // {
                transition = transitionTransform (
                  if effectQualification
                  then postgresqlProvider.effectQualificationTransition
                  else base.transition
                );
              };
          };
          credential = {
            artifact = packageRuntimeSelector;
            definition = terminalExport {
              selected = credentialEffects;
              group = "credential";
              handler = "native-credential-delivery";
              requestSchema = credentialRequest;
              methods = credentialMethods;
              persistent = false;
            };
            handler = {
              artifact = packageRuntimeSelector;
              entryPoint = "libexec/aos-credential-delivery-handler";
              arguments = credentialRequest;
              result = credentialObservation;
            };
          };
          endpoint = {
            artifact = packageRuntimeSelector;
            definition = terminalExport {
              selected = endpointEffects;
              group = "endpoint";
              handler = "native-network-endpoint";
              requestSchema = endpointRequest;
              methods = endpointMethods;
              persistent = false;
            };
            handler = {
              artifact = packageRuntimeSelector;
              entryPoint = "libexec/aos-network-endpoint-handler";
              arguments = endpointRequest;
              result = endpointObservation;
            };
          };
          network-policy = {
            artifact = packageRuntimeSelector;
            definition = terminalExport {
              selected = networkPolicyEffects;
              group = "network-policy";
              handler = "native-host-network-policy";
              requestSchema = networkPolicyRequest false;
              methods = networkPolicyMethods;
              persistent = false;
              guarantees = [loopbackIngressGuarantee];
            };
            handler = {
              artifact = packageRuntimeSelector;
              entryPoint = "libexec/aos-host-network-policy-handler";
              arguments = networkPolicyRequest false;
              result = networkPolicyObservation;
            };
          };
          postgresql-terminal = {
            artifact = packageRuntimeSelector;
            definition = terminalExport {
              selected = postgresqlEffects;
              group = "postgresql-terminal";
              handler = "native-postgresql";
              requestSchema = postgresqlRequest;
              methods = postgresqlMethods;
              persistent = true;
            };
            handler = {
              artifact = packageRuntimeSelector;
              entryPoint = "libexec/aos-postgresql-handler";
              arguments = postgresqlRequest;
              result = postgresqlObservation;
            };
          };
          storage = {
            artifact = packageRuntimeSelector;
            definition = terminalExport {
              selected = storageEffects;
              group = "storage";
              handler = "native-host-storage";
              requestSchema = storageRequest;
              methods = storageMethods;
              persistent = true;
              selectedLifecycle = {
                stableResourceIdentity = true;
                releasesEphemeralOnDisable = true;
                retainsPersistentByDefault = true;
                persistentDeleteMethod = null;
              };
            };
            handler = {
              artifact = packageRuntimeSelector;
              entryPoint = "libexec/aos-host-storage-handler";
              arguments = storageRequest;
              result = storageObservation;
            };
          };
        };
      };

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/share/ability-reference-postgresql"
            ln -s ${selectedControl}/bin/postgresql-control "$out/bin/postgresql-control"
            printf '%s\n' 'production PostgreSQL ability fixture' \
              > "$out/share/ability-reference-postgresql/README"
          '';
        }
      ];

      meta = {
        description = "Production PostgreSQL ability fixture";
        license = "Apache-2.0";
      };
    };

  suite = mkSuite {
    pname = "ability-reference-postgresql";
    selectedControl = control;
    selectedPostgresql = postgresql;
    selectedProviderSource = providerSource;
  };
  upgradeSuite = mkSuite {
    pname = "ability-reference-postgresql-upgrade";
    selectedControl = upgradeControl;
    selectedPostgresql = upgradePostgresql;
    selectedProviderSource = upgradeProviderSource;
  };
  adoptionSourceSuite = mkSuite {
    pname = "ability-reference-postgresql-adoption-source";
    selectedControl = control;
    selectedPostgresql = postgresql;
    selectedProviderSource = adoptionSourceProviderSource;
    stateFormat = compatibleStateFormat;
  };
  adoptionCandidateSuite = mkSuite {
    pname = "ability-reference-postgresql-adoption-candidate";
    selectedControl = upgradeControl;
    selectedPostgresql = upgradePostgresql;
    selectedProviderSource = upgradeProviderSource;
    stateFormat = compatibleStateFormat;
  };
  adoptionIncompatibleSuite = mkSuite {
    pname = "ability-reference-postgresql-adoption-incompatible";
    selectedControl = upgradeControl;
    selectedPostgresql = upgradePostgresql;
    selectedProviderSource = upgradeProviderSource;
    stateFormat = incompatibleStateFormat;
  };
  adoptionInterruptedSuite = mkSuite {
    pname = "ability-reference-postgresql-adoption-candidate-interrupted";
    selectedControl = adoptionInterruptedControl;
    selectedPostgresql = upgradePostgresql;
    selectedProviderSource = faultProviderSources."hold-quarantine-after-start";
    stateFormat = compatibleStateFormat;
  };
  faultSuites = builtins.listToAttrs (map (faultPoint: {
      name = faultPoint;
      value = mkSuite {
        pname = "ability-reference-postgresql-fault-${faultPoint}";
        selectedControl = faultControls.${faultPoint};
        selectedPostgresql = postgresql;
        selectedProviderSource = faultProviderSources.${faultPoint};
      };
    })
    faultPoints);
in {
  inherit
    adoptionIncompatibleSuite
    adoptionInterruptedSuite
    adoptionSourceSuite
    adoptionCandidateSuite
    control
    faultControls
    faultSuites
    suite
    upgradeControl
    upgradePostgresql
    upgradeProviderSource
    upgradeSuite
    ;

  consumer = mkDerivation {
    pname = "ability-reference-postgresql-consumer";
    version = "1.0.0";
    src = providerSource;
    abilities = {
      config.aos.abilities.requirementTemplates.postgresql = requirement postgresqlInterface [];
    };
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/share/ability-reference-postgresql-consumer"
          printf '%s\n' 'PostgreSQL SQL-probe consumer fixture' \
            > "$out/share/ability-reference-postgresql-consumer/README"
        '';
      }
    ];
    meta = {
      description = "PostgreSQL consumer-context readiness fixture";
      license = "Apache-2.0";
    };
  };
}
