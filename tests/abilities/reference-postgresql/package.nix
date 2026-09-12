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
  transitionTransform ? transition: transition,
}: let
  contract = import ../../../lib/abilities/postgresql.nix {inherit lib;};
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
    name = "ability-reference-postgresql-control-adoption-v2-interrupted";
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
  adoptionV1ProviderSource = mkProviderSource "adoption-v1";
  faultProviderSources = builtins.listToAttrs (map (faultPoint: {
      name = faultPoint;
      value = mkProviderSource faultPoint;
    })
    faultPoints);

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
      runtimeDeps = [selectedControl selectedPostgresql];
      abilityPackage = {
        activationMode = "structured-effects";
        requiredFeatures =
          if stateFormat == null
          then ["abilities-v1"]
          else ["abilities-v1" "provider-state-format-v1"];
        artifacts = [selectedControl selectedPostgresql];
        ownership = [[]];
        exports = {
          postgresql = {
            artifact = selectedProviderSource;
            export = let
              base = postgresqlExport stateFormat;
            in
              base // {transition = transitionTransform base.transition;};
          };
          credential = {
            artifact = packageRuntime;
            export = terminalExport {
              selected = credentialEffects;
              group = "credential";
              handler = "native-credential-delivery-v1";
              requestSchema = credentialRequest;
              methods = credentialMethods;
              persistent = false;
            };
          };
          endpoint = {
            artifact = packageRuntime;
            export = terminalExport {
              selected = endpointEffects;
              group = "endpoint";
              handler = "native-network-endpoint-v1";
              requestSchema = endpointRequest;
              methods = endpointMethods;
              persistent = false;
            };
          };
          network-policy = {
            artifact = packageRuntime;
            export = terminalExport {
              selected = networkPolicyEffects;
              group = "network-policy";
              handler = "native-host-network-policy-v1";
              requestSchema = networkPolicyRequest false;
              methods = networkPolicyMethods;
              persistent = false;
              guarantees = [loopbackIngressGuarantee];
            };
          };
          postgresql-terminal = {
            artifact = packageRuntime;
            export = terminalExport {
              selected = postgresqlEffects;
              group = "postgresql-terminal";
              handler = "native-postgresql-v1";
              requestSchema = postgresqlRequest;
              methods = postgresqlMethods;
              persistent = true;
            };
          };
          storage = {
            artifact = packageRuntime;
            export = terminalExport {
              selected = storageEffects;
              group = "storage";
              handler = "native-host-storage-v1";
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
          };
        };
        handlers = {
          native-credential-delivery-v1 = {
            artifact = packageRuntime;
            entryPoint = "libexec/aos-credential-delivery-handler-v1";
            arguments = credentialRequest;
            result = credentialObservation;
          };
          native-network-endpoint-v1 = {
            artifact = packageRuntime;
            entryPoint = "libexec/aos-network-endpoint-handler-v1";
            arguments = endpointRequest;
            result = endpointObservation;
          };
          native-host-storage-v1 = {
            artifact = packageRuntime;
            entryPoint = "libexec/aos-host-storage-handler-v1";
            arguments = storageRequest;
            result = storageObservation;
          };
          native-host-network-policy-v1 = {
            artifact = packageRuntime;
            entryPoint = "libexec/aos-host-network-policy-handler-v1";
            arguments = networkPolicyRequest false;
            result = networkPolicyObservation;
          };
          native-postgresql-v1 = {
            artifact = packageRuntime;
            entryPoint = "libexec/aos-postgresql-handler-v1";
            arguments = postgresqlRequest;
            result = postgresqlObservation;
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
  adoptionV1Suite = mkSuite {
    pname = "ability-reference-postgresql-adoption-v1";
    selectedControl = control;
    selectedPostgresql = postgresql;
    selectedProviderSource = adoptionV1ProviderSource;
    stateFormat = compatibleStateFormat;
  };
  adoptionV2Suite = mkSuite {
    pname = "ability-reference-postgresql-adoption-v2";
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
    pname = "ability-reference-postgresql-adoption-v2-interrupted";
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
    adoptionV1Suite
    adoptionV2Suite
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
    abilityPackage = {
      activationMode = "contracts-only";
      requirements.postgresql = requirement postgresqlInterface [];
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
