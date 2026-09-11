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
}: let
  inherit (lib.abilities) schemas;

  providerSource = ./providers/postgresql;

  interface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  postgresqlInterface =
    interface
    "aos.postgresql"
    "sha256:0c2cfe5a8480b0dd1113e56414241cb81c54c080a5e0bc63be60b6d033464898";
  endpointEffects =
    interface
    "aos.network-endpoint-effects"
    "sha256:6b4d345ab4350917a04b770f0ac4b82888ffe6ef7e647caa9fe94ccb9f9dac6a";
  storageEffects =
    interface
    "aos.host-storage-effects"
    "sha256:f87cd9e408e229dd2fb121ee7f49d57bc452cb427da539cb35cb4c66256aac0f";
  networkPolicyEffects =
    interface
    "aos.host-network-policy-effects"
    "sha256:13851cb0af020c2ba09663d562017a706124e00ae4a66279d09bf9ffec3dd199";
  credentialEffects =
    interface
    "aos.credential-delivery-effects"
    "sha256:bc251c0837c1d453a6c5840d9146d9e27a95ad82032d9b4c60baf40d293cf1eb";
  postgresqlEffects =
    interface
    "aos.postgresql-effects"
    "sha256:6a1e7d5fb03d9b91127144a64fb96e4c98f4995e7f4f0de258f79fb61fbb9fd6";

  loopbackIngressGuarantee = lib.abilities.guarantee {
    name = "aos.guarantee.loopback-tcp-ingress-enforcement";
    version = 1;
    descriptor = "sha256:6b12b1c4db768f272434c6e43ca8c484887fc0fa3a51be2ae2784982325c2092";
  };

  string = maximum:
    schemas.string {
      maxLength = maximum;
      syntax = null;
    };
  localKey = schemas.string {
    maxLength = 128;
    syntax = "local-key-v1";
  };
  postgresqlName = schemas.string {
    maxLength = 63;
    syntax = "local-key-v1";
  };
  revision = string 71;
  optionalRevision = schemas.optional revision;
  path = string 4096;

  endpoint = schemas.record {
    fields = {
      address = string 15;
      port = schemas.integer {
        minimum = 1024;
        maximum = 65535;
      };
      transport = schemas.enum ["tcp"];
    };
    optional = [];
  };
  endpointRequest = schemas.record {
    fields = {
      address = schemas.enum ["127.0.0.1"];
      port = schemas.integer {
        minimum = 0;
        maximum = 65535;
      };
      transport = schemas.enum ["tcp"];
    };
    optional = [];
  };
  credentialView = schemas.record {
    fields = {
      path = path;
      version = revision;
    };
    optional = [];
  };
  credentialRequest = schemas.record {
    fields = {
      version = revision;
      view = localKey;
    };
    optional = [];
  };
  credentialObservation = schemas.record {
    fields = {
      delivered = schemas.boolean;
      observed_version = optionalRevision;
      requested_version = revision;
      schema = schemas.enum ["aos.ability.credential-delivery-observation/v1"];
      view = localKey;
    };
    optional = [];
  };
  storageRequest = schemas.record {
    fields = {
      cluster = localKey;
      purpose = localKey;
    };
    optional = [];
  };
  networkPolicyRequest = requiredEndpoint:
    schemas.record {
      fields = {
        direction = schemas.enum ["ingress"];
        endpoint =
          if requiredEndpoint
          then endpoint
          else schemas.optional endpoint;
        protocol = schemas.enum ["tcp"];
      };
      optional = [];
    };
  postgresqlRequest = schemas.record {
    fields = {
      cluster = localKey;
      configuration_revision = revision;
      database = postgresqlName;
      credential_view = schemas.optional credentialView;
      endpoint = schemas.optional endpoint;
      role = postgresqlName;
      storage_path = schemas.optional path;
    };
    optional = [];
  };
  postgresqlContribution = schemas.record {
    fields = {
      cluster = localKey;
      database = postgresqlName;
      role = postgresqlName;
      credential_version = revision;
    };
    optional = [];
  };

  revisionedObservation = schema: fields:
    schemas.record {
      fields =
        fields
        // {
          observed_revision = optionalRevision;
          requested_revision = revision;
          inherit schema;
        };
      optional = [];
    };
  endpointObservation =
    revisionedObservation
    (schemas.enum ["aos.ability.network-endpoint-observation/v1"])
    {
      endpoint = schemas.optional endpoint;
      owned = schemas.boolean;
    };
  storageObservation =
    revisionedObservation
    (schemas.enum ["aos.ability.host-storage-observation/v1"])
    {
      attached = schemas.boolean;
      exists = schemas.boolean;
      path = path;
    };
  networkPolicyObservation =
    revisionedObservation
    (schemas.enum ["aos.ability.host-network-policy-observation/v1"])
    {
      active = schemas.boolean;
      endpoint = schemas.optional endpoint;
    };
  postgresqlObservation = schemas.record {
    fields = {
      cluster = localKey;
      database = postgresqlName;
      endpoint = schemas.optional endpoint;
      observed_revision = optionalRevision;
      production_control_path = schemas.enum ["/bin/postgresql-control"];
      ready = schemas.boolean;
      role = postgresqlName;
      schema = schemas.enum ["aos.ability.postgresql-observation/v1"];
      submitted_revision = revision;
    };
    optional = [];
  };

  output = schema: phase: lifetime: {
    inherit schema phase lifetime;
    visibility = "protected";
  };
  runtimeOutput = schema: lifetime: output schema "runtime" lifetime;
  observationOutput = schema: output schema "observation" "attempt";

  lifecycle = persistent: {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = !persistent;
    retainsPersistentByDefault = persistent;
    persistentDeleteMethod = null;
  };
  aggregation = group: {
    scope = "provider-instance";
    key = "slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = group;
  };
  requirementWithGuarantees = selected: methods: guarantees: {
    inherit (selected) abi descriptor;
    interface = selected.name;
    inherit methods guarantees;
    strength = "required";
    fallback = null;
  };
  requirement = selected: methods: requirementWithGuarantees selected methods [];
  outcome = evidence: {
    completionEvidence = evidence;
    observationEvidence = evidence;
    supportsRejectedBeforeEffect = true;
    indeterminate = "reconcile";
  };
  method = target: name: operationFamily: parameters: outputs: evidence: {
    targetResource = target;
    inherit operationFamily parameters outputs;
    permittedOperations = [name];
    guarantees = [];
    outcome = outcome evidence;
  };

  endpointMethods = {
    materialize =
      method endpointEffects.name "materialize" {
        kind = "network-endpoint";
        action = "materialize";
      }
      endpointRequest {
        endpoint = runtimeOutput endpoint "instance";
      }
      endpointObservation;
    observe =
      method endpointEffects.name "observe" {
        kind = "network-endpoint";
        action = "observe";
      }
      endpointRequest {
        endpoint = runtimeOutput endpoint "instance";
      }
      endpointObservation;
    release =
      method endpointEffects.name "release" {
        kind = "network-endpoint";
        action = "release";
      }
      endpointRequest {}
      endpointObservation;
  };
  storageMethods = {
    ensure =
      method storageEffects.name "ensure" {
        kind = "host-storage";
        action = "ensure";
      }
      storageRequest {
        path = runtimeOutput path "persistent";
      }
      storageObservation;
    observe =
      method storageEffects.name "observe" {
        kind = "host-storage";
        action = "observe";
      }
      storageRequest {
        path = runtimeOutput path "persistent";
      }
      storageObservation;
    release =
      method storageEffects.name "release" {
        kind = "host-storage";
        action = "release";
      }
      storageRequest {}
      storageObservation;
  };
  networkPolicyMethods = let
    withEnforcement = methodContract:
      methodContract
      // {
        guarantees = [loopbackIngressGuarantee];
      };
  in {
    apply = withEnforcement (
      method networkPolicyEffects.name "apply" {
        kind = "host-network-policy";
        action = "apply";
      } (networkPolicyRequest true) {
        active = runtimeOutput schemas.boolean "instance";
      }
      networkPolicyObservation
    );
    observe = withEnforcement (
      method networkPolicyEffects.name "observe" {
        kind = "host-network-policy";
        action = "observe";
      } (networkPolicyRequest true) {
        active = runtimeOutput schemas.boolean "instance";
      }
      networkPolicyObservation
    );
    remove =
      method networkPolicyEffects.name "remove" {
        kind = "host-network-policy";
        action = "remove";
      } (networkPolicyRequest false) {}
      networkPolicyObservation;
  };
  credentialMethods = {
    acquire =
      method credentialEffects.name "acquire" {
        kind = "credential";
        action = "acquire";
      }
      credentialRequest {
        credential-view = runtimeOutput credentialView "instance";
      }
      credentialObservation;
    deliver =
      method credentialEffects.name "deliver" {
        kind = "credential";
        action = "deliver";
      }
      credentialRequest {
        credential-view = runtimeOutput credentialView "instance";
      }
      credentialObservation;
    release =
      method credentialEffects.name "release" {
        kind = "release-resource";
      }
      credentialRequest {}
      credentialObservation;
  };
  postgresqlMethods = {
    materialize =
      method postgresqlEffects.name "materialize" {
        kind = "prepare-managed-configuration";
      }
      postgresqlRequest {
        configuration-revision = runtimeOutput revision "persistent";
      }
      postgresqlObservation;
    observe =
      method postgresqlEffects.name "observe" {
        kind = "observe-readiness";
      }
      postgresqlRequest {
        observed-revision = observationOutput optionalRevision;
        ready = observationOutput schemas.boolean;
        submitted-revision = observationOutput revision;
      }
      postgresqlObservation;
    start =
      method postgresqlEffects.name "start" {
        kind = "service-lifecycle";
        action = "start";
      }
      postgresqlRequest {}
      postgresqlObservation;
    restart =
      method postgresqlEffects.name "restart" {
        kind = "service-lifecycle";
        action = "restart";
      }
      postgresqlRequest {}
      postgresqlObservation;
    stop =
      method postgresqlEffects.name "stop" {
        kind = "service-lifecycle";
        action = "stop";
      }
      postgresqlRequest {}
      postgresqlObservation;
  };

  terminalExport = {
    selected,
    group,
    handler,
    requestSchema,
    methods,
    persistent,
    guarantees ? [],
  }:
    lib.abilities.define {
      interface = selected.name;
      abi = selected.abi;
      inherit requestSchema methods handler;
      outputs = {};
      lifecycle = lifecycle persistent;
      inherit guarantees;
      aggregation = aggregation group;
      requires = {};
      ownsResourceKinds = [selected.name];
    };

  postgresqlProvider = import ./providers/postgresql/default.nix;

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
  }:
    mkDerivation {
      inherit pname;
      version = "1.0.0";
      src = selectedProviderSource;
      runtimeDeps = [selectedControl selectedPostgresql];
      abilityPackage = {
        activationMode = "structured-effects";
        artifacts = [selectedControl selectedPostgresql];
        ownership = [[]];
        exports = {
          postgresql = {
            artifact = selectedProviderSource;
            export = lib.abilities.define {
              interface = postgresqlInterface.name;
              abi = postgresqlInterface.abi;
              requestSchema = postgresqlContribution;
              outputs.clusters = output (schemas.map {
                keyMaxLength = 128;
                keySyntax = "local-key-v1";
                maxEntries = 64;
                value = schemas.resourceReference;
              }) "planning" "persistent";
              methods = {};
              lifecycle = lifecycle true;
              guarantees = [];
              aggregation = aggregation "postgresql";
              requires = {
                credential = requirement credentialEffects ["acquire" "deliver" "release"];
                endpoint = requirement endpointEffects ["materialize" "observe" "release"];
                network-policy =
                  requirementWithGuarantees
                  networkPolicyEffects
                  ["apply" "observe" "remove"]
                  [loopbackIngressGuarantee];
                postgresql-terminal = requirement postgresqlEffects ["materialize" "observe" "restart" "start" "stop"];
                storage = requirement storageEffects ["ensure" "observe" "release"];
              };
              composeEntry = "compose";
              transitionEntry = "transition";
              ownsResourceKinds = [postgresqlInterface.name];
              compose = postgresqlProvider.compose;
              transition = postgresqlProvider.transition;
            };
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
