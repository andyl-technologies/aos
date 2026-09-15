##! Fixed-point checks for the package-owned release maintenance services.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  program = name: {
    artifact = lib.abilities.packageOutput {};
    entry_point = "bin/${name}";
    arguments = ["--fixed"];
  };
  qualifiedProgram = name: {
    artifact = lib.abilities.packageOutput {package = "aos";};
    entry_point = "bin/${name}";
    arguments = ["--fixed"];
  };
  enabledConfiguration = {
    enable = true;
    releaseProgram = program "release";
    timestampProgram = program "timestamp";
    backupProgram = program "backup";
    restoreCheckProgram = program "restore-check";
    alertProgram = program "alert";
    releaseCredentials.signing-key = "release-signing-key";
    timestampCredentials.timestamp-key = "timestamp-signing-key";
    backupCredentials.backup-key = "backup-encryption-key";
    alertCredentials.alert-token = "alert-delivery-token";
  };
  evaluate = releaseCoordinator:
    lib.evalModules {
      inherit lib;
      modules = [
        lib.abilities.module
        {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
            contributable = true;
          };
          aos.abilities.environment = {
            authority = "deployment";
            key = "release-coordinator-test";
            stage = "host";
          };
          aos.services.releaseCoordinator = releaseCoordinator;
        }
      ];
      packageModules = [
        {
          name = "aos";
          module = ../../pkgs/tools/aos/_release-coordinator/module.nix;
        }
      ];
    };
  disabled = evaluate {};
  enabled = evaluate enabledConfiguration;
  missingPrograms = evaluate {enable = true;};
  sharedCredential = evaluate (enabledConfiguration
    // {
      releaseCredentials.signing-key = "shared-key";
      backupCredentials.backup-key = "shared-key";
    });
  abilities = evaluated: evaluated.config.aos.abilities;
  requests = evaluated: (abilities evaluated).requests;
  request = name: (requests enabled)."aos:${name}".parameters;
  assertionsHold = evaluated:
    builtins.all (assertion: assertion.assertion) evaluated.config.assertions;
  resultOf = requestName: output: {
    _type = "aos-request-output-reference";
    request = "aos:${requestName}";
    inherit output;
  };
  requirementNames = builtins.attrNames (abilities enabled).requirementTemplates;
  expectedRequirements = builtins.sort builtins.lessThan [
    "aos:credential-delivery"
    "aos:group-resolution"
    "aos:linux-service-isolation"
    "aos:named-credential-resolution"
    "aos:network-readiness"
    "aos:persistent-storage-allocation"
    "aos:principal-resolution"
    "aos:scheduled-activation"
    "aos:service-activation"
    "aos:service-concurrency"
    "aos:service-credentials"
    "aos:service-dependencies"
    "aos:service-failure-policy"
    "aos:service-identity"
    "aos:service-isolation"
    "aos:service-lifecycle"
    "aos:service-logging"
    "aos:service-storage"
    "aos:storage-allocation"
  ];
  lifecycleNames = [
    "release"
    "timestamp"
    "backup"
    "restore-check"
    "alert-release"
    "alert-timestamp"
    "alert-backup"
    "alert-restore-check"
  ];
  scheduledNames = ["timestamp" "backup" "restore-check"];
  concurrentNames = ["release" "backup" "restore-check"];
  failedOperations = ["release" "timestamp" "backup" "restore-check"];
  portableOptionTree = options:
    builtins.all
    (name: let
      option = options.${name};
    in
      if option ? type
      then option.type ? _abilitySchema
      else portableOptionTree option)
    (builtins.attrNames options);
in
  assert assertionsHold enabled;
  assert !assertionsHold missingPrograms;
  assert !assertionsHold sharedCredential;
  assert (abilities disabled).instances == {};
  assert (abilities disabled).requests == {};
  assert (abilities disabled).requirementTemplates == (abilities enabled).requirementTemplates;
  assert requirementNames == expectedRequirements;
  assert portableOptionTree enabled.options.aos.services.releaseCoordinator;
  assert builtins.all
  (name: (request "${name}-lifecycle").service == name)
  lifecycleNames;
  assert builtins.all
  (name: !(request "${name}-lifecycle").enabled)
  lifecycleNames;
  assert (request "release-lifecycle").start_timeout_millis == 604800000;
  assert (request "timestamp-lifecycle").start_timeout_millis == 900000;
  assert (request "backup-lifecycle").start_timeout_millis == 21600000;
  assert (request "restore-check-lifecycle").start_timeout_millis == 21600000;
  assert builtins.all
  (name: (request "${name}-lifecycle").stop_timeout_millis == 90000)
  lifecycleNames;
  assert builtins.all
  (name: (request "${name}-schedule").enabled)
  scheduledNames;
  assert builtins.all
  (name: (request "${name}-schedule").persistent)
  scheduledNames;
  assert builtins.all
  (name: (request "${name}-schedule").accuracy_millis == 60000)
  scheduledNames;
  assert builtins.all
  (name: (request "${name}-schedule").randomized_delay_millis == 300000)
  scheduledNames;
  assert builtins.all
  (name:
    (request "${name}-activation").bindings
    == [
      {
        name = "schedule";
        resource = resultOf "${name}-schedule" "activation-resource";
        relationship = "resource-triggers-service";
      }
    ])
  scheduledNames;
  assert builtins.all
  (name:
    request "${name}-concurrency"
    == {
      service = name;
      enabled = false;
      group = "release-state";
      conflict = "reject";
    })
  concurrentNames;
  assert !(requests enabled) ? "aos:timestamp-concurrency";
  assert (request "restore-check-dependencies").after
  == [(resultOf "backup-lifecycle" "service-resource")];
  assert (request "release-dependencies").after
  == [(resultOf "network-readiness" "readiness-resource")];
  assert (request "timestamp-dependencies").wants
  == [(resultOf "network-readiness" "readiness-resource")];
  assert (request "restore-check-isolation").network == "none";
  assert (request "restore-check-linux_isolation").network_address_families == ["unix"];
  assert (request "release-isolation").home_access == "inaccessible";
  assert builtins.all
  (name: (request "${name}-isolation").home_access == "inaccessible")
  lifecycleNames;
  assert builtins.all
  (name: !((request "${name}-group") ? requested_id))
  ["aos-release" "aos-release-timestamp" "aos-release-backup" "aos-release-monitor"];
  assert builtins.all
  (name: !((request "${name}-principal") ? requested_id))
  ["aos-release" "aos-release-timestamp" "aos-release-backup" "aos-release-monitor"];
  assert (request "aos-release-backup-principal").supplementary_groups
  == [
    (resultOf "aos-release-group" "group-name")
    (resultOf "aos-release-timestamp-group" "group-name")
  ];
  assert (request "release-state")
  == {
    name = "aos-release-coordinator";
    purpose = "state";
    mode = "0750";
    requested_path = "/var/lib/aos-release-coordinator";
    owner = resultOf "aos-release-principal" "principal-name";
    group = resultOf "aos-release-group" "group-name";
  };
  assert (request "restore-runtime").requested_path == "/run/aos-release-restore-check";
  assert (request "backup-storage").mounts
  == [
    {
      name = "state";
      source = resultOf "backup-state" "planned-path";
      access = "read-write";
      ownership = "provider";
    }
    {
      name = "runtime";
      source = resultOf "backup-runtime" "planned-path";
      access = "read-write";
      ownership = "provider";
    }
    {
      name = "release-state";
      source = resultOf "release-state" "planned-path";
      access = "read-only";
      ownership = "provider";
    }
    {
      name = "timestamp-state";
      source = resultOf "timestamp-state" "planned-path";
      access = "read-only";
      ownership = "provider";
    }
  ];
  assert (request "release-credential-signing-key-source")
  == {
    name = "release-signing-key";
    scope = "system";
  };
  assert (request "release-credential-signing-key")
  == {
    name = "signing-key";
    source = resultOf "release-credential-signing-key-source" "credential-resource";
    encrypted = false;
  };
  assert (request "release-credentials").views
  == [
    {
      name = "signing-key";
      reference = resultOf "release-credential-signing-key" "credential-path";
      encrypted = false;
      optional = false;
    }
  ];
  assert builtins.all
  (failedOperation:
    (request "${failedOperation}-failure_policy").handlers
    == [(resultOf "alert-${failedOperation}-lifecycle" "service-resource")])
  failedOperations;
  assert builtins.all
  (failedOperation:
    (builtins.head (request "alert-${failedOperation}-lifecycle").start).executable.arguments
    == ["--fixed" failedOperation])
  failedOperations;
  assert !(lib.hasInfix "systemd" (builtins.toJSON (requests enabled)));
  assert !(lib.hasInfix ".service" (builtins.toJSON (requests enabled)));
  assert !(lib.hasInfix "/nix/store" (builtins.toJSON (requests enabled)));
  assert builtins.length (builtins.attrNames (requests enabled)) == 97;
  assert (request "release-lifecycle").start
  == [
    {
      executable = qualifiedProgram "release";
      ignore_failure = false;
    }
  ]; true
