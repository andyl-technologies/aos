##! Checks production packages use manager-neutral logical service contracts.
{
  lib,
  pkgs,
}: let
  packageContract = package: let
    ability = builtins.fromJSON (
      builtins.unsafeDiscardStringContext package.abilityContract.abilityTemplateJson
    );
    exposure = package.expose.passthru.manifest;
  in {
    inherit ability exposure;
    hasConfigModule = package ? config && package ? configModule;
  };

  nginx = packageContract pkgs.nginx;
  postgresql = packageContract pkgs.postgresql;
  inventory = import ../../qualification/package-activation-inventory.nix {
    inherit pkgs lib;
  };
  serviceManagement = import ../../lib/abilities/service-management.nix {
    inherit (lib.abilities) schemas guarantee;
  };
  migratedServices = [
    "cloudcore"
    "conntrack-tools"
    "containerd"
    "edgecore"
    "envoy"
    "etcd"
    "garage"
    "krb5"
    "kubelet"
    "mariadb"
    "openldap"
    "rsync"
  ];

  commonFeatures = [
    "configuration"
    "identity"
    "isolation"
    "readiness"
    "storage"
    "supervision"
  ];
  specialServices = {
    garage = [
      {
        key = "prepare";
        dependencies = [];
      }
      {
        key = "main";
        dependencies = ["prepare"];
      }
    ];
    krb5 = [
      {
        key = "initialize";
        dependencies = [];
      }
      {
        key = "kdc";
        dependencies = ["initialize"];
      }
      {
        key = "administration";
        dependencies = ["initialize"];
      }
    ];
    mariadb = [
      {
        key = "initialize";
        dependencies = [];
      }
      {
        key = "main";
        dependencies = ["initialize"];
      }
    ];
  };
  serviceSpec = name: let
    services =
      specialServices.${
        name
      } or [
        {
          key = "main";
          dependencies = [];
        }
      ];
    hasDependencies = builtins.any (service: service.dependencies != []) services;
  in {
    inherit services;
    interface = "aos.service.${name}";
    methods = ["observe" "restart" "start" "stop"];
    features = commonFeatures ++ lib.optional hasDependencies "dependencies";
  };
  systemdUnits = {
    cloudcore.main = "cloudcore.service";
    conntrack-tools.main = "conntrackd.service";
    containerd.main = "containerd.service";
    edgecore.main = "edgecore.service";
    envoy.main = "envoy.service";
    etcd.main = "etcd.service";
    garage = {
      prepare = "garage-prepare.service";
      main = "garage.service";
    };
    krb5 = {
      initialize = "krb5-kdc-init.service";
      kdc = "krb5-kdc.service";
      administration = "kadmind.service";
    };
    kubelet.main = "kubelet.service";
    mariadb = {
      initialize = "mariadb-init.service";
      main = "mariadb.service";
    };
    openldap.main = "openldap.service";
    rsync.main = "rsyncd.service";
  };

  migratedContract = name: let
    package = pkgs.${name};
    contract = packageContract package;
    spec = serviceSpec name;
    provider = builtins.head contract.ability.implementation.providers;
    requirement = builtins.head provider.requirements;
    requiredGuarantees = builtins.sort (
      left: right: left.name < right.name
    ) (serviceManagement.featureGuarantees spec.features);
    mappedUnits = builtins.attrValues systemdUnits.${name};
  in
    contract.ability.activation_mode
    == "structured-effects"
    && contract.ability.package.name == name
    && contract.ability.ownership == [[]]
    && builtins.length contract.ability.exports == 1
    && (builtins.head contract.ability.exports).interface.name == spec.interface
    && (builtins.head contract.ability.exports).interface.abi == 1
    && provider.implementation.kind == "pure-composition"
    && provider.owns_resource_kinds == [serviceManagement.interface.name]
    && requirement.accepted_interfaces == [serviceManagement.interface]
    && requirement.methods == spec.methods
    && requirement.guarantees == requiredGuarantees
    && builtins.attrNames systemdUnits.${name}
    == builtins.sort builtins.lessThan (builtins.map (service: service.key) spec.services)
    && builtins.all (
      unit: builtins.elem unit contract.exposure.expose.units
    )
    mappedUnits
    && contract.exposure.expose.units != [];

  serviceProvider = import ../../pkgs/build-support/_service-ability-provider {
    spec = serviceSpec "rsync";
  };
  garageProvider = import ../../pkgs/build-support/_service-ability-provider {
    spec = serviceSpec "garage";
  };
  providerId = {
    environment = {
      authority = "deployment";
      key = "host";
      stage = "host";
    };
    package = "sha256:${lib.concatStrings (builtins.genList (_: "1") 64)}";
    interface = "sha256:${lib.concatStrings (builtins.genList (_: "2") 64)}";
    key = "main";
  };
  rsyncInterface = {
    name = "aos.service.rsync";
    abi = 1;
    descriptor = "sha256:${lib.concatStrings (builtins.genList (_: "3") 64)}";
  };
  manualOverrideRevision = "sha256:${lib.concatStrings (builtins.genList (_: "4") 64)}";
  activationRevision = "sha256:${lib.concatStrings (builtins.genList (_: "6") 64)}";
  supplementalRevisionInput = "sha256:${lib.concatStrings (builtins.genList (_: "7") 64)}";
  composition = serviceProvider.compose {
    provider = providerId;
    interface = rsyncInterface;
    package = providerId.package;
    activation_revision = activationRevision;
    configuration.enabled = true;
  };
  manualOverrideComposition = serviceProvider.compose {
    provider = providerId;
    interface = rsyncInterface;
    package = providerId.package;
    activation_revision = activationRevision;
    configuration = {
      enabled = true;
      revision = manualOverrideRevision;
    };
  };
  customizedComposition = serviceProvider.compose {
    provider = providerId;
    interface = rsyncInterface;
    package = providerId.package;
    activation_revision = activationRevision;
    configuration = {
      enabled = true;
      restart_token = "restart-on-demand";
      revision_inputs = [supplementalRevisionInput];
    };
  };
  resource = (builtins.head composition.resources).resource;
  binding = {
    id = "sha256:${lib.concatStrings (builtins.genList (_: "5") 64)}";
    request = {
      consumer = providerId;
      scope = [providerId.key];
      key = "service-terminal";
    };
    interface = serviceManagement.interface;
    caller_grant = {
      methods = ["observe" "restart" "start" "stop"];
      resources = [];
    };
  };
  transition = serviceProvider.transition {
    provider = providerId;
    interface = rsyncInterface;
    operation_scope = ["service" "rsync"];
    authorized_bindings = [
      {
        authority.role = "desired";
        inherit binding;
      }
    ];
    controllers = composition.controllers;
    changes = [
      {
        kind = "create";
        inherit resource;
      }
    ];
  };
  start = builtins.head transition.operations;
  restartTransition = serviceProvider.transition {
    provider = providerId;
    interface = rsyncInterface;
    operation_scope = ["service" "rsync"];
    authorized_bindings = [
      {
        authority.role = "desired";
        inherit binding;
      }
    ];
    controllers = composition.controllers;
    changes = [
      {
        kind = "update";
        inherit resource;
      }
    ];
  };
  removalTransition = serviceProvider.transition {
    provider = providerId;
    interface = rsyncInterface;
    operation_scope = ["service" "rsync"];
    authorized_bindings = [
      {
        authority = {
          role = "teardown";
          source_request = binding.request;
        };
        inherit binding;
      }
    ];
    controllers = composition.controllers;
    changes = [
      {
        kind = "remove";
        inherit resource;
      }
    ];
  };
  garageInterface = rsyncInterface // {name = "aos.service.garage";};
  garageComposition = garageProvider.compose {
    provider = providerId;
    interface = garageInterface;
    package = providerId.package;
    activation_revision = activationRevision;
    configuration.enabled = true;
  };
  garageStartTransition = garageProvider.transition {
    provider = providerId;
    interface = garageInterface;
    operation_scope = ["service" "garage"];
    authorized_bindings = [
      {
        authority.role = "desired";
        inherit binding;
      }
    ];
    controllers = garageComposition.controllers;
    changes =
      builtins.map (entry: {
        kind = "create";
        inherit (entry) resource;
      })
      garageComposition.resources;
  };
  garageStopTransition = garageProvider.transition {
    provider = providerId;
    interface = garageInterface;
    operation_scope = ["service" "garage"];
    authorized_bindings = [
      {
        authority = {
          role = "teardown";
          source_request = binding.request;
        };
        inherit binding;
      }
    ];
    controllers = garageComposition.controllers;
    changes =
      builtins.map (entry: {
        kind = "remove";
        inherit (entry) resource;
      })
      garageComposition.resources;
  };
  disabledComposition = serviceProvider.compose {
    provider = providerId;
    interface = rsyncInterface;
    package = providerId.package;
    activation_revision = activationRevision;
    configuration.enabled = false;
  };
  invalidRevision = builtins.tryEval (builtins.deepSeq (serviceProvider.compose {
      provider = providerId;
      interface = rsyncInterface;
      configuration = {
        enabled = true;
        revision = "latest";
      };
    })
    true);
  ambiguousRevision = builtins.tryEval (builtins.deepSeq (serviceProvider.compose {
      provider = providerId;
      interface = rsyncInterface;
      package = providerId.package;
      activation_revision = activationRevision;
      configuration = {
        enabled = true;
        revision = manualOverrideRevision;
        restart_token = "force-restart";
      };
    })
    true);
  unknownInterface = builtins.tryEval (builtins.deepSeq (serviceProvider.compose {
      provider = providerId;
      interface = rsyncInterface // {name = "aos.service.unknown";};
      package = providerId.package;
      activation_revision = activationRevision;
      configuration.enabled = true;
    })
    true);

  retainsLegacySurface = contract:
    contract.ability.activation_mode
    == "structured-effects"
    && contract.hasConfigModule
    && contract.exposure.expose.config.artifacts != []
    && contract.exposure.expose.units != []
    && contract.exposure.permissions.network == "host"
    && contract.exposure.permissions."host-paths" != [];
in
  assert retainsLegacySurface nginx;
  assert retainsLegacySurface postgresql;
  assert nginx.exposure.permissions.capabilities == ["CAP_NET_BIND_SERVICE"];
  assert postgresql.exposure.expose.target == "aos-pkg-postgresql.target";
  assert builtins.all migratedContract migratedServices;
  assert inventory.legacyEffectful == [];
  assert composition.requests != [];
  assert (builtins.head composition.resources).revision == activationRevision;
  assert (builtins.head manualOverrideComposition.resources).revision == manualOverrideRevision;
  assert (builtins.head customizedComposition.resources).revision != activationRevision;
  assert builtins.match "sha256:[0-9a-f]{64}" (builtins.head customizedComposition.resources).revision != null;
  assert start.method == "start";
  assert start.inputs.value;
  assert start.controller == (builtins.head composition.controllers).controller;
  assert builtins.map (operation: operation.method) restartTransition.operations == ["restart"];
  assert restartTransition.edges == [];
  assert builtins.map (operation: operation.method) removalTransition.operations == ["stop"];
  assert garageStartTransition.edges
  == [
    {
      from = {
        kind = "operation";
        key = {
          scope = ["service" "garage"];
          key = "start-prepare";
        };
      };
      to = {
        kind = "operation";
        key = {
          scope = ["service" "garage"];
          key = "start-main";
        };
      };
      kind = "required-success";
    }
  ];
  assert garageStopTransition.edges
  == [
    {
      from = {
        kind = "operation";
        key = {
          scope = ["service" "garage"];
          key = "stop-main";
        };
      };
      to = {
        kind = "operation";
        key = {
          scope = ["service" "garage"];
          key = "stop-prepare";
        };
      };
      kind = "required-success";
    }
  ];
  assert disabledComposition.resources == [];
  assert disabledComposition.controllers == [];
  assert !invalidRevision.success;
  assert !ambiguousRevision.success;
  assert !unknownInterface.success; true
