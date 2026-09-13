##! Checks production structured packages retain their legacy catalog surface.
{
  lib,
  pkgs,
}: let
  packageContract = package: let
    ability = builtins.fromJSON (
      builtins.unsafeDiscardStringContext package.abilities.abilityTemplateJson
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
  serviceCatalog = import ../../lib/abilities/providers/service-package/catalog.nix;
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

  migratedContract = name: let
    package = pkgs.${name};
    contract = packageContract package;
    provider = builtins.head contract.ability.implementation.providers;
    requirement = builtins.head provider.requirements;
    workloadUnits = builtins.filter (lib.hasSuffix ".service") contract.exposure.expose.units;
  in
    contract.ability.activation_mode
    == "structured-effects"
    && contract.ability.package.name == name
    && contract.ability.ownership == [[]]
    && builtins.length contract.ability.exports == 1
    && (builtins.head contract.ability.exports).interface.name == serviceCatalog.${name}.interface
    && (builtins.head contract.ability.exports).interface.abi == 1
    && provider.implementation.kind == "pure-composition"
    && provider.owns_resource_kinds == ["aos.systemd-service-effects"]
    && requirement.accepted_interfaces
    == [
      {
        name = "aos.systemd-service-effects";
        abi = 1;
        descriptor = "sha256:383803bfd7eb105968a80a796fc4726b5663890e88220d26b20dbd2b33349b50";
      }
    ]
    && requirement.methods == ["start" "stop"]
    && requirement.guarantees
    == [
      {
        name = "aos.local-systemd-manager";
        version = 1;
        descriptor = "sha256:50995c1c62000543639c8d9f85995c35cc44a9022933ed79e5447654593291d4";
      }
    ]
    && builtins.all (
      unit: builtins.elem unit contract.exposure.expose.units
    )
    serviceCatalog.${name}.units
    && builtins.length workloadUnits == builtins.length serviceCatalog.${name}.units
    && contract.exposure.expose.units != [];

  serviceProvider = import ../../lib/abilities/providers/service-package;
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
    interface = {
      name = "aos.systemd-service-effects";
      abi = 1;
      descriptor = "sha256:383803bfd7eb105968a80a796fc4726b5663890e88220d26b20dbd2b33349b50";
    };
    caller_grant = {
      methods = ["start" "stop"];
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
  assert start.inputs.value.unit == "rsyncd.service";
  assert start.controller == (builtins.head composition.controllers).controller;
  assert builtins.map (operation: operation.method) restartTransition.operations == ["stop" "start"];
  assert builtins.length restartTransition.edges == 1;
  assert builtins.map (operation: operation.method) removalTransition.operations == ["stop"];
  assert disabledComposition.resources == [];
  assert disabledComposition.controllers == [];
  assert !invalidRevision.success;
  assert !ambiguousRevision.success;
  assert !unknownInterface.success; true
