##! tests/abilities/composition.nix - Recursive nginx composition fixture.
{abilities}: let
  inherit (abilities) schemas;

  reverse = builtins.foldl' (values: value: [value] ++ values) [];

  selectedInterface = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };

  # These keys model resolver-authenticated selections. This fixture exercises
  # pure expansion rather than publication, where Rust derives these digests.
  configurationKey =
    selectedInterface
    "aos.managed-configuration"
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  serviceKey =
    selectedInterface
    "aos.systemd-service"
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  credentialKey =
    selectedInterface
    "aos.credential-delivery"
    "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

  emptyLifecycle = {
    stableResourceIdentity = true;
    releasesEphemeralOnDisable = true;
    retainsPersistentByDefault = true;
    persistentDeleteMethod = null;
  };
  aggregation = group: {
    scope = "provider-instance";
    key = "authorized-slot";
    rejectSlotCollisions = true;
    mergeContract = null;
    controllerGroup = group;
  };

  configurationExport = abilities.pinInterface {
    export = abilities.define {
      interface = configurationKey.name;
      abi = configurationKey.abi;
      requestSchema = schemas.record {
        fields.files = schemas.map {
          keyMaxLength = 128;
          keySyntax = "local-key-v1";
          maxEntries = 64;
          value = schemas.string {
            maxLength = 4096;
            syntax = null;
          };
        };
        optional = [];
      };
      outputs.publishedConfiguration = {
        schema = schemas.resourceReference;
        phase = "planning";
        visibility = "protected";
        lifetime = "instance";
      };
      methods = {};
      lifecycle = emptyLifecycle;
      guarantees = [];
      aggregation = aggregation "configuration";
      requires = {};
      composeEntry = "compose";
      transitionEntry = "transition";
      ownsResourceKinds = ["aos.resource.configuration"];
      compose = {
        requests,
        instance,
        ...
      }: {
        requests = {};
        outputs.publishedConfiguration = abilities.resourceReference {
          interface = configurationKey;
          resource = {
            provider = instance.id;
            key = "published";
          };
          operations = ["publish" "read"];
          lifetime = "instance";
        };
        resources = [];
        conditionalRequirements = [];
      };
      transition = _context: abilities.effects.empty;
    };
    descriptor = configurationKey.descriptor;
  };

  serviceExport = abilities.pinInterface {
    export = abilities.define {
      interface = serviceKey.name;
      abi = serviceKey.abi;
      requestSchema = schemas.record {
        fields = {
          configuration = schemas.resourceReference;
          unit = schemas.string {
            maxLength = 128;
            syntax = "local-key-v1";
          };
        };
        optional = [];
      };
      outputs.manager = {
        schema = schemas.resourceReference;
        phase = "planning";
        visibility = "protected";
        lifetime = "instance";
      };
      methods = {};
      lifecycle = emptyLifecycle;
      guarantees = [];
      aggregation = aggregation "services";
      requires = {};
      ownsResourceKinds = ["aos.resource.service"];
      handler = "systemd-service-handler";
      provide = {instance, ...}: {
        requests = {};
        outputs.manager = abilities.resourceReference {
          interface = serviceKey;
          resource = {
            provider = instance.id;
            key = "manager";
          };
          operations = ["observe" "start"];
          lifetime = "instance";
        };
        resources = [];
        conditionalRequirements = [];
      };
    };
    descriptor = serviceKey.descriptor;
  };

  credentialExport = abilities.pinInterface {
    export = abilities.define {
      interface = credentialKey.name;
      abi = credentialKey.abi;
      requestSchema = schemas.record {
        fields.host = schemas.string {
          maxLength = 128;
          syntax = "qualified-name-v1";
        };
        optional = [];
      };
      outputs = {};
      methods = {};
      lifecycle = emptyLifecycle;
      guarantees = [];
      aggregation = aggregation "credentials";
      requires = {};
      ownsResourceKinds = ["aos.resource.credential-view"];
      handler = "credential-delivery-handler";
    };
    descriptor = credentialKey.descriptor;
  };

  virtualHostSchema = schemas.record {
    fields = {
      host = schemas.string {
        maxLength = 128;
        syntax = "qualified-name-v1";
      };
      port = schemas.integer {
        minimum = 1;
        maximum = 65535;
      };
      tls = schemas.boolean;
    };
    optional = ["tls"];
  };

  nginxExport = abilities.define {
    interface = "aos.nginx-virtual-host";
    abi = 1;
    requestSchema = virtualHostSchema;
    outputs.count = {
      schema = schemas.integer {
        minimum = 0;
        maximum = 64;
      };
      phase = "evaluation";
      visibility = "public";
      lifetime = "instance";
    };
    methods = {};
    lifecycle = emptyLifecycle;
    guarantees = [];
    aggregation = aggregation "nginx";
    requires = {
      configuration = {
        interface = configurationKey.name;
        abi = configurationKey.abi;
        descriptor = configurationKey.descriptor;
        methods = [];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      metadata = {
        interface = configurationKey.name;
        abi = configurationKey.abi;
        descriptor = configurationKey.descriptor;
        methods = [];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      service = {
        interface = serviceKey.name;
        abi = serviceKey.abi;
        descriptor = serviceKey.descriptor;
        methods = [];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
      credential = {
        interface = credentialKey.name;
        abi = credentialKey.abi;
        descriptor = credentialKey.descriptor;
        methods = [];
        guarantees = [];
        strength = "required";
        fallback = null;
      };
    };
    composeEntry = "compose";
    transitionEntry = "transition";
    ownsResourceKinds = ["aos.resource.nginx"];
    compose = {
      requests,
      bindings,
      instance,
    }: let
      tlsHosts =
        builtins.filter
        (request: request.tls or false)
        (builtins.attrValues requests);
      usesTls = tlsHosts != [];
    in {
      requests =
        {
          configuration = {
            through = bindings.configuration;
            slot = "${instance.id.key}.configuration";
            parameters.files =
              builtins.mapAttrs
              (_slot: request: "${request.host}:${builtins.toString request.port}")
              requests;
          };
          metadata = {
            through = bindings.metadata;
            slot = "${instance.id.key}.metadata";
            parameters.files =
              builtins.mapAttrs
              (_slot: request: "owner=${request.host}")
              requests;
          };
          service = {
            through = bindings.service;
            slot = "${instance.id.key}.service";
            parameters = {
              unit =
                if instance.badResult or false
                then abilities.resultOf "configuration" "publishedConfiguration"
                else instance.serviceName;
              configuration = abilities.resultOf "configuration" "publishedConfiguration";
            };
          };
        }
        // (
          if usesTls
          then {
            credential = {
              through = bindings.credential;
              slot = "${instance.id.key}.credential";
              parameters.host = (builtins.head tlsHosts).host;
            };
          }
          else {}
        );
      outputs.count = builtins.length (builtins.attrNames requests);
      resources = [];
      conditionalRequirements =
        if usesTls
        then ["credential"]
        else [];
    };
    transition = _context: abilities.effects.empty;
  };

  environment = abilities.environmentId {
    authority = "deployment";
    key = "web";
    stage = "host";
  };
  instanceId = key:
    abilities.instanceId {
      inherit environment key;
    };
  instance = key: values:
    abilities.instance {
      id = instanceId key;
      inherit values;
    };

  binding = bindingKey: requirement: providerKey: provider: interface:
    abilities.bindingReference {
      binding = bindingKey;
      inherit requirement providerKey;
      inherit interface;
      provider = instanceId provider;
    };

  nginxProvider = {
    key,
    serviceName,
    credential ? false,
    badResult ? false,
  }: {
    export = nginxExport;
    instance = instance key {inherit serviceName badResult;};
    scope = [key];
    bindings =
      {
        configuration = binding "${key}.configuration" "configuration" "managed" "managed" configurationKey;
        metadata = binding "${key}.metadata" "metadata" "managed" "managed" configurationKey;
        service = binding "${key}.service" "service" "systemd" "systemd" serviceKey;
      }
      // (
        if credential
        then {
          credential = binding "${key}.credential" "credential" "credentials" "credentials" credentialKey;
        }
        else {}
      );
  };

  providers = {
    nginx-edge = nginxProvider {
      key = "nginx-edge";
      serviceName = "nginx-edge.service";
    };
    nginx-internal = nginxProvider {
      key = "nginx-internal";
      serviceName = "nginx-internal.service";
    };
    managed = {
      export = configurationExport;
      instance = instance "managed" {};
      scope = ["managed"];
      bindings = {};
    };
    systemd = {
      export = serviceExport;
      instance = instance "systemd" {};
      scope = ["systemd"];
      bindings = {};
    };
  };

  tlsProviders =
    providers
    // {
      nginx-edge = nginxProvider {
        key = "nginx-edge";
        serviceName = "nginx-edge.service";
        credential = true;
      };
      credentials = {
        export = credentialExport;
        instance = instance "credentials" {};
        scope = ["credentials"];
        bindings = {};
      };
    };

  lateResultProviders =
    providers
    // {
      managed =
        providers.managed
        // {
          export =
            configurationExport
            // {
              outputs =
                configurationExport.outputs
                // {
                  publishedConfiguration =
                    configurationExport.outputs.publishedConfiguration
                    // {
                      phase = "runtime";
                    };
                };
            };
        };
    };

  applicationContribution = application: slot: host: port:
    abilities.contribution {
      request = abilities.requestId {
        consumer = instanceId application;
        scope = [];
        key = "web";
      };
      inherit slot;
      grant = "${application}.web";
      value = {inherit host port;};
    };

  edgeContributions = [
    (applicationContribution "app-b" "app-b" "b.example" 8081)
    (applicationContribution "app-a" "app-a" "a.example" 8080)
  ];
  internalContributions = [
    (applicationContribution "app-c" "app-c" "c.internal" 9000)
  ];
  tlsContribution = let
    contribution = applicationContribution "app-tls" "app-tls" "tls.example" 8443;
  in
    contribution // {value = contribution.value // {tls = true;};};

  roots = [
    {
      provider = "nginx-internal";
      contributions = internalContributions;
    }
    {
      provider = "nginx-edge";
      contributions = edgeContributions;
    }
  ];
  reversedRoots =
    builtins.map
    (root: root // {contributions = reverse root.contributions;})
    (reverse roots);

  cycleKey =
    selectedInterface
    "aos.test.cycle"
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  cycleExport = group:
    abilities.pinInterface {
      export = abilities.define {
        interface = cycleKey.name;
        abi = cycleKey.abi;
        requestSchema = schemas.boolean;
        outputs = {};
        methods = {};
        lifecycle = emptyLifecycle;
        guarantees = [];
        aggregation = aggregation group;
        requires.next = {
          interface = cycleKey.name;
          abi = cycleKey.abi;
          descriptor = cycleKey.descriptor;
          methods = [];
          guarantees = [];
          strength = "required";
          fallback = null;
        };
        composeEntry = "compose";
        transitionEntry = "transition";
        ownsResourceKinds = [];
        compose = {
          bindings,
          instance,
          ...
        }: {
          requests.next = {
            through = bindings.next;
            slot = "${instance.id.key}.next";
            parameters = true;
          };
          outputs = {};
          resources = [];
          conditionalRequirements = [];
        };
        transition = _context: abilities.effects.empty;
      };
      descriptor = cycleKey.descriptor;
    };
  cycleProviders = {
    cycle-a = {
      export = cycleExport "cycle-a";
      instance = instance "cycle-a" {};
      scope = ["cycle-a"];
      bindings.next = binding "cycle-a.next" "next" "cycle-b" "cycle-b" cycleKey;
    };
    cycle-b = {
      export = cycleExport "cycle-b";
      instance = instance "cycle-b" {};
      scope = ["cycle-b"];
      bindings.next = binding "cycle-b.next" "next" "cycle-a" "cycle-a" cycleKey;
    };
  };
  cycleContribution = abilities.contribution {
    request = abilities.requestId {
      consumer = instanceId "cycle-root";
      scope = [];
      key = "cycle";
    };
    slot = "root";
    grant = "cycle-root";
    value = true;
  };
in {
  inherit configurationExport;
  expansion = abilities.expand {inherit providers roots;};
  reversed = abilities.expand {
    inherit providers;
    roots = reversedRoots;
  };
  collision = abilities.expand {
    inherit providers;
    roots = [
      {
        provider = "nginx-edge";
        contributions = [
          (applicationContribution "app-a" "shared" "a.example" 8080)
          (applicationContribution "app-b" "shared" "b.example" 8081)
        ];
      }
    ];
  };
  emptyRoot = abilities.expand {
    inherit providers;
    roots = [
      {
        provider = "nginx-edge";
        contributions = [];
      }
    ];
  };
  duplicateProviderAlias = abilities.expand {
    providers = providers // {managed-alias = providers.managed;};
    roots = [];
  };
  providerCycle = abilities.expand {
    providers = cycleProviders;
    roots = [
      {
        provider = "cycle-a";
        contributions = [cycleContribution];
      }
    ];
  };
  badResult = abilities.expand {
    providers =
      providers
      // {
        nginx-edge = nginxProvider {
          key = "nginx-edge";
          serviceName = "nginx-edge.service";
          badResult = true;
        };
      };
    roots = [
      {
        provider = "nginx-edge";
        contributions = edgeContributions;
      }
    ];
  };
  lateResult = abilities.expand {
    providers = lateResultProviders;
    roots = [
      {
        provider = "nginx-edge";
        contributions = edgeContributions;
      }
    ];
  };
  tlsOff = abilities.expand {
    inherit providers;
    roots = [
      {
        provider = "nginx-edge";
        contributions = edgeContributions;
      }
    ];
  };
  tlsOn = abilities.expand {
    providers = tlsProviders;
    roots = [
      {
        provider = "nginx-edge";
        contributions = [tlsContribution];
      }
    ];
  };
}
