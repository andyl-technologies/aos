##! Focused PostgreSQL transition checks for observation-driven repair kinds.
let
  providerModule = import ./providers/postgresql/default.nix;

  environment = {
    authority = "deployment";
    key = "postgresql-reconciliation-test";
    stage = "host";
  };
  provider = {
    inherit environment;
    key = "postgresql";
  };
  cluster = "repair";
  operationScope = ["postgresql"];

  resource = kind: {
    inherit provider;
    key = "${cluster}-${kind}";
  };
  resources = {
    credential = resource "credential";
    endpoint = resource "endpoint";
    networkPolicy = resource "network-policy";
    postgresql = resource "postgresql";
    storage = resource "storage";
  };
  revision = suffix: "sha256:${builtins.concatStringsSep "" (builtins.genList (_: suffix) 32)}";

  interface = name: {
    inherit name;
    abi = 1;
    descriptor = revision "aa";
  };
  interfaces = {
    credential = interface "aos.credential-delivery-effects";
    endpoint = interface "aos.network-endpoint-effects";
    networkPolicy = interface "aos.host-network-policy-effects";
    postgresql = interface "aos.postgresql-effects";
    storage = interface "aos.host-storage-effects";
  };

  desiredBinding = requestKey: selectedInterface: selectedResource: methods: access: {
    authority.role = "desired";
    binding = {
      id = "desired-${requestKey}";
      request = {
        consumer = provider;
        scope = operationScope;
        key = requestKey;
      };
      interface = selectedInterface;
      caller_grant = {
        inherit methods;
        resources = [
          {
            resource = selectedResource;
            inherit access;
            operations = methods;
          }
        ];
      };
    };
  };
  teardownBinding = {
    authority = {
      role = "teardown";
      source_request = {
        consumer = provider;
        scope = operationScope;
        key = "postgresql-terminal";
      };
    };
    binding = {
      id = "teardown-postgresql-terminal";
      interface = interfaces.postgresql;
      caller_grant = {
        methods = ["stop"];
        resources = [
          {
            resource = resources.postgresql;
            access = "exclusive-write";
            operations = ["stop"];
          }
        ];
      };
    };
  };
  authorizedBindings = repairKind: let
    lifecycleMethod =
      if repairKind == "reconcile-stopped"
      then "start"
      else "restart";
  in [
    (desiredBinding "credential" interfaces.credential resources.credential ["acquire"] "read")
    (desiredBinding "endpoint" interfaces.endpoint resources.endpoint ["observe"] "read")
    (desiredBinding "network-policy" interfaces.networkPolicy resources.networkPolicy ["observe"] "read")
    (desiredBinding "postgresql-terminal" interfaces.postgresql resources.postgresql ["materialize" "observe" lifecycleMethod] "exclusive-write")
    (desiredBinding "storage" interfaces.storage resources.storage ["observe"] "read")
    teardownBinding
  ];

  contribution = {
    aggregate = {
      inherit provider;
      group = "postgresql";
    };
    slot = cluster;
    value = {
      inherit cluster;
      database = "application";
      role = "application_role";
      credential_version = revision "bb";
    };
  };
  snapshot = {contributions = [contribution];};
  controllerFor = selectedResource: {
    resource = selectedResource;
    controller = {
      inherit provider;
      group = "postgresql";
    };
  };
  controllers = builtins.map controllerFor (builtins.attrValues resources);

  unchanged = selectedResource: {
    resource = selectedResource;
    current = revision "cc";
    desired = revision "cc";
    kind = "unchanged";
  };
  context = repairKind: {
    inherit provider controllers;
    operation_scope = operationScope;
    before = snapshot;
    after = snapshot;
    authorized_bindings = authorizedBindings repairKind;
    changes = [
      (unchanged resources.credential)
      (unchanged resources.endpoint)
      (unchanged resources.networkPolicy)
      {
        resource = resources.postgresql;
        current = revision "dd";
        desired = revision "dd";
        kind = repairKind;
      }
      (unchanged resources.storage)
    ];
  };

  stopped = providerModule.transition (context "reconcile-stopped");
  divergent = providerModule.transition (context "reconcile-divergent");
  operationsFor = fragment:
    builtins.filter
    (operation: operation.target.resource == resources.postgresql)
    fragment.operations;
  methodsFor = fragment: builtins.map (operation: operation.method) (operationsFor fragment);
  bindingFor = fragment: method:
    (builtins.head (builtins.filter
        (operation:
          operation.target.resource == resources.postgresql
          && operation.method == method)
        fragment.operations)).binding;
  requiredEdge = from: to: {
    from = {
      kind = "operation";
      key = {
        scope = operationScope;
        key = "${from}-${resources.postgresql.key}";
      };
    };
    to = {
      kind = "operation";
      key = {
        scope = operationScope;
        key = "${to}-${resources.postgresql.key}";
      };
    };
    kind = "required-success";
  };
in
  assert methodsFor stopped == ["materialize" "observe" "start" "stop"];
  assert bindingFor stopped "stop" == "teardown-postgresql-terminal";
  assert bindingFor stopped "materialize" == "desired-postgresql-terminal";
  assert builtins.elem (requiredEdge "materialize" "start") stopped.edges;
  assert methodsFor divergent == ["materialize" "observe" "restart" "stop"];
  assert bindingFor divergent "stop" == "teardown-postgresql-terminal";
  assert bindingFor divergent "materialize" == "desired-postgresql-terminal";
  assert builtins.elem (requiredEdge "materialize" "restart") divergent.edges;
  {
    reconcile_stopped = methodsFor stopped;
    reconcile_divergent = methodsFor divergent;
  }
