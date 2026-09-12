##! Pure graph author for real native systemd-manager matrix operations.
let
  systemdManager = {
    name = "aos.systemd-manager";
    abi = 1;
    descriptor = "sha256:ff940aedc92c6492557de96a9d802ad27e8dc945155adc23c7542b0bb5e3bce3";
  };
  units = {
    primary = "aos-matrix-primary.service";
    secondary = "aos-matrix-secondary.service";
    witness = "aos-matrix-witness.service";
    foreign = "aos-matrix-foreign.service";
  };
  resources = provider:
    builtins.mapAttrs (_: unit: {
      inherit provider;
      key = builtins.replaceStrings ["." "_"] ["-" "-"] unit;
    })
    units;
  revision = configuration: unit:
    "sha256:${builtins.hashString "sha256" (builtins.toJSON {
      inherit unit;
      inherit (configuration) action revision;
    })}";
  compose = context: let
    owned = resources context.provider;
    managerReferences = builtins.mapAttrs (_: resource: {
      source = "resource-reference";
      reference = {
        interface = systemdManager;
        inherit resource;
        operations = ["observe" "reload" "restart" "start" "stop"];
        lifetime = "instance";
      };
    }) owned;
  in {
    schema = "aos.ability.composition-fragment/v1";
    requests = [
      {
        id = {
          consumer = context.provider;
          scope = [context.provider.key];
          key = "manager";
        };
        accepted_interfaces = [systemdManager];
        methods = ["observe" "reload" "restart" "start" "stop"];
        guarantees = [
          {
            name = "aos.local-systemd-manager";
            version = 1;
            descriptor = "sha256:50995c1c62000543639c8d9f85995c35cc44a9022933ed79e5447654593291d4";
          }
        ];
        lifetime = "instance";
      }
    ];
    contributions = [];
    resources = builtins.map (name: {
      resource = owned.${name};
      revision = revision context.configuration units.${name};
    }) ["primary" "secondary" "witness" "foreign"];
    outputs = [
      {
        aggregate = {
          provider = context.provider;
          group = "matrix-systemd";
        };
        interface = context.interface;
        port = "managers";
        value = {
          source = "object";
          fields = managerReferences;
        };
      }
    ];
    controllers = builtins.map (name: {
      resource = owned.${name};
      controller = {
        provider = context.provider;
        group = "matrix-systemd";
      };
    }) ["primary" "secondary" "witness" "foreign"];
  };
in {
  inherit compose;

  transition = context: let
    owned = resources context.provider;
    configuration =
      if context.after.instances != []
      then (builtins.head context.after.instances).configuration
      else (builtins.head context.before.instances).configuration;
    selected = builtins.filter (entry:
      entry.binding.request.consumer == context.provider
      && entry.binding.request.key == "manager")
    context.authorized_bindings;
    binding =
      if builtins.length selected == 1
      then (builtins.head selected).binding
      else throw "systemd-manager matrix transition requires one native binding";
    scoped = key: {
      scope = context.operation_scope;
      inherit key;
    };
    node = key: {
      kind = "operation";
      key = scoped key;
    };
    access = method:
      if method == "observe"
      then "read"
      else "exclusive-write";
    operation = key: resource: unit: method: {
      key = scoped key;
      branch_context = [];
      binding = binding.id;
      authority = "caller";
      interface = binding.interface;
      inherit method;
      family =
        if method == "observe"
        then {kind = "observe-readiness";}
        else {
          kind = "service-lifecycle";
          action = method;
        };
      phase = "converging";
      input_phase = "planning";
      target = {
        interface = binding.interface;
        inherit resource;
        operations = [method];
        lifetime = "instance";
      };
      inputs = {
        source = "literal";
        value = {inherit unit;};
      };
      preconditions = [];
      accesses = [
        {
          inherit resource;
          mode = access method;
        }
      ];
      controller =
        if method == "observe"
        then null
        else {
          provider = context.provider;
          group = "matrix-systemd";
        };
      deadline = {
        attempt_timeout_millis = 300000;
        total_recovery_millis = 1200000;
      };
      recovery = {
        retry = {kind = "disabled";};
        reconcile = {
          interface = binding.interface;
          inherit method;
        };
        cancel = {
          interface = binding.interface;
          inherit method;
        };
        compensate = null;
      };
    };
    method = configuration.action;
    primary = operation "matrix-primary" owned.primary units.primary method;
    secondary = operation "matrix-secondary" owned.secondary units.secondary method;
    witness = operation "matrix-witness" owned.witness units.witness "start";
    operations = [primary secondary] ++ (if method == "observe" then [witness] else []);
    edges = [
      {
        from = node "matrix-primary";
        to = node "matrix-secondary";
        kind = "required-success";
      }
    ] ++ (if method == "observe" then [
      {
        from = node "matrix-secondary";
        to = node "matrix-witness";
        kind = "required-success";
      }
    ] else []);
  in {
    schema = "aos.ability.transition-fragment/v1";
    inherit operations edges;
    decisions = [];
    merges = [];
    exports = [];
    imports = [];
    links = [];
    handoffs = [];
    provider_readiness = [];
    obligations = [];
  };
}
