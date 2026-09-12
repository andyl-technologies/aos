##! Pure K3s aggregate provider for the Kubernetes activation fixture.
{bootstrapMatrix ? false}: let
  systemdBootstrap = {
    name = "aos.systemd-provider-bootstrap";
    abi = 1;
    descriptor = "sha256:833e92258892d87a1f1cb16f66bfd1629c47a97386a9853cd93ffa30037b82f1";
  };
  kubernetesEffects = {
    name = "aos.kubernetes-object-effects";
    abi = 1;
    descriptor = "sha256:bbced9c501c3c41ab4b5f2a70a2945bde2128ef0a37ad900f6d9f1e2f110963e";
  };

  childRequest = context: key: acceptedInterface: methods: {
    id = {
      consumer = context.provider;
      scope = [context.provider.key];
      inherit key;
    };
    accepted_interfaces = [acceptedInterface];
    inherit methods;
    guarantees = [];
    lifetime = "instance";
  };

  bindingFor = context: request: let
    selected = builtins.filter (binding: binding.request == request.id) context.bindings;
  in
    if builtins.length selected == 1
    then builtins.head selected
    else null;

  resourceFor = context: key: {
    provider = context.provider;
    inherit key;
  };

  revisionFor = value: "sha256:${builtins.hashString "sha256" (builtins.toJSON value)}";

  objectFor = context: contribution: let
    revision = revisionFor contribution.value;
    resource = resourceFor context "${contribution.slot}-helmchart";
    owner = "sha256:${builtins.hashString "sha256" "aos.ability.kubernetes-object-owner/v1\u0000${builtins.toJSON resource}"}";
    forbiddenClusterRole = contribution.value.chart == "__aos_forbidden_cluster_role__";
    objectName =
      if forbiddenClusterRole
      then "aos-forbidden-cluster-role"
      else contribution.slot;
    metadata =
      {
        annotations = {
          "aos.andyl.com/object-revision" = revision;
          "aos.andyl.com/resource-owner" = owner;
        };
        name = objectName;
      }
      // (
        if forbiddenClusterRole
        then {}
        else {namespace = "kube-system";}
      );
    object =
      if forbiddenClusterRole
      then {
        apiVersion = "rbac.authorization.k8s.io/v1";
        kind = "ClusterRole";
        inherit metadata;
        rules = [];
      }
      else {
        apiVersion = "helm.cattle.io/v1";
        kind = "HelmChart";
        inherit metadata;
        spec = {
          inherit (contribution.value) chart repo version;
          targetNamespace = contribution.value.target_namespace;
          valuesContent = contribution.value.values_content;
        };
      };
  in {
    inherit resource revision;
    name = contribution.slot;
    json = builtins.toJSON object;
  };

  compose = context: let
    contributions = builtins.sort (left: right: left.slot < right.slot) context.contributions;
    systemdRequest = childRequest context "systemd-bootstrap" systemdBootstrap ["observe-manager" "start" "stop"];
    kubernetesRequest = childRequest context "kubernetes-terminal" kubernetesEffects ["apply" "delete" "observe"];
    objects = builtins.map (objectFor context) contributions;
    serviceValue = {unit = "k3s.service";};
    serviceResource = resourceFor context "server-service";
    serviceValues =
      [
        {
          name = "primary";
          resource = serviceResource;
          value = serviceValue;
        }
      ]
      ++ builtins.filter (entry: entry != null) [
        (
          if bootstrapMatrix
          then {
            name = "secondary";
            resource = resourceFor context "matrix-secondary-service";
            value = {unit = "aos-kubernetes-matrix-foreign.service";};
          }
          else null
        )
      ];
    resources = builtins.sort (left: right: left.resource.key < right.resource.key) (
      (map (service: {
          inherit (service) resource;
          revision = revisionFor service.value;
        })
        serviceValues)
      ++ builtins.map (object: {
        inherit (object) resource revision;
      })
      objects
    );
    objectFields = builtins.listToAttrs (builtins.map (object: {
        name = object.name;
        value = {
          source = "literal";
          value = object.json;
        };
      })
      objects);
    referenceFields = builtins.listToAttrs (builtins.map (object: {
        name = object.name;
        value = {
          source = "resource-reference";
          reference = {
            interface = context.interface;
            resource = object.resource;
            operations = ["apply" "delete" "observe"];
            lifetime = "instance";
          };
        };
      })
      objects);
  in {
    schema = "aos.ability.composition-fragment/v1";
    requests = [kubernetesRequest systemdRequest];
    contributions = [];
    inherit resources;
    outputs = [
      {
        aggregate = {
          provider = context.provider;
          group = "k3s";
        };
        interface = context.interface;
        port = "object-json";
        value = {
          source = "object";
          fields = objectFields;
        };
      }
      {
        aggregate = {
          provider = context.provider;
          group = "k3s";
        };
        interface = context.interface;
        port = "objects";
        value = {
          source = "object";
          fields = referenceFields;
        };
      }
      {
        aggregate = {
          provider = context.provider;
          group = "k3s";
        };
        interface = context.interface;
        port = "service";
        value = {
          source = "resource-reference";
          reference = {
            interface = context.interface;
            resource = serviceResource;
            operations = ["observe-manager" "start" "stop"];
            lifetime = "instance";
          };
        };
      }
      {
        aggregate = {
          provider = context.provider;
          group = "k3s";
        };
        interface = context.interface;
        port = "services";
        value = {
          source = "object";
          fields = builtins.listToAttrs (map (service: {
              name = service.name;
              value = {
                source = "resource-reference";
                reference = {
                  interface = context.interface;
                  resource = service.resource;
                  operations = ["observe-manager" "start" "stop"];
                  lifetime = "instance";
                };
              };
            })
            serviceValues);
        };
      }
    ];
    controllers =
      builtins.map (revision: {
        inherit (revision) resource;
        controller = {
          provider = context.provider;
          group = "k3s";
        };
      })
      resources;
  };
in rec {
  inherit compose;

  transition = context: let
    changed = builtins.filter (change: change.kind == "create" || change.kind == "update") context.changes;
    removed = builtins.filter (change: change.kind == "remove") context.changes;
    isService = change: builtins.match ".*-service" change.resource.key != null;
    serviceChanged = builtins.filter isService changed;
    objectChanged = builtins.filter (change: !isService change) changed;
    serviceRemoved = builtins.filter isService removed;
    objectRemoved = builtins.filter (change: !isService change) removed;
    binding = key: methods: let
      selected = builtins.filter (entry:
        entry.binding.request.consumer
        == context.provider
        && entry.binding.request.key == key
        && builtins.all (method: builtins.elem method entry.binding.caller_grant.methods) methods)
      context.authorized_bindings;
    in
      if builtins.length selected == 1
      then (builtins.head selected).binding
      else throw "K3s transition requires exactly one authorized ${key} binding";
    systemd = binding "systemd-bootstrap" ["observe-manager" "start" "stop"];
    kubernetes = binding "kubernetes-terminal" ["apply" "delete" "observe"];
    scopedKey = key: {
      scope = context.operation_scope;
      inherit key;
    };
    operationNode = operation: {
      kind = "operation";
      key = operation.key;
    };
    controller = {
      provider = context.provider;
      group = "k3s";
    };
    recovery = {
      retry = {kind = "disabled";};
      reconcile = null;
      cancel = null;
      compensate = null;
    };
    deadline = {
      attempt_timeout_millis = 120000;
      total_recovery_millis = 120000;
    };
    operation = binding: method: family: resource: mode: {
      key = scopedKey "${method}-${resource.key}";
      branch_context = [];
      inherit (binding) interface;
      inherit method family recovery deadline controller;
      binding = binding.id;
      authority = "caller";
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
        value = true;
      };
      preconditions = [];
      accesses = [{inherit resource mode;}];
    };
    starts = builtins.map (change:
      operation systemd "start" {
        kind = "service-lifecycle";
        action = "start";
      }
      change.resource "exclusive-write")
    serviceChanged;
    needsKubernetes = objectChanged != [] || objectRemoved != [];
    readinessResources =
      if bootstrapMatrix
      then [
        (resourceFor context "matrix-secondary-service")
        (resourceFor context "server-service")
      ]
      else [resourceFor context "server-service"];
    ready = map (resource:
      operation systemd "observe-manager" {kind = "observe-readiness";} resource "read")
    readinessResources;
    applies = builtins.map (change:
      operation kubernetes "apply" {
        kind = "kubernetes-object";
        action = "apply";
      }
      change.resource "exclusive-write")
    objectChanged;
    deletes = builtins.map (change:
      operation kubernetes "delete" {
        kind = "kubernetes-object";
        action = "delete";
      }
      change.resource "exclusive-write")
    objectRemoved;
    stops = builtins.map (change:
      operation systemd "stop" {
        kind = "service-lifecycle";
        action = "stop";
      }
      change.resource "exclusive-write")
    serviceRemoved;
    readinessEdges = builtins.concatMap (readiness:
      builtins.map (objectOperation: {
        from = operationNode readiness;
        to = operationNode objectOperation;
        kind = "readiness";
      }) (applies ++ deletes))
    ready;
    startEdges =
      builtins.map (start: {
        from = operationNode start;
        to = operationNode (builtins.head ready);
        kind = "required-success";
      })
      starts;
    stopEdges = builtins.concatMap (stop:
      builtins.map (delete: {
        from = operationNode delete;
        to = operationNode stop;
        kind = "required-success";
      })
      deletes)
    stops;
  in {
    schema = "aos.ability.transition-fragment/v1";
    operations =
      starts
      ++ (
        if needsKubernetes
        then ready
        else if bootstrapMatrix
        then ready
        else []
      )
      ++ applies
      ++ deletes
      ++ stops;
    decisions = [];
    merges = [];
    edges = startEdges ++ readinessEdges ++ stopEdges;
    exports = [];
    imports = [];
    links = [];
    handoffs = [];
    provider_readiness =
      if needsKubernetes
      then [
        {
          binding = kubernetes.id;
          producer = (builtins.head ready).key;
          output = "cluster-assignment";
        }
      ]
      else [];
    obligations = [];
  };

  # Qualification retains the real bootstrap/object ordering while making
  # every selected terminal method lead to another authenticated handler call.
  effectQualificationTransition = context: let
    original = transition context;
    recoverable = operation:
      operation
      // {
        recovery =
          operation.recovery
          // {
            reconcile = {
              inherit (operation) interface method;
            };
          };
      };
    fragment = original // {operations = builtins.map recoverable original.operations;};
    operationsFor = method:
      builtins.filter (operation: operation.method == method) fragment.operations;
    ready = operationsFor "observe-manager";
    applies = operationsFor "apply";
    deletes = operationsFor "delete";
    stops = operationsFor "stop";
    operationNode = operation: {
      kind = "operation";
      key = operation.key;
    };
    observeBefore = apply:
      apply
      // {
        key = apply.key // {key = "observe-before-${apply.target.resource.key}";};
        method = "observe";
        family = {
          kind = "kubernetes-object";
          action = "observe";
        };
        target = apply.target // {operations = ["observe"];};
        accesses = builtins.map (entry: entry // {mode = "read";}) apply.accesses;
        recovery =
          apply.recovery
          // {
            reconcile = {
              inherit (apply) interface;
              method = "observe";
            };
          };
      };
    settleApply = apply:
      apply // {key = apply.key // {key = "settle-${apply.key.key}";};};
    settleReady = operation: suffix:
      operation // {key = operation.key // {key = "settle-${suffix}";};};
    observed = builtins.map observeBefore applies;
    settledApplies = builtins.map settleApply applies;
    deleteWitnesses = builtins.concatMap (delete:
      builtins.map (operation: settleReady operation "delete-${delete.target.resource.key}") ready)
    deletes;
    stopWitnesses = builtins.map (operation:
      operation // {key = operation.key // {key = "settle-${operation.key.key}";};})
    stops;
    edge = from: to: {
      from = operationNode from;
      to = operationNode to;
      kind = "required-success";
    };
    observeEdges =
      builtins.concatMap (pair: [
        (edge (builtins.head ready) pair.observe)
        (edge pair.observe pair.apply)
        (edge pair.apply pair.settle)
      ]) (builtins.map (index: {
          apply = builtins.elemAt applies index;
          observe = builtins.elemAt observed index;
          settle = builtins.elemAt settledApplies index;
        })
        (builtins.genList (index: index) (builtins.length applies)));
    deleteEdges = builtins.concatMap (delete:
      builtins.concatMap (operation: [
        (edge operation delete)
        (edge delete (settleReady operation "delete-${delete.target.resource.key}"))
      ])
      ready)
    deletes;
    stopEdges = builtins.map (index:
      edge
      (builtins.elemAt stops index)
      (builtins.elemAt stopWitnesses index))
    (builtins.genList (index: index) (builtins.length stops));
    dependencyRank = kind:
      builtins.getAttr kind {
        data = 0;
        required-success = 1;
        ordering-only = 2;
        readiness = 3;
        branch-guard = 4;
        branch-merge = 5;
        retention = 6;
        communication = 7;
      };
    operationLess = left: right: left.key.key < right.key.key;
    edgeLess = left: right:
      if left.from.key.key != right.from.key.key
      then left.from.key.key < right.from.key.key
      else if left.to.key.key != right.to.key.key
      then left.to.key.key < right.to.key.key
      else dependencyRank left.kind < dependencyRank right.kind;
  in
    assert applies == [] || builtins.length ready == 1;
    assert deletes == [] || builtins.length ready == 1;
      fragment
      // {
        operations = builtins.sort operationLess (
          fragment.operations
          ++ observed
          ++ settledApplies
          ++ deleteWitnesses
          ++ stopWitnesses
        );
        edges = builtins.sort edgeLess (
          fragment.edges ++ observeEdges ++ deleteEdges ++ stopEdges
        );
      };
}
