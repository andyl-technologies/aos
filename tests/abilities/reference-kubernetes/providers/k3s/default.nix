##! Pure K3s aggregate provider for the Kubernetes activation fixture.
let
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
    resources = builtins.sort (left: right: left.resource.key < right.resource.key) (
      [
        {
          resource = serviceResource;
          revision = revisionFor serviceValue;
        }
      ]
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
    ];
    controllers = builtins.map (revision: {
      inherit (revision) resource;
      controller = {
        provider = context.provider;
        group = "k3s";
      };
    }) resources;
  };
in {
  inherit compose;

  transition = context: let
    changed = builtins.filter (change: change.kind == "create" || change.kind == "update") context.changes;
    removed = builtins.filter (change: change.kind == "remove") context.changes;
    serviceChanged = builtins.filter (change: change.resource.key == "server-service") changed;
    objectChanged = builtins.filter (change: change.resource.key != "server-service") changed;
    serviceRemoved = builtins.filter (change: change.resource.key == "server-service") removed;
    objectRemoved = builtins.filter (change: change.resource.key != "server-service") removed;
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
    serviceResource = resourceFor context "server-service";
    starts = builtins.map (_:
      operation systemd "start" {
        kind = "service-lifecycle";
        action = "start";
      }
      serviceResource "exclusive-write")
    serviceChanged;
    needsKubernetes = objectChanged != [] || objectRemoved != [];
    ready = operation systemd "observe-manager" {kind = "observe-readiness";} serviceResource "read";
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
    stops = builtins.map (_:
      operation systemd "stop" {
        kind = "service-lifecycle";
        action = "stop";
      }
      serviceResource "exclusive-write")
    serviceRemoved;
    readinessEdges = builtins.map (objectOperation: {
      from = operationNode ready;
      to = operationNode objectOperation;
      kind = "readiness";
    }) (applies ++ deletes);
    startEdges =
      builtins.map (start: {
        from = operationNode start;
        to = operationNode ready;
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
        then [ready]
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
          producer = ready.key;
          output = "cluster-assignment";
        }
      ]
      else [];
    obligations = [];
  };
}
