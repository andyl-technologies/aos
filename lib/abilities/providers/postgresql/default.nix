##! Pure PostgreSQL provider with runtime endpoint, credential, and storage data flow.
let
  endpointEffects = {
    name = "aos.network-endpoint-effects";
    abi = 1;
    descriptor = "sha256:6b4d345ab4350917a04b770f0ac4b82888ffe6ef7e647caa9fe94ccb9f9dac6a";
  };
  storageEffects = {
    name = "aos.host-storage-effects";
    abi = 1;
    descriptor = "sha256:f87cd9e408e229dd2fb121ee7f49d57bc452cb427da539cb35cb4c66256aac0f";
  };
  networkPolicyEffects = {
    name = "aos.host-network-policy-effects";
    abi = 1;
    descriptor = "sha256:13851cb0af020c2ba09663d562017a706124e00ae4a66279d09bf9ffec3dd199";
  };
  credentialEffects = {
    name = "aos.credential-delivery-effects";
    abi = 1;
    descriptor = "sha256:bc251c0837c1d453a6c5840d9146d9e27a95ad82032d9b4c60baf40d293cf1eb";
  };
  postgresqlEffects = {
    name = "aos.postgresql-effects";
    abi = 1;
    descriptor = "sha256:6a1e7d5fb03d9b91127144a64fb96e4c98f4995e7f4f0de258f79fb61fbb9fd6";
  };
  loopbackIngressGuarantee = {
    name = "aos.guarantee.loopback-tcp-ingress-enforcement";
    version = 1;
    descriptor = "sha256:6b12b1c4db768f272434c6e43ca8c484887fc0fa3a51be2ae2784982325c2092";
  };

  operationDeadline = {
    attempt_timeout_millis = 300000;
    total_recovery_millis = 1200000;
  };

  resourceFor = provider: cluster: kind: {
    inherit provider;
    key = "${cluster}-${kind}";
  };

  digestRevision = value: "sha256:${builtins.hashString "sha256" (builtins.toJSON value)}";

  allocationContract = {
    address = "127.0.0.1";
    port = 0;
    transport = "tcp";
  };

  validContribution = contribution:
    contribution.value.cluster
    == contribution.slot
    && contribution.value.database != "postgres"
    && contribution.value.database != "template0"
    && contribution.value.database != "template1"
    && contribution.value.role != "aos-ability-postgresql"
    && builtins.match "^aos-ability-pg-.*" contribution.value.role == null;

  resourceEntriesFor = context: contribution: let
    provider = context.provider;
    cluster = contribution.slot;
    value = contribution.value;
    endpointRevision = digestRevision {
      allocation = allocationContract;
      inherit cluster;
    };
    storageContract = {
      inherit cluster;
      purpose = "database";
    };
    storageRevision = digestRevision storageContract;
    policyRevision = digestRevision {
      direction = "ingress";
      endpoint_revision = endpointRevision;
      protocol = "tcp";
    };
    postgresqlRevision = digestRevision {
      inherit cluster endpointRevision policyRevision storageRevision;
      implementation = context.implementation;
      database = value.database;
      role = value.role;
      credential_version = value.credential_version;
    };
    entry = kind: revision: {
      resource = resourceFor provider cluster kind;
      inherit revision;
    };
  in [
    (entry "credential" value.credential_version)
    (entry "endpoint" endpointRevision)
    (entry "network-policy" policyRevision)
    (entry "postgresql" postgresqlRevision)
    (entry "storage" storageRevision)
  ];

  childRequest = context: key: acceptedInterface: methods: guarantees: lifetime: {
    id = {
      consumer = context.provider;
      scope = [context.provider.key];
      inherit key;
    };
    accepted_interfaces = [acceptedInterface];
    inherit methods guarantees lifetime;
  };

  compose = context: let
    contributions = builtins.sort (left: right: left.slot < right.slot) context.contributions;
    requests = [
      (childRequest context "credential" credentialEffects ["acquire" "deliver" "release"] [] "instance")
      (childRequest context "endpoint" endpointEffects ["materialize" "observe" "release"] [] "instance")
      (childRequest context "network-policy" networkPolicyEffects ["apply" "observe" "remove"] [loopbackIngressGuarantee] "instance")
      (childRequest context "postgresql-terminal" postgresqlEffects ["materialize" "observe" "restart" "start" "stop"] [] "persistent")
      (childRequest context "storage" storageEffects ["ensure" "observe" "release"] [] "persistent")
    ];
    resources =
      builtins.sort
      (left: right: left.resource.key < right.resource.key)
      (builtins.concatMap (resourceEntriesFor context) contributions);
    clusterFields = builtins.listToAttrs (builtins.map
      (contribution: {
        name = contribution.slot;
        value = {
          source = "resource-reference";
          reference = {
            interface = context.interface;
            resource = resourceFor context.provider contribution.slot "postgresql";
            operations = ["observe" "restart" "start" "stop"];
            lifetime = "persistent";
          };
        };
      })
      contributions);
  in
    if !(builtins.all validContribution contributions)
    then throw "PostgreSQL contribution uses a reserved database or provider role"
    else {
      schema = "aos.ability.composition-fragment/v1";
      requests =
        if contributions == []
        then []
        else requests;
      contributions = [];
      inherit resources;
      outputs = [
        {
          aggregate = {
            provider = context.provider;
            group = "postgresql";
          };
          interface = context.interface;
          port = "clusters";
          value = {
            source = "object";
            fields = clusterFields;
          };
        }
      ];
      controllers =
        builtins.map
        (entry: {
          inherit (entry) resource;
          controller = {
            provider = context.provider;
            group = "postgresql";
          };
        })
        resources;
    };

  transition = context: let
    postgresqlSuffix = "-postgresql";
    suffixLength = builtins.stringLength postgresqlSuffix;
    clusterFor = change: let
      key = change.resource.key;
      keyLength = builtins.stringLength key;
      suffixOffset = keyLength - suffixLength;
      hasSuffix =
        keyLength
        > suffixLength
        && builtins.substring suffixOffset suffixLength key == postgresqlSuffix;
    in
      if hasSuffix
      then builtins.substring 0 suffixOffset key
      else throw "PostgreSQL transition received a non-PostgreSQL resource key '${key}'";
    isPostgresqlResource = change:
      change.resource.provider
      == context.provider
      && (let
        key = change.resource.key;
        keyLength = builtins.stringLength key;
      in
        keyLength
        > suffixLength
        && builtins.substring (keyLength - suffixLength) suffixLength key == postgresqlSuffix);
    isReconciliation = change:
      change.kind
      == "reconcile-stopped"
      || change.kind == "reconcile-divergent";
    clusterHasChildReconciliation = cluster:
      builtins.any
      (candidate:
        candidate.resource.provider
        == context.provider
        && isReconciliation candidate
        && builtins.elem candidate.resource (
          builtins.map
          (kind: resourceFor context.provider cluster kind)
          ["credential" "endpoint" "network-policy" "storage"]
        ))
      context.changes;
    changed =
      builtins.filter
      (change:
        isPostgresqlResource change
        && (
          change.kind
          == "create"
          || change.kind == "update"
          || isReconciliation change
          || change.kind == "unchanged"
        ))
      context.changes;
    removed =
      builtins.filter
      (change: isPostgresqlResource change && change.kind == "remove")
      context.changes;
    teardownOnly =
      context.authorized_bindings != []
      && builtins.all (entry: entry.authority.role == "teardown") context.authorized_bindings;
    contributionFor = snapshot: cluster: let
      selected =
        builtins.filter
        (contribution:
          contribution.aggregate.provider
          == context.provider
          && contribution.aggregate.group == "postgresql"
          && contribution.slot == cluster)
        snapshot.contributions;
    in
      if builtins.length selected == 1
      then (builtins.head selected).value
      else throw "PostgreSQL transition requires exactly one contribution for cluster '${cluster}'";
    beforeContributionFor = cluster:
      if context.before == null
      then throw "PostgreSQL teardown requires authenticated prior desired state"
      else contributionFor context.before cluster;
    resource = cluster: kind: resourceFor context.provider cluster kind;
    changeFor = resourceId: let
      selected = builtins.filter (change: change.resource == resourceId) context.changes;
    in
      if builtins.length selected == 1
      then builtins.head selected
      else throw "PostgreSQL transition requires exactly one visible change for ${resourceId.key}";
    selectedAction = change: mutation: observation:
      if change.kind == "create" || change.kind == "update" || isReconciliation change
      then mutation
      else if change.kind == "unchanged"
      then observation
      else throw "PostgreSQL transition cannot provision child ${change.resource.key} from '${change.kind}'";
    terminalsFor = authorityRole: requestKey: resourceId: method: access:
        builtins.filter
        (entry:
          entry.authority.role
          == authorityRole
          && (
            if authorityRole == "desired"
            then
              entry.binding.request.consumer
              == context.provider
              && entry.binding.request.key == requestKey
            else
              entry.authority.source_request.consumer
              == context.provider
              && entry.authority.source_request.key == requestKey
          )
          && builtins.elem method entry.binding.caller_grant.methods
          && builtins.length (builtins.filter
            (permission:
              permission.resource
              == resourceId
              && (
                permission.access
                == access
                || (access == "read" && permission.access == "exclusive-write")
              )
              && builtins.elem method permission.operations)
            entry.binding.caller_grant.resources)
          == 1)
        context.authorized_bindings;
    terminalFor = authorityRole: requestKey: resourceId: method: access: let
      selected = terminalsFor authorityRole requestKey resourceId method access;
    in
      if builtins.length selected == 1
      then (builtins.head selected).binding
      else throw "PostgreSQL transition requires one authorized ${authorityRole} ${requestKey}.${method} binding for ${resourceId.key}";
    controllerFor = resourceId: let
      selected = builtins.filter (entry: entry.resource == resourceId) context.controllers;
    in
      if builtins.length selected == 1
      then (builtins.head selected).controller
      else throw "PostgreSQL transition requires one controller for ${resourceId.key}";
    scopedKey = key: {
      scope = context.operation_scope;
      inherit key;
    };
    node = key: {
      kind = "operation";
      key = scopedKey key;
    };
    result = key: output: {
      source = "operation-result";
      reference = {
        producer = node key;
        inherit output;
      };
    };
    literal = value: {
      source = "literal";
      inherit value;
    };
    object = fields: {
      source = "object";
      inherit fields;
    };
    operation = {
      authorityRole,
      requestKey,
      resourceId,
      method,
      family,
      phase,
      inputPhase,
      inputs,
      access,
      lifetime,
    }: let
      terminal = terminalFor authorityRole requestKey resourceId method access;
    in {
      key = scopedKey "${method}-${resourceId.key}";
      branch_context = [];
      binding = terminal.id;
      authority = "caller";
      interface = terminal.interface;
      inherit method family phase inputs;
      input_phase = inputPhase;
      target = {
        interface = terminal.interface;
        resource = resourceId;
        operations = [method];
        inherit lifetime;
      };
      preconditions = [];
      accesses = [
        {
          resource = resourceId;
          mode = access;
        }
      ];
      controller = controllerFor resourceId;
      deadline = operationDeadline;
      recovery = {
        retry = {
          kind = "bounded";
          max_attempts = 2;
          backoff_millis = 0;
        };
        reconcile = {
          interface = terminal.interface;
          inherit method;
        };
        cancel = null;
        compensate = null;
      };
    };
    provision = change: let
      cluster = clusterFor change;
      contribution = contributionFor context.after cluster;
      priorContribution =
        if context.before == null
        then null
        else contributionFor context.before cluster;
      identityChanged =
        priorContribution
        != null
        && (
          priorContribution.database
          != contribution.database
          || priorContribution.role != contribution.role
        );
      configurationRevision = change.desired;
      endpointResource = resource cluster "endpoint";
      storageResource = resource cluster "storage";
      credentialResource = resource cluster "credential";
      policyResource = resource cluster "network-policy";
      postgresqlResource = resource cluster "postgresql";
      endpointChange = changeFor endpointResource;
      storageChange = changeFor storageResource;
      credentialChange = changeFor credentialResource;
      policyChange = changeFor policyResource;
      noOp =
        change.kind
        == "unchanged"
        && !clusterHasChildReconciliation cluster;
      endpointMethod = selectedAction endpointChange "materialize" "observe";
      storageMethod = selectedAction storageChange "ensure" "observe";
      credentialMethod = selectedAction credentialChange "deliver" "acquire";
      policyMethod = selectedAction policyChange "apply" "observe";
      lifecycleMethod =
        if change.kind == "create" || change.kind == "reconcile-stopped"
        then "start"
        else "restart";
      endpointKey = "${endpointMethod}-${endpointResource.key}";
      storageKey = "${storageMethod}-${storageResource.key}";
      credentialKey = "${credentialMethod}-${credentialResource.key}";
      policyKey = "${policyMethod}-${policyResource.key}";
      materializeKey = "materialize-${postgresqlResource.key}";
      lifecycleKey = "${lifecycleMethod}-${postgresqlResource.key}";
      observeKey = "observe-${postgresqlResource.key}";
      endpointValue = result endpointKey "endpoint";
      storageValue = result storageKey "path";
      credentialValue = result credentialKey "credential-view";
      postgresqlRuntimeInput = object {
        cluster = literal cluster;
        configuration_revision = literal configurationRevision;
        database = literal contribution.database;
        credential_view = credentialValue;
        endpoint = endpointValue;
        role = literal contribution.role;
        storage_path = storageValue;
      };
      lifecycleInput = literal {
        inherit cluster;
        configuration_revision = configurationRevision;
        database = contribution.database;
        credential_view = null;
        endpoint = null;
        role = contribution.role;
        storage_path = null;
      };
      endpointOperation = operation {
        authorityRole = "desired";
        requestKey = "endpoint";
        resourceId = endpointResource;
        method = endpointMethod;
        family = {
          kind = "network-endpoint";
          action = endpointMethod;
        };
        phase = "preparing";
        inputPhase = "planning";
        inputs = literal allocationContract;
        access =
          if endpointMethod == "observe"
          then "read"
          else "exclusive-write";
        lifetime = "instance";
      };
      storageOperation = operation {
        authorityRole = "desired";
        requestKey = "storage";
        resourceId = storageResource;
        method = storageMethod;
        family = {
          kind = "host-storage";
          action = storageMethod;
        };
        phase = "preparing";
        inputPhase = "planning";
        inputs = literal {
          inherit cluster;
          purpose = "database";
        };
        access =
          if storageMethod == "observe"
          then "read"
          else "exclusive-write";
        lifetime = "persistent";
      };
      credentialOperation = operation {
        authorityRole = "desired";
        requestKey = "credential";
        resourceId = credentialResource;
        method = credentialMethod;
        family = {
          kind = "credential";
          action = credentialMethod;
        };
        phase = "preparing";
        inputPhase = "planning";
        inputs = literal {
          version = contribution.credential_version;
          view = credentialResource.key;
        };
        access =
          if credentialMethod == "acquire"
          then "read"
          else "exclusive-write";
        lifetime = "instance";
      };
      policyOperation = operation {
        authorityRole = "desired";
        requestKey = "network-policy";
        resourceId = policyResource;
        method = policyMethod;
        family = {
          kind = "host-network-policy";
          action = policyMethod;
        };
        phase = "publishing";
        inputPhase = "runtime";
        inputs = object {
          direction = literal "ingress";
          endpoint = endpointValue;
          protocol = literal "tcp";
        };
        access =
          if policyMethod == "observe"
          then "read"
          else "exclusive-write";
        lifetime = "instance";
      };
      materializeOperation = operation {
        authorityRole = "desired";
        requestKey = "postgresql-terminal";
        resourceId = postgresqlResource;
        method = "materialize";
        family = {kind = "prepare-managed-configuration";};
        phase = "preparing";
        inputPhase = "runtime";
        inputs = postgresqlRuntimeInput;
        access = "exclusive-write";
        lifetime = "persistent";
      };
      lifecycleOperation = operation {
        authorityRole = "desired";
        requestKey = "postgresql-terminal";
        resourceId = postgresqlResource;
        method = lifecycleMethod;
        family = {
          kind = "service-lifecycle";
          action = lifecycleMethod;
        };
        phase = "converging";
        inputPhase = "planning";
        inputs = lifecycleInput;
        access = "exclusive-write";
        lifetime = "persistent";
      };
      observeOperation = operation {
        authorityRole = "desired";
        requestKey = "postgresql-terminal";
        resourceId = postgresqlResource;
        method = "observe";
        family = {kind = "observe-readiness";};
        phase = "converging";
        inputPhase = "runtime";
        inputs = postgresqlRuntimeInput;
        access = "read";
        lifetime = "persistent";
      };
      edge = from: to: kind: {
        from = node from;
        to = node to;
        inherit kind;
      };
    in
      if change.kind == "update" && identityChanged
      then throw "PostgreSQL database and role are immutable for an existing cluster"
      else {
        operations =
          if noOp
          then [
            credentialOperation
            endpointOperation
            observeOperation
            policyOperation
            storageOperation
          ]
          else [
            credentialOperation
            endpointOperation
            lifecycleOperation
            materializeOperation
            observeOperation
            policyOperation
            storageOperation
          ];
        edges =
          if noOp
          then [
            (edge credentialKey observeKey "data")
            (edge endpointKey observeKey "data")
            (edge endpointKey policyKey "data")
            (edge policyKey observeKey "required-success")
            (edge storageKey observeKey "data")
          ]
          else [
            (edge credentialKey materializeKey "data")
            (edge credentialKey observeKey "data")
            (edge endpointKey materializeKey "data")
            (edge endpointKey observeKey "data")
            (edge endpointKey policyKey "data")
            (edge materializeKey lifecycleKey "required-success")
            (edge policyKey lifecycleKey "required-success")
            (edge lifecycleKey observeKey "required-success")
            (edge storageKey materializeKey "data")
            (edge storageKey observeKey "data")
          ];
        export = {
          key = "ready-${cluster}";
          kind = "completion";
          node = node observeKey;
          outputs = {
            observed-revision = {
              producer = node observeKey;
              output = "observed-revision";
            };
            ready = {
              producer = node observeKey;
              output = "ready";
            };
            submitted-revision = {
              producer = node observeKey;
              output = "submitted-revision";
            };
          };
        };
        inherit cluster lifecycleKey;
      };
    retire = change: let
      cluster = clusterFor change;
      contribution = beforeContributionFor cluster;
      configurationRevision = change.current;
      endpointResource = resource cluster "endpoint";
      storageResource = resource cluster "storage";
      credentialResource = resource cluster "credential";
      policyResource = resource cluster "network-policy";
      postgresqlResource = resource cluster "postgresql";
      stopKey = "stop-${postgresqlResource.key}";
      policyKey = "remove-${policyResource.key}";
      endpointRepairKey = "materialize-${endpointResource.key}";
      endpointReleaseKey = "release-${endpointResource.key}";
      credentialKey = "release-${credentialResource.key}";
      storageKey = "release-${storageResource.key}";
      stopOperation = operation {
        authorityRole = "teardown";
        requestKey = "postgresql-terminal";
        resourceId = postgresqlResource;
        method = "stop";
        family = {
          kind = "service-lifecycle";
          action = "stop";
        };
        phase = "converging";
        inputPhase = "planning";
        inputs = literal {
          inherit cluster;
          configuration_revision = configurationRevision;
          database = contribution.database;
          credential_view = null;
          endpoint = null;
          role = contribution.role;
          storage_path = null;
        };
        access = "exclusive-write";
        lifetime = "persistent";
      };
      policyOperation = operation {
        authorityRole = "teardown";
        requestKey = "network-policy";
        resourceId = policyResource;
        method = "remove";
        family = {
          kind = "host-network-policy";
          action = "remove";
        };
        phase = "converging";
        inputPhase = "planning";
        inputs = literal {
          direction = "ingress";
          endpoint = null;
          protocol = "tcp";
        };
        access = "exclusive-write";
        lifetime = "instance";
      };
      endpointRepairOperation = operation {
        authorityRole = "teardown";
        requestKey = "endpoint";
        resourceId = endpointResource;
        method = "materialize";
        family = {
          kind = "network-endpoint";
          action = "materialize";
        };
        phase = "preparing";
        inputPhase = "planning";
        inputs = literal allocationContract;
        access = "exclusive-write";
        lifetime = "instance";
      };
      endpointOperation = operation {
        authorityRole = "teardown";
        requestKey = "endpoint";
        resourceId = endpointResource;
        method = "release";
        family = {
          kind = "network-endpoint";
          action = "release";
        };
        phase = "converging";
        inputPhase = "planning";
        inputs = literal allocationContract;
        access = "exclusive-write";
        lifetime = "instance";
      };
      credentialOperation = operation {
        authorityRole = "teardown";
        requestKey = "credential";
        resourceId = credentialResource;
        method = "release";
        family = {kind = "release-resource";};
        phase = "converging";
        inputPhase = "planning";
        inputs = literal {
          version = contribution.credential_version;
          view = credentialResource.key;
        };
        access = "exclusive-write";
        lifetime = "instance";
      };
      storageOperation = operation {
        authorityRole = "teardown";
        requestKey = "storage";
        resourceId = storageResource;
        method = "release";
        family = {
          kind = "host-storage";
          action = "release";
        };
        phase = "converging";
        inputPhase = "planning";
        inputs = literal {
          inherit cluster;
          purpose = "database";
        };
        access = "exclusive-write";
        lifetime = "persistent";
      };
      edge = from: to: {
        from = node from;
        to = node to;
        kind = "required-success";
      };
    in {
      operations = [
        credentialOperation
        endpointRepairOperation
        endpointOperation
        policyOperation
        stopOperation
        storageOperation
      ];
      edges = [
        (edge stopKey credentialKey)
        (edge stopKey endpointRepairKey)
        (edge endpointRepairKey policyKey)
        (edge policyKey endpointReleaseKey)
        (edge endpointReleaseKey storageKey)
      ];
      inherit cluster stopKey;
      replacement = {
        operations = [stopOperation];
        edges = [];
        inherit cluster stopKey;
      };
    };
    replacementChanges = builtins.filter
      (change: let
        postgresqlResource = change.resource;
        lifecycleMethod =
          if change.kind == "reconcile-stopped"
          then "start"
          else "restart";
      in
        (change.kind == "update" || isReconciliation change)
        && builtins.length (terminalsFor "teardown" "postgresql-terminal" postgresqlResource "stop" "exclusive-write") == 1
        && (
          teardownOnly
          || (
            builtins.length (terminalsFor "desired" "postgresql-terminal" postgresqlResource "materialize" "exclusive-write") == 1
            && builtins.length (terminalsFor "desired" "postgresql-terminal" postgresqlResource lifecycleMethod "exclusive-write") == 1
          )
        ))
      changed;
    replacementStopped = builtins.map (change: (retire change).replacement) replacementChanges;
    provisioned =
      if teardownOnly
      then []
      else builtins.map provision changed;
    retired = builtins.map retire removed;
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
  in {
    schema = "aos.ability.transition-fragment/v1";
    operations = builtins.sort operationLess (
      builtins.concatMap (entry: entry.operations) provisioned
      ++ builtins.concatMap (entry: entry.operations) replacementStopped
      ++ builtins.concatMap (entry: entry.operations) retired
    );
    decisions = [];
    merges = [];
    edges = builtins.sort edgeLess (
      builtins.concatMap (entry: entry.edges) provisioned
      ++ builtins.concatMap (entry: entry.edges) replacementStopped
      ++ builtins.concatMap (entry: entry.edges) retired
    );
    exports =
      builtins.sort
      (left: right: left.key < right.key)
      (builtins.map (entry: entry.export) provisioned);
    imports = [];
    links = [];
    handoffs = [];
    provider_readiness = [];
    obligations = [];
  };
in {
  inherit compose transition;
}
