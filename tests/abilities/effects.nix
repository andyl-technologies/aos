##! tests/abilities/effects.nix - Canonical nginx transition effect fixture.
{abilities}: let
  inherit (abilities) effects schemas;

  environment = abilities.environmentId {
    authority = "deployment";
    key = "web";
    stage = "host";
  };
  instanceId = key:
    abilities.instanceId {
      inherit environment key;
    };

  interfaceKey = name: descriptor: {
    inherit name descriptor;
    abi = 1;
  };
  configurationInterface =
    interfaceKey
    "aos.managed-configuration"
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  serviceInterface =
    interfaceKey
    "aos.systemd-service"
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

  binding = bindingKey: requirement: providerKey: interface:
    abilities.bindingReference {
      binding = bindingKey;
      inherit requirement providerKey interface;
      provider = instanceId providerKey;
    };
  configurationBinding =
    binding
    "nginx.configuration"
    "configuration"
    "managed"
    configurationInterface;
  serviceBinding =
    binding
    "nginx.service"
    "service"
    "systemd"
    serviceInterface;

  resource = provider: interface: key: operations:
    abilities.resourceReference {
      inherit interface operations;
      resource = {
        provider = instanceId provider;
        inherit key;
      };
      lifetime = "instance";
    };
  configuration = operation:
    resource
    "managed"
    configurationInterface
    "nginx-configuration"
    [operation];
  service = operation:
    resource
    "systemd"
    serviceInterface
    "nginx-service"
    [operation];

  sourceArtifact = abilities.artifactReference {
    content = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    storePath = "/nix/store/00000000000000000000000000000000-nginx-source";
    narHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    closure = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
  };

  recovery = {
    retry = {
      kind = "bounded";
      max_attempts = 3;
      backoff_millis = 100;
    };
    reconcile = null;
    cancel = null;
    compensate = null;
  };
  deadline = {
    attempt_timeout_millis = 30000;
    total_recovery_millis = 120000;
  };

  invoke = {
    target,
    through,
    method,
    family,
    inputs ? {},
    phase ? "converging",
    inputPhase ? "observation",
    mode ? "read",
    group,
  }:
    effects.invoke {
      inherit target through method family inputs phase inputPhase deadline recovery;
      authority = "provider";
      preconditions = [];
      accesses = [
        {
          resource = target.resource;
          inherit mode;
        }
      ];
      controller = {
        provider = target.resource.provider;
        inherit group;
      };
    };

  readyDescriptor = {
    schema = schemas.boolean;
    phase = "observation";
    visibility = "protected";
    lifetime = "attempt";
  };

  readyBranch = method: family:
    effects.graph {
      apply = invoke {
        target = service method;
        through = serviceBinding;
        inherit method family;
        inputs.revision = effects.ancestorResult 2 "publish" "revision";
        mode =
          if family.kind == "service-lifecycle"
          then "exclusive-write"
          else "read";
        group = "services";
      };
      nested = effects.ifResult {
        selector = effects.ancestorResult 2 "policy" "enabled";
        alternatives = {
          false = effects.empty;
          true = effects.empty;
        };
        outputs = {};
      };
    };

  transition = effects.graph {
    policy = invoke {
      target = service "observe";
      through = serviceBinding;
      method = "observe";
      family = {kind = "observe-readiness";};
      inputs = {};
      group = "services";
    };

    candidate = invoke {
      target = configuration "prepare";
      through = configurationBinding;
      method = "prepare";
      family = {kind = "prepare-managed-configuration";};
      inputs.source = sourceArtifact;
      phase = "preparing";
      inputPhase = "artifact";
      mode = "exclusive-write";
      group = "configuration";
    };

    publish = effects.after ["candidate"] (invoke {
      target = configuration "publish";
      through = configurationBinding;
      method = "publish";
      family = {kind = "publish-configuration";};
      inputs.candidate = effects.result "candidate" "candidate";
      phase = "publishing";
      inputPhase = "runtime";
      mode = "exclusive-write";
      group = "configuration";
    });

    change = effects.after ["publish"] (invoke {
      target = service "observe";
      through = serviceBinding;
      method = "observe";
      family = {kind = "observe-readiness";};
      inputs.revision = effects.result "publish" "revision";
      group = "services";
    });

    choice = effects.ifResult {
      selector = effects.result "change" "needs_reload";
      alternatives = {
        false = readyBranch "observe" {kind = "observe-readiness";};
        true = readyBranch "reload" {
          kind = "service-lifecycle";
          action = "reload";
        };
      };
      outputs.ready = {
        descriptor = readyDescriptor;
        alternatives = {
          false = effects.result "apply" "ready";
          true = effects.result "apply" "ready";
        };
      };
    };

    record = invoke {
      target = configuration "record";
      through = configurationBinding;
      method = "record";
      family = {kind = "record-generation-association";};
      inputs.ready = effects.mergedResult "choice" "ready";
      mode = "exclusive-write";
      group = "configuration";
    };

    mode = effects.after ["record"] (invoke {
      target = service "classify";
      through = serviceBinding;
      method = "classify";
      family = {kind = "observe-readiness";};
      inputs = {};
      group = "services";
    });

    modeChoice = effects.matchResult {
      selector = effects.result "mode" "action";
      tagField = "kind";
      alternatives = {
        reload = readyBranch "reload" {
          kind = "service-lifecycle";
          action = "reload";
        };
        restart = readyBranch "restart" {
          kind = "service-lifecycle";
          action = "restart";
        };
      };
      outputs.ready = {
        descriptor = readyDescriptor;
        alternatives = {
          reload = effects.result "apply" "ready";
          restart = effects.result "apply" "ready";
        };
      };
    };

    final = invoke {
      target = service "observe";
      through = serviceBinding;
      method = "observe";
      family = {kind = "observe-readiness";};
      inputs.ready = effects.mergedResult "modeChoice" "ready";
      group = "services";
    };
  };

  missingReference = effects.graph {
    consumer = invoke {
      target = service "observe";
      through = serviceBinding;
      method = "observe";
      family = {kind = "observe-readiness";};
      inputs.value = effects.result "absent" "value";
      group = "services";
    };
  };

  cycle = effects.graph {
    first = invoke {
      target = service "observe";
      through = serviceBinding;
      method = "observe";
      family = {kind = "observe-readiness";};
      inputs.value = effects.result "second" "value";
      group = "services";
    };
    second = invoke {
      target = service "observe";
      through = serviceBinding;
      method = "observe";
      family = {kind = "observe-readiness";};
      inputs.value = effects.result "first" "value";
      group = "services";
    };
  };

  incompleteBoolean = effects.graph {
    choice = effects.ifResult {
      selector = effects.result "selector" "value";
      alternatives.false = effects.empty;
      outputs = {};
    };
  };

  escapingReference = effects.graph {
    consumer = invoke {
      target = service "observe";
      through = serviceBinding;
      method = "observe";
      family = {kind = "observe-readiness";};
      inputs.value = effects.ancestorResult 1 "absent" "value";
      group = "services";
    };
  };

  externalMergeProducer = effects.graph {
    selector = invoke {
      target = service "observe";
      through = serviceBinding;
      method = "observe";
      family = {kind = "observe-readiness";};
      inputs = {};
      group = "services";
    };
    choice = effects.ifResult {
      selector = effects.result "selector" "ready";
      alternatives = {
        false = effects.empty;
        true = effects.empty;
      };
      outputs.ready = {
        descriptor = readyDescriptor;
        alternatives = {
          false = effects.ancestorResult 2 "selector" "ready";
          true = effects.ancestorResult 2 "selector" "ready";
        };
      };
    };
  };

  makeChainNodes = count:
    builtins.listToAttrs (builtins.genList (index: let
        name = "step-${builtins.toString index}";
        operation = invoke {
          target = service "observe";
          through = serviceBinding;
          method = "observe";
          family = {kind = "observe-readiness";};
          inputs = {};
          group = "services";
        };
      in {
        inherit name;
        value =
          if index == 0
          then operation
          else effects.after ["step-${builtins.toString (index - 1)}"] operation;
      })
      count);
  chainNodes = makeChainNodes 65;
  analysisHeavyChain = effects.graph (makeChainNodes 600);

  largeString = builtins.concatStringsSep "" (
    builtins.genList (_: "0123456789abcdef") 65536
  );
  oversizedValue = builtins.genList (_: largeString) 33;
  oversizedDocument = effects.graph {
    consumer = invoke {
      target = service "observe";
      through = serviceBinding;
      method = "observe";
      family = {kind = "observe-readiness";};
      inputs.payload = oversizedValue;
      group = "services";
    };
  };
in {
  normalized = effects.normalize ["nginx"] transition;
  reversed = effects.normalize ["nginx"] (effects.graph {
    inherit (transition.nodes) modeChoice mode final record choice change publish candidate policy;
  });
  omitted = effects.normalize [] (effects.when false transition);
  longChain = effects.normalize ["chain"] (effects.graph chainNodes);
  inherit
    missingReference
    cycle
    incompleteBoolean
    escapingReference
    externalMergeProducer
    analysisHeavyChain
    oversizedValue
    oversizedDocument
    ;
}
