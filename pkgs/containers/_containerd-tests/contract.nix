##! Focused native ability and real-parser contract for containerd.
{
  pkgs,
  lib,
  self,
}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  environmentId = lib.abilities.environmentId {
    authority = "deployment";
    key = "containerd-test";
    stage = "host";
  };
  environment = builtins.removeAttrs environmentId ["_type"];
  filesystemProvider = lib.abilities.instanceId {
    environment = environmentId;
    key = "filesystem-provider";
  };
  registryResource = lib.abilities.resourceReference {
    interface = serviceManagement.interfaces.hostPathView.identity;
    resource = {
      provider = filesystemProvider;
      key = "registry-configuration";
    };
    operations = ["observe"];
    lifetime = "persistent";
  };
  evaluate = containerdConfig:
    lib.evalModules {
      modules = [
        ../../../modules/abilities/default.nix
        {
          options.assertions = lib.mkOption {
            type = lib.types.listOf lib.types.attrs;
            default = [];
            contributable = true;
          };
          aos.abilities.environment = environment;
          containerd = containerdConfig;
        }
      ];
      packageModules = [
        {
          name = "containerd";
          module.imports = [../_containerd-config/module.nix];
        }
      ];
      inherit lib;
    };
  assertionsHold = result:
    builtins.all (assertion: assertion.assertion) result.config.assertions;
  evaluated = evaluate {
    enable = true;
    metricsAddress = "127.0.0.1:11338";
    snapshotter = "native";
    requiredPlugins = ["io.containerd.cri.v1.runtime"];
  };
  evaluatedWithRegistry = evaluate {
    enable = true;
    registryConfigResource = registryResource;
  };
  invalidDisabledRuntime = evaluate {
    disabledPlugins = ["io.containerd.cri.v1.runtime"];
  };
  invalidDuplicateRequired = evaluate {
    requiredPlugins = ["io.containerd.cri.v1.runtime" "io.containerd.cri.v1.runtime"];
  };
  invalidSocket = builtins.tryEval ((evaluate {
      grpcSocketName = "../containerd.sock";
    })
    .config
    .containerd
    .grpcSocketName);
  invalidRoot = builtins.tryEval ((evaluate {
      root = "/srv/containerd";
    })
    .config
    .containerd
    .root);
  invalidState = builtins.tryEval ((evaluate {
      state = "/tmp/containerd";
    })
    .config
    .containerd
    .state);
  abilities = evaluated.config.aos.abilities;
  registryAbilities = evaluatedWithRegistry.config.aos.abilities;
  requests = builtins.attrNames abilities.requests;
  registryRequests = builtins.attrNames registryAbilities.requests;
  configurationSource = abilities.requests."containerd:server-configuration".parameters.source;
  configurationJson = builtins.toJSON configurationSource;
  kernelRequest = abilities.requests."containerd:kernel-modules".parameters;
  socketView = abilities.requests."containerd:grpc-socket-view".parameters;
  lifecycleRequest = abilities.requests."containerd:main-lifecycle".parameters;
  storageRequest = abilities.requests."containerd:main-storage".parameters;
  registryIsolation = registryAbilities.requests."containerd:main-isolation".parameters;
  plannedPath = request: {
    _type = "aos-request-output-reference";
    request = "containerd:${request}";
    output = "planned-path";
  };
  configFile = pkgs.writeTextFile {
    name = "containerd-contract.toml";
    destination = "/config.toml";
    text = ''
      version = 3
      root = "/var/lib/containerd"
      state = "/run/containerd"
      required_plugins = ["io.containerd.cri.v1.runtime"]

      [grpc]
      address = "/run/containerd/contract.sock"

      [metrics]
      address = "127.0.0.1:11338"

      [plugins."io.containerd.cri.v1.images"]
      snapshotter = "native"

      [plugins."io.containerd.cri.v1.images".pinned_images]
      sandbox = "registry.k8s.io/pause:3.10"

      [plugins."io.containerd.cri.v1.runtime".containerd]
      default_runtime_name = "runc"

      [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc]
      runtime_type = "io.containerd.runc.v2"

      [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runc.options]
      SystemdCgroup = true
    '';
  };
  contractHolds =
    assertionsHold evaluated
    && assertionsHold evaluatedWithRegistry
    && !assertionsHold invalidDisabledRuntime
    && !assertionsHold invalidDuplicateRequired
    && !invalidSocket.success
    && !invalidRoot.success
    && !invalidState.success
    && builtins.elem "containerd:main-lifecycle" requests
    && builtins.elem "containerd:main-dependencies" requests
    && builtins.elem "containerd:main-readiness" requests
    && builtins.elem "containerd:server-configuration" requests
    && builtins.elem "containerd:root-storage" requests
    && builtins.elem "containerd:state-storage" requests
    && builtins.elem "containerd:grpc-socket-view" requests
    && builtins.elem "containerd:kernel-modules" requests
    && !(builtins.elem "containerd:registry-config-view" requests)
    && builtins.elem "containerd:registry-config-view" registryRequests
    && configurationSource.kind == "structured-value"
    && configurationSource.format == "toml"
    && !(lib.hasInfix "/var/lib/containerd" configurationJson)
    && !(lib.hasInfix "/run/containerd" configurationJson)
    && !(lib.hasInfix "/run/containerd/containerd.sock" configurationJson)
    && !(lib.hasInfix ''"output":"storage-path"'' configurationJson)
    && kernelRequest
    == {
      modules = ["overlay"];
      required = true;
    }
    && socketView.source_path == plannedPath "state-storage"
    && socketView.relative_path == "containerd.sock"
    && builtins.map (mount: mount.source) storageRequest.mounts
    == [
      (plannedPath "root-storage")
      (plannedPath "state-storage")
    ]
    && builtins.length registryIsolation.host_paths == 1
    && lifecycleRequest.start != [];
in
  assert contractHolds;
    pkgs.runCommand "containers-containerd-ability-module-contract" {} ''
      ${self}/bin/containerd --config ${configFile}/config.toml config dump > dump.toml
      ${pkgs.grep}/bin/grep -q 'address =.*contract.sock' dump.toml
      ${pkgs.grep}/bin/grep -q 'snapshotter =.*native' dump.toml
      mkdir -p "$out"
      printf '%s\n' PASS > "$out/result"
    ''
