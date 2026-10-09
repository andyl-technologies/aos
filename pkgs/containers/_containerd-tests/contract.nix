##! Native containerd effects preserve allocation and produce parser-valid TOML.
{
  pkgs,
  lib,
  self,
  mkSystem,
}: let
  evaluate = settings:
    lib.evalPackageModules {
      scope = ["test" "containerd"];
      packages = [self pkgs.systemd];
      operatorModules = [{containerd = settings;}];
    };
  evaluated = evaluate {
    enable = true;
    metricsAddress = "127.0.0.1:11338";
    snapshotter = "native";
    requiredPlugins = ["io.containerd.cri.v1.runtime"];
    grpcSocketName = "contract.sock";
  };
  registry = evaluate {
    enable = true;
    registryConfigResource = "/etc/containerd/certs.d";
  };
  operations = evaluated.config.aos.abilities;
  directory = operations.filesystem.operations.directory.effects;
  socket = operations.filesystem.operations.view.effects.containerd-socket;
  configuration = operations.configuration.operations.file.effects.containerd;
  service = evaluated.config.aos.services.containerd;
  # The parser fixture supplies the exact realized producer paths. The native
  # graph assertions below separately check that fragments retain those edges.
  resolve = fragment:
    if builtins.isString fragment
    then fragment
    else if fragment == directory.containerd-root.outputs.path
    then "/var/lib/containerd"
    else if fragment == directory.containerd-state.outputs.path
    then "/run/containerd"
    else if fragment == socket.outputs.path
    then "/run/containerd/contract.sock"
    else throw "Unexpected deferred containerd parser fixture value";
  configFile = pkgs.writeTextFile {
    name = "containerd-contract";
    destination = "/config.toml";
    text = lib.concatMapStrings resolve configuration.input.fragments;
  };
  rejects = settings: let result = evaluate settings; in !(builtins.tryEval (builtins.deepSeq result.config.containerd (builtins.deepSeq result.deployment true))).success;
in
  assert builtins.deepSeq [evaluated.deployment registry.deployment] true;
  assert directory.containerd-root.lifetime == "persistent";
  assert directory.containerd-root.input.mode == "0750";
  assert directory.containerd-state.input.mode == "0750";
  assert socket.input.sourcePath == directory.containerd-state.outputs.path;
  assert socket.input.relativePath == "contract.sock";
  assert builtins.elem directory.containerd-root.outputs.path configuration.input.fragments;
  assert builtins.elem socket.outputs.path configuration.input.fragments;
  assert operations.kernelModules.operations.ensure.effects.containerd.input
  == {
    modules = ["overlay"];
    required = true;
  };
  assert builtins.map (mount: mount.source) service.storage.mounts == [directory.containerd-root.outputs.path directory.containerd-state.outputs.path];
  assert service.supervision.startup_protocol == "notification";
  assert service.policy.hardening.resource_control_delegation;
  assert service.isolation.privilege == "privileged";
  assert registry.config.aos.services.containerd.isolation.host_paths != [];
  assert !(operations.filesystem.operations.view.effects ? containerd-registry);
  assert rejects {disabledPlugins = ["io.containerd.cri.v1.runtime"];};
  assert rejects {requiredPlugins = ["duplicate" "duplicate"];};
  assert rejects {grpcSocketName = "../containerd.sock";};
  assert rejects {root = "/srv/containerd";};
  assert rejects {state = "/tmp/containerd";};
    pkgs.runCommand "containers-containerd-native-contract" {} ''
      ${self}/bin/containerd --config ${configFile}/config.toml config dump > dump.toml
      ${pkgs.grep}/bin/grep -q 'address =.*contract.sock' dump.toml
      ${pkgs.grep}/bin/grep -q 'snapshotter =.*native' dump.toml
      ${pkgs.grep}/bin/grep -q 'SystemdCgroup = true' dump.toml
      mkdir -p "$out"
      printf '%s\n' PASS > "$out/result"
    ''
