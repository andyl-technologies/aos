##! Focused typed configuration and real-parser contract for containerd.
{
  pkgs,
  lib,
  self,
}: let
  evaluate = host:
    lib.evalModules {
      inherit lib;
      modules = [
        {
          options = {
            assertions = lib.mkOption {
              type = lib.types.listOf lib.types.attrs;
              default = [];
            };
            containerd.config = lib.mkOption {
              type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
              default = {};
            };
          };
        }
      ];
      operatorModules = [host];
      packageModules = [
        {
          name = "containerd";
          authorization = {
            owns = ["containerd"];
            contributes = {};
          };
          configRoot = ../_containerd-config;
          module = ../_containerd-config/module.nix;
          outputs = {
            self = builtins.toString self;
            dependencies = {};
          };
        }
      ];
    };
  configured = evaluate {
    containerd = {
      enable = true;
      grpcAddress = "/run/containerd/contract.sock";
      metricsAddress = "127.0.0.1:11338";
      snapshotter = "native";
      requiredPlugins = ["io.containerd.cri.v1.runtime"];
    };
  };
  invalid = evaluate {
    containerd.disabledPlugins = ["io.containerd.cri.v1.runtime"];
  };
  rendered = configured.config.containerd.config;
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

      [plugins."io.containerd.cri.v1.images".registry]
      config_path = "/etc/containerd/certs.d"

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
  contract = assert rendered.runtime.CONTAINERD_ENABLED == "true";
  assert rendered.config.grpc.address == "/run/containerd/contract.sock";
  assert rendered.config.metrics.address == "127.0.0.1:11338";
  assert rendered.config.plugins."io.containerd.cri.v1.images".snapshotter == "native";
  assert !(builtins.all (entry: entry.assertion) invalid.config.assertions); true;
in
  pkgs.runCommand "containers-containerd-config-module-contract" {} ''
    : ${lib.escapeShellArg (toString contract)}
    ${self}/bin/containerd --config ${configFile}/config.toml config dump > dump.toml
    ${pkgs.grep}/bin/grep -q 'address =.*contract.sock' dump.toml
    ${pkgs.grep}/bin/grep -q 'snapshotter =.*native' dump.toml
    ${pkgs.grep}/bin/grep -q 'ExecStart=.*containerd.*config.toml' \
      ${self.expose}/units/containerd.service
    mkdir -p "$out"
    printf '%s\n' ok > "$out/result"
  ''
