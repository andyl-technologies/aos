##! Typed runtime configuration for the package-owned KubeEdge EdgeCore role.
{
  config,
  lib,
  ...
}: let
  cfg = config.edgecore;
  inherit (lib) mkOption types;
  positiveInt = types.addCheck types.int (value: value > 0);
  secretRef = description:
    types.submodule ({...}: {
      config._module.strict = true;
      options.ref = mkOption {
        type = types.nullOr (types.strMatching "(tpm2-credstore|desired-toml|system-credential)(:[A-Za-z0-9_.-]+)?");
        default = null;
        inherit description;
      };
    });
  credentials = {
    ca-certificate = cfg.tls.caCertificate.ref;
    client-certificate = cfg.tls.clientCertificate.ref;
    client-private-key = cfg.tls.clientPrivateKey.ref;
  };
  rendered = ''
    apiVersion: edgecore.config.kubeedge.io/v1alpha2
    kind: EdgeCore
    database:
      dataSource: /var/lib/aos-pkg-edgecore/edgecore.db
    modules:
      deviceTwin:
        enable: true
        dmiSockPath: /run/aos-pkg-edgecore/dmi.sock
      edgeHub:
        enable: true
        heartbeat: 15
        httpServer: ${cfg.cloudHub.httpServer}
        tlsCaFile: /run/credentials/edgecore.service/ca-certificate
        tlsCertFile: /run/credentials/edgecore.service/client-certificate
        tlsPrivateKeyFile: /run/credentials/edgecore.service/client-private-key
        websocket:
          enable: true
          handshakeTimeout: 30
          readDeadline: 15
          server: ${cfg.cloudHub.server}
          writeDeadline: 15
      edged:
        enable: true
        hostnameOverride: ${cfg.nodeName}
        maxContainerCount: -1
        maxPerPodContainerCount: 1
        podSandboxImage: ${cfg.podSandboxImage}
        registerNodeNamespace: default
        registerSchedulable: true
        rootDirectory: /var/lib/aos-pkg-edgecore/kubelet
        tailoredKubeletConfig:
          address: 127.0.0.1
          cgroupDriver: ${cfg.cgroupDriver}
          cgroupsPerQOS: true
          clusterDomain: cluster.local
          containerRuntimeEndpoint: ${cfg.runtimeEndpoint}
          imageServiceEndpoint: ${cfg.runtimeEndpoint}
          failSwapOn: false
          maxPods: ${toString cfg.maxPods}
          podLogsDir: /var/log/pods
          resolvConf: /etc/resolv.conf
          staticPodPath: /var/lib/aos-pkg-edgecore/manifests
      eventBus:
        enable: false
  '';
  requiredRefs = builtins.attrValues credentials;
in {
  options.edgecore = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned KubeEdge EdgeCore service.";
    };
    nodeName = mkOption {
      type = types.strMatching "[a-z0-9]([-a-z0-9.]*[a-z0-9])?";
      default = "edge-node";
      description = "Kubernetes node name advertised by EdgeCore.";
    };
    cloudHub = {
      httpServer = mkOption {
        type = types.strMatching "https://[^\n\r ]+";
        description = "CloudHub HTTPS enrollment endpoint.";
      };
      server = mkOption {
        type = types.strMatching "[^\n\r ]+:[0-9]+";
        description = "CloudHub WebSocket endpoint.";
      };
    };
    runtimeEndpoint = mkOption {
      type = types.strMatching "unix:///[^\n\r ]+";
      default = "unix:///run/containerd/containerd.sock";
      description = "CRI runtime and image service endpoint.";
    };
    cgroupDriver = mkOption {
      type = types.enum ["cgroupfs" "systemd"];
      default = "systemd";
      description = "Container runtime cgroup driver.";
    };
    maxPods = mkOption {
      type = positiveInt;
      default = 110;
      description = "Maximum pods admitted on the edge node.";
    };
    podSandboxImage = mkOption {
      type = types.strMatching "[^\n\r ]+";
      default = "registry.k8s.io/pause:3.10";
      description = "Pod sandbox image reference.";
    };
    tls = {
      caCertificate = mkOption {
        type = secretRef "Opaque CloudHub CA certificate reference.";
        default = {};
      };
      clientCertificate = mkOption {
        type = secretRef "Opaque EdgeCore client certificate reference.";
        default = {};
      };
      clientPrivateKey = mkOption {
        type = secretRef "Opaque EdgeCore client private-key reference.";
        default = {};
      };
    };
  };

  config = {
    assertions = [
      {
        assertion = !cfg.enable || builtins.all (value: value != null) requiredRefs;
        message = "edgecore.enable requires CA, client certificate, and client private-key references";
      }
    ];
    edgecore.config.runtime.EDGECORE_ENABLED = cfg.enable;
    edgecore.credentials = lib.mapAttrs (_: ref: {inherit ref;}) (lib.filterAttrs (_: ref: ref != null) credentials);
    environment.etc."aos/packages/edgecore/edgecore.yaml" = {
      text = rendered;
      mode = "0444";
    };
  };
}
