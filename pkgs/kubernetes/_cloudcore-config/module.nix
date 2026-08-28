##! Typed runtime configuration for the package-owned KubeEdge CloudCore role.
{
  config,
  lib,
  ...
}: let
  cfg = config.cloudcore;
  inherit (lib) mkOption types;
  positiveInt = types.addCheck types.int (value: value > 0);
  address = types.strMatching "[A-Za-z0-9][A-Za-z0-9.:-]*";
  bool = value:
    if value
    then "true"
    else "false";
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
    kubeconfig = cfg.kubeApi.kubeconfig.ref;
    ca-certificate = cfg.tls.caCertificate.ref;
    ca-private-key = cfg.tls.caPrivateKey.ref;
    server-certificate = cfg.tls.serverCertificate.ref;
    server-private-key = cfg.tls.serverPrivateKey.ref;
  };
  rendered = ''
    apiVersion: cloudcore.config.kubeedge.io/v1alpha1
    kind: CloudCore
    commonConfig:
      monitorServer:
        bindAddress: ${cfg.monitorAddress}
      tunnelPort: 10350
    kubeAPIConfig:
      burst: ${toString cfg.kubeApi.burst}
      contentType: application/vnd.kubernetes.protobuf
      kubeConfig: /run/credentials/cloudcore.service/kubeconfig
      master: ""
      qps: ${toString cfg.kubeApi.qps}
    modules:
      cloudHub:
        advertiseAddress:
    ${lib.concatMapStringsSep "\n" (value: "    - ${value}") cfg.advertiseAddresses}
        enable: true
        https:
          address: ${cfg.https.address}
          enable: ${bool cfg.https.enable}
          port: ${toString cfg.https.port}
        nodeLimit: ${toString cfg.nodeLimit}
        tlsCAFile: /run/credentials/cloudcore.service/ca-certificate
        tlsCAKeyFile: /run/credentials/cloudcore.service/ca-private-key
        tlsCertFile: /run/credentials/cloudcore.service/server-certificate
        tlsPrivateKeyFile: /run/credentials/cloudcore.service/server-private-key
        unixsocket:
          address: unix:///var/lib/aos-pkg-cloudcore/kubeedge.sock
          enable: true
        websocket:
          address: ${cfg.websocket.address}
          enable: ${bool cfg.websocket.enable}
          port: ${toString cfg.websocket.port}
      iptablesManager:
        enable: false
        mode: internal
      router:
        enable: false
  '';
  requiredRefs = builtins.attrValues credentials;
in {
  options.cloudcore = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned KubeEdge CloudCore service.";
    };
    advertiseAddresses = mkOption {
      type = types.listOf address;
      default = ["127.0.0.1"];
      description = "Addresses advertised to EdgeCore nodes.";
    };
    monitorAddress = mkOption {
      type = types.strMatching "[^\n\r ]+";
      default = "127.0.0.1:9091";
      description = "CloudCore metrics listener address.";
    };
    nodeLimit = mkOption {
      type = positiveInt;
      default = 1000;
      description = "Maximum simultaneously connected edge nodes.";
    };
    kubeApi = {
      kubeconfig = mkOption {
        type = secretRef "Opaque Kubernetes API kubeconfig reference.";
        default = {};
      };
      qps = mkOption {
        type = positiveInt;
        default = 2500;
        description = "Kubernetes API request rate.";
      };
      burst = mkOption {
        type = positiveInt;
        default = 5000;
        description = "Kubernetes API request burst limit.";
      };
    };
    https = {
      enable = mkOption {
        type = types.bool;
        default = true;
      };
      address = mkOption {
        type = address;
        default = "0.0.0.0";
      };
      port = mkOption {
        type = types.port;
        default = 10002;
      };
    };
    websocket = {
      enable = mkOption {
        type = types.bool;
        default = true;
      };
      address = mkOption {
        type = address;
        default = "0.0.0.0";
      };
      port = mkOption {
        type = types.port;
        default = 10000;
      };
    };
    tls = {
      caCertificate = mkOption {
        type = secretRef "Opaque CloudCore CA certificate reference.";
        default = {};
      };
      caPrivateKey = mkOption {
        type = secretRef "Opaque CloudCore CA private-key reference.";
        default = {};
      };
      serverCertificate = mkOption {
        type = secretRef "Opaque CloudCore server certificate reference.";
        default = {};
      };
      serverPrivateKey = mkOption {
        type = secretRef "Opaque CloudCore server private-key reference.";
        default = {};
      };
    };
  };

  config = {
    assertions = [
      {
        assertion = !cfg.enable || cfg.advertiseAddresses != [];
        message = "cloudcore.enable requires at least one cloudcore.advertiseAddresses entry";
      }
      {
        assertion = !cfg.enable || builtins.all (value: value != null) requiredRefs;
        message = "cloudcore.enable requires kubeconfig and all CloudHub TLS credential references";
      }
      {
        assertion = !cfg.enable || cfg.https.enable || cfg.websocket.enable;
        message = "cloudcore.enable requires HTTPS or WebSocket CloudHub transport";
      }
    ];
    cloudcore.config.runtime.CLOUDCORE_ENABLED = cfg.enable;
    cloudcore.credentials = lib.mapAttrs (_: ref: {inherit ref;}) (lib.filterAttrs (_: ref: ref != null) credentials);
    environment.etc."aos/packages/cloudcore/cloudcore.yaml" = {
      text = rendered;
      mode = "0444";
    };
  };
}
