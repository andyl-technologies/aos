##! Typed runtime configuration for the package-owned KubeEdge CloudCore role.
{
  config,
  lib,
  package,
  packageName,
  packageVersion,
  ...
}: let
  cfg = config.aos.cloudcore;
  serviceEnabled = config.aos.services.cloudcore.enable;
  inherit (lib) mkOption;
  positiveInt = lib.types.ints.between 1 9007199254740991;
  refinedString = name: description: pattern: lib.types.strMatching pattern;
  address = lib.types.strMatching "[A-Za-z0-9][A-Za-z0-9.:-]*";
  nonWhitespace = lib.types.strMatching "[^[:space:]]+";
  port = lib.types.ints.between 1 65535;
  bool = value:
    if value
    then "true"
    else "false";
  credentialType = lib.types.nullOr (lib.types.submodule config.aos.abilities.credential.operations.deliver.input);
  credentials = {
    kubeconfig = cfg.kubeApi.kubeconfig;
    ca-certificate = cfg.tls.caCertificate;
    ca-private-key = cfg.tls.caPrivateKey;
    server-certificate = cfg.tls.serverCertificate;
    server-private-key = cfg.tls.serverPrivateKey;
  };
  configurationFragments = [
    {
      kind = "literal";
      text = ''
        apiVersion: cloudcore.config.kubeedge.io/v1alpha1
        kind: CloudCore
        commonConfig:
          monitorServer:
            bindAddress: ${cfg.monitorAddress}
          tunnelPort: 10350
        kubeAPIConfig:
          burst: ${toString cfg.kubeApi.burst}
          contentType: application/vnd.kubernetes.protobuf
          kubeConfig:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "kubeconfig";
    }
    {
      kind = "literal";
      text = ''
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
            tlsCAFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "ca-certificate";
    }
    {
      kind = "literal";
      text = ''
        tlsCAKeyFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "ca-private-key";
    }
    {
      kind = "literal";
      text = ''
        tlsCertFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "server-certificate";
    }
    {
      kind = "literal";
      text = ''
        tlsPrivateKeyFile:${" "}
      '';
    }
    {
      kind = "execution-path";
      value = credentialPath "server-private-key";
    }
    {
      kind = "literal";
      text = ''
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
    }
  ];
  requiredRefs = builtins.attrValues credentials;
  deliveries = config.aos.abilities.credential.operations.deliver.effects;
  credentialPath = name: deliveries."cloudcore-${name}".outputs.path;
  configuredCredentials = lib.filterAttrs (_: ref: ref != null) credentials;
  network = config.aos.abilities.network.operations.ready.effects.cloudcore;
  configuration = config.aos.abilities.configuration.operations.file.effects.cloudcore;
  ingress = config.aos.abilities.networkPolicy.operations.ruleset.effects.host;
  service = {
    policy.hardening = {
      allow_privilege_escalation = false;
      ambient_privileges = [];
      privilege_bounds = {
        kind = "restricted";
        privileges = [];
      };
      resource_control_delegation = false;
      resource_control_access = "read-only";
      device_access_scope = "private";
      host_clock_mutation = false;
      host_name_mutation = false;
      operating_system_log_access = false;
      operating_system_extension_access = false;
      operating_system_tunable_access = false;
      lock_execution_personality = true;
      writable_executable_memory = false;
      isolation_domains = [];
      network_families = [
        "ipv4"
        "ipv6"
        "local"
      ];
      memory_pressure_adjustment = 0;
      permit_realtime = false;
      permit_elevated_file_identity = false;
      process_visibility = "self";
      operation_architectures = ["native"];
      operation_allow = [];
      operation_deny = [];
      denied_operation_action = "return-permission-denied";
      operation_profile = "system-service";
      isolated_identity_mapping = "none";
    };
    service = "cloudcore";
    lifecycle = {
      description = "KubeEdge cloud control plane (${packageName} ${packageVersion})";
      execution_model = "foreground";
      environment_files = [];
      condition = [];
      pre_start = [];
      start = [
        {
          executable = {
            path = "${package}/bin/cloudcore";
            arguments = [
              "--config"
              configuration.outputs.path
            ];
          };
          ignore_failure = false;
        }
      ];
      post_start = [];
      stop = [];
      post_stop = [];
      restart = "on-failure";
      restart_delay_millis = 5000;
      remain_after_exit = false;
      start_timeout_millis = 90000;
      stop_timeout_millis = 90000;
    };
    dependencies = {
      after = [
        network.outputs.resource
        ingress.outputs.resource
      ];
      before = [];
      requires = [ingress.outputs.resource];
      wants = [network.outputs.resource];
    };
    directories.managed = [
      {
        path = "aos-pkg-cloudcore";
        purpose = "state";
        mode = "0700";
        retention = "persistent";
      }
      {
        path = "aos-pkg-cloudcore";
        purpose = "runtime";
        mode = "0750";
        retention = "restart";
      }
      {
        path = "cloudcore";
        purpose = "logs";
        mode = "0750";
        retention = "persistent";
      }
    ];
    configuration.views = [
      {
        name = "configuration";
        source = configuration.outputs.path;
        optional = false;
      }
    ];
    credentials.views =
      lib.mapAttrsToList (name: reference: {
        inherit name;
        reference = credentialPath name;
        inherit (reference) encrypted;
        optional = true;
      })
      configuredCredentials;
    logging = {
      standard_output = "structured";
      standard_error = "structured";
      directories = ["cloudcore"];
      directory_mode = "0750";
    };
    identity = {
      supplementary_groups = [];
      ephemeral = true;
      file_creation_mask = "0077";
    };
    isolation = {
      privilege = "unprivileged";
      filesystem = "read-only-system";
      network = "host";
      process_visibility = "private";
      termination_scope = "all-processes";
      temporary_directory = "private";
      devices = [];
      host_paths = [];
      permit_core_dumps = false;
    };
  };
in {
  options.aos.cloudcore = {
    advertiseAddresses = mkOption {
      type = lib.types.listOf address;
      default = ["127.0.0.1"];
      description = "Addresses advertised to EdgeCore nodes.";
    };
    monitorAddress = mkOption {
      type = nonWhitespace;
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
        type = credentialType;
        default = null;
        description = "Opaque credential reference for CloudCore's Kubernetes API kubeconfig.";
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
        type = lib.types.bool;
        default = true;
        description = "Enable CloudHub's HTTPS enrollment listener.";
      };
      address = mkOption {
        type = address;
        default = "0.0.0.0";
        description = "Address on which CloudHub accepts HTTPS enrollment requests.";
      };
      port = mkOption {
        type = port;
        default = 10002;
        readOnly = true;
        description = "Fixed HTTPS enrollment port used by this package.";
      };
    };
    websocket = {
      enable = mkOption {
        type = lib.types.bool;
        default = true;
        description = "Enable CloudHub's WebSocket listener for connected edge nodes.";
      };
      address = mkOption {
        type = address;
        default = "0.0.0.0";
        description = "Address on which CloudHub accepts WebSocket connections from edge nodes.";
      };
      port = mkOption {
        type = port;
        default = 10000;
        readOnly = true;
        description = "Fixed WebSocket listener port used by this package.";
      };
    };
    tls = {
      caCertificate = mkOption {
        type = credentialType;
        default = null;
        description = "Opaque credential reference for the CloudHub certificate authority certificate.";
      };
      caPrivateKey = mkOption {
        type = credentialType;
        default = null;
        description = "Opaque credential reference for the CloudHub certificate authority private key.";
      };
      serverCertificate = mkOption {
        type = credentialType;
        default = null;
        description = "Opaque credential reference for the CloudHub server certificate.";
      };
      serverPrivateKey = mkOption {
        type = credentialType;
        default = null;
        description = "Opaque credential reference for the CloudHub server private key.";
      };
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = !serviceEnabled || cfg.advertiseAddresses != [];
          message = "cloudcore.enable requires at least one cloudcore.advertiseAddresses entry";
        }
        {
          assertion =
            !serviceEnabled
            || builtins.all
            (reference:
              reference
              != null
              && ((reference.name != null) != (reference.resource != null)))
            requiredRefs;
          message = "cloudcore.enable requires kubeconfig and all CloudHub TLS credential references";
        }
        {
          assertion = !serviceEnabled || cfg.https.enable || cfg.websocket.enable;
          message = "cloudcore.enable requires HTTPS or WebSocket CloudHub transport";
        }
      ];
      aos.services.cloudcore = lib.mkDefault service;
    }
    (lib.mkIf serviceEnabled {
      aos.networkPolicy = {
        enable = lib.mkDefault true;
        ingress.cloudcore.endpoints =
          lib.optional cfg.websocket.enable {
            transport = "tcp";
            port = cfg.websocket.port;
          }
          ++ lib.optional cfg.https.enable {
            transport = "tcp";
            port = cfg.https.port;
          };
      };
      aos.abilities = {
        network.operations.ready.effects.cloudcore.input = {
          scope = "address-configured";
          families = ["ipv4" "ipv6"];
        };
        configuration.operations.file.effects.cloudcore.input = {
          path = "/etc/cloudcore/config.yaml";
          fragments = map (fragment:
            if fragment.kind == "literal"
            then fragment.text
            else fragment.value)
          configurationFragments;
          mode = "0444";
        };
        credential.operations.deliver.effects = builtins.listToAttrs (lib.mapAttrsToList (credentialName: input: {
            name = "cloudcore-${credentialName}";
            value = {inherit input;};
          })
          configuredCredentials);
      };
    })
  ];
}
