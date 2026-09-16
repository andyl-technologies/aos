##! Fixed-point checks for package-owned Kubernetes service declarations.
{
  lib,
  pkgs,
}: let
  packageModule = lib.abilities.authenticatedPackageModuleRecordFor;
  evaluatePackages = consumerPackages: configuration:
    lib.evalModules {
      inherit lib;
      modules = [
        ../../modules/abilities/default.nix
        {
          aos.abilities.environment = {
            authority = "deployment";
            key = "kubernetes-package-services-test";
            stage = "host";
          };
        }
        configuration
      ];
      packageModules = builtins.map packageModule (
        [
          pkgs.aos-kernel-tunable-provider
          pkgs.systemd
        ]
        ++ consumerPackages
      );
    };
  evaluate = package: configuration:
    evaluatePackages [package] configuration;
  evaluateIntegration = package: configuration:
    evaluatePackages [pkgs.k3s-combined package] configuration;
  requests = evaluated: evaluated.config.aos.abilities.requests;
  packageRequests = evaluated: package:
    lib.filterAttrs (name: _: lib.hasPrefix "${package}:" name) (requests evaluated);
  cloudcore = evaluate pkgs.cloudcore {
    cloudcore = {
      enable = true;
      advertiseAddresses = ["192.0.2.20"];
      kubeApi.kubeconfig.name = "kubeconfig";
      tls = {
        caCertificate.name = "ca";
        caPrivateKey.name = "ca-key";
        serverCertificate.name = "server";
        serverPrivateKey.name = "server-key";
      };
    };
  };
  edgecore = evaluate pkgs.edgecore {
    edgecore = {
      enable = true;
      nodeName = "edge-01";
      cloudHub = {
        httpServer = "https://cloud.example.test";
        server = "cloud.example.test:10000";
      };
      tls = {
        caCertificate.name = "ca";
        clientCertificate.name = "client";
        clientPrivateKey.name = "client-key";
      };
    };
  };
  kubelet = evaluate pkgs.kubelet {
    kubelet = {
      enable = true;
      nodeName = "worker-a";
      maxPods = 80;
      registerNode = true;
      kubeconfig.name = "kubelet";
    };
  };
  disabledCloudcore = evaluate pkgs.cloudcore {};
  disabledEdgecore = evaluate pkgs.edgecore {
    edgecore.cloudHub = {
      httpServer = "https://cloud.example.test";
      server = "cloud.example.test:10000";
    };
  };
  disabledKubelet = evaluate pkgs.kubelet {};
  k3sWorker = evaluate pkgs.k3s-worker {
    k3s = {
      enable = true;
      serverUrl = "https://control.example.test:6443";
      token.name = "k3s-token";
    };
  };
  disabledK3sWorker = evaluate pkgs.k3s-worker {
    k3s = {
      serverUrl = "https://control.example.test:6443";
      token.name = "k3s-token";
    };
  };
  k3sCombined = evaluate pkgs.k3s-combined {
    k3s = {
      enable = true;
      token.name = "k3s-token";
      networking.flannelBackend = "wireguard-native";
    };
  };
  k3sControlPlane = evaluate pkgs.k3s-control-plane {
    k3s = {
      enable = true;
      token.name = "k3s-token";
      server = {
        clusterInit = true;
        disableComponents = [
          "traefik"
          "servicelb"
        ];
        tlsSans = ["api.example.test"];
      };
      kubeconfigMode = "0640";
    };
  };
  objectControllerDeclaration = k3sCombined.config.aos.abilities.interfaces."k3s-combined:kubernetes-object-set";
  objectContributionDeclaration = k3sCombined.config.aos.abilities.interfaces."k3s-combined:kubernetes-objects";
  identityOf = declaration:
    lib.abilities.interfaceIdentity (
      lib.abilities.interfaceDocumentFromDeclaration declaration
    );
  objectControllerIdentity = identityOf objectControllerDeclaration;
  objectContributionIdentity = identityOf objectContributionDeclaration;
  cilium = evaluateIntegration pkgs.cilium {
    cilium = {
      enable = true;
      kubeProxyReplacement = true;
      operatorReplicas = 2;
    };
  };
  disabledCilium = evaluateIntegration pkgs.cilium {};
  longhorn = evaluateIntegration pkgs.longhorn-manager {
    longhorn = {
      enable = true;
      defaultReplicaCount = 2;
      nodeLabel = "true";
    };
  };
  disabledLonghorn = evaluateIntegration pkgs.longhorn-manager {};
  k3sPackageAbilities = pkgs.k3s-combined.abilities;
  k3sWorkerPackageAbilities = pkgs.k3s-worker.abilities;
  edgecorePackageAbilities = pkgs.edgecore.abilities;
  ciliumPackageAbilities = pkgs.cilium.abilities;
  longhornPackageAbilities = pkgs.longhorn-manager.abilities;
  commandFor = evaluated: key: (requests evaluated).${key}.parameters.start;
  outputReference = request: output: {
    _type = "aos-request-output-reference";
    inherit request output;
  };
  sourceFor = evaluated: package: (requests evaluated)."${package}:configuration".parameters.source;
  literalConfiguration = evaluated: package:
    lib.concatMapStrings (
      fragment:
        if fragment.kind == "literal"
        then fragment.text
        else "<credential-path>"
    )
    (sourceFor evaluated package).fragments;
  decodedObject = evaluated: package:
    builtins.fromJSON (
      builtins.unsafeDiscardStringContext
      (
        builtins.head (requests evaluated)."${package}:objects".parameters.objects
      ).content
    );
  containsManagerCredentialPath = source:
    builtins.any (
      fragment: fragment.kind == "literal" && lib.hasInfix "/run/credentials" fragment.text
    )
    source.fragments;
  portableOptionTree = options:
    builtins.all
    (name: let
      option = options.${name};
    in
      if option ? type
      then option.type ? _abilitySchema
      else portableOptionTree option)
    (builtins.attrNames options);
in
  assert !(lib.abilities.interfaces ? kubernetesObjectManagement);
  assert commandFor cloudcore "cloudcore:cloudcore-lifecycle"
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {package = "cloudcore";};
        entry_point = "bin/cloudcore";
        arguments = [
          "--config"
          {
            _type = "aos-request-output-reference";
            request = "cloudcore:configuration";
            output = "planned-path";
          }
        ];
      };
      ignore_failure = false;
    }
  ];
  assert (requests cloudcore)."cloudcore:ingress-policy".parameters.endpoints
  == [
    {
      transport = "tcp";
      port = 10000;
    }
    {
      transport = "tcp";
      port = 10002;
    }
  ];
  assert (requests edgecore)."edgecore:kernel-modules".parameters.modules
  == [
    "overlay"
    "br_netfilter"
  ];
  assert (requests edgecore)."edgecore:kernel-tunables".parameters
  == {
    values = {
      "net.ipv4.ip_forward" = "1";
      "net.ipv6.conf.all.forwarding" = "1";
    };
    dependencies = [];
  };
  assert builtins.elem
  (outputReference "edgecore:kernel-tunables" "readiness-resource")
  (requests edgecore)."edgecore:edgecore-dependencies".parameters.requires;
  assert let
    requirement = edgecorePackageAbilities.requirementTemplates.kernel-tunables;
    interface = builtins.head requirement.accepted_interfaces;
  in
    {
      inherit (interface) name abi descriptor;
    }
    == lib.abilities.interfaces.kernelTunables.interface.identity;
  assert (requests edgecore)."edgecore:edgecore-linux_device_policy".parameters.baseline_access
  == "standard-runtime-devices";
  assert builtins.length (
    builtins.filter (fragment: fragment.kind == "execution-path")
    (sourceFor cloudcore "cloudcore").fragments
  )
  == 5;
  assert builtins.length (
    builtins.filter (fragment: fragment.kind == "execution-path")
    (sourceFor edgecore "edgecore").fragments
  )
  == 3;
  assert (sourceFor cloudcore "cloudcore").kind == "interpolated-text";
  assert lib.hasInfix "apiVersion: cloudcore.config.kubeedge.io/v1alpha1" (literalConfiguration cloudcore "cloudcore");
  assert lib.hasInfix "    - 192.0.2.20" (literalConfiguration cloudcore "cloudcore");
  assert (sourceFor edgecore "edgecore").kind == "interpolated-text";
  assert lib.hasInfix "apiVersion: edgecore.config.kubeedge.io/v1alpha2" (literalConfiguration edgecore "edgecore");
  assert lib.hasInfix "hostnameOverride: edge-01" (literalConfiguration edgecore "edgecore");
  assert lib.hasInfix "server: cloud.example.test:10000" (literalConfiguration edgecore "edgecore");
  assert !containsManagerCredentialPath (sourceFor cloudcore "cloudcore");
  assert !containsManagerCredentialPath (sourceFor edgecore "edgecore");
  assert packageRequests disabledCloudcore "cloudcore" == {};
  assert packageRequests disabledEdgecore "edgecore" == {};
  assert packageRequests disabledKubelet "kubelet" == {};
  assert disabledCloudcore.config.aos.abilities.requirementTemplates == cloudcore.config.aos.abilities.requirementTemplates;
  assert disabledEdgecore.config.aos.abilities.requirementTemplates == edgecore.config.aos.abilities.requirementTemplates;
  assert disabledKubelet.config.aos.abilities.requirementTemplates == kubelet.config.aos.abilities.requirementTemplates;
  assert portableOptionTree cloudcore.options.cloudcore;
  assert portableOptionTree edgecore.options.edgecore;
  assert portableOptionTree kubelet.options.kubelet;
  assert portableOptionTree k3sWorker.options.k3s;
  assert portableOptionTree cilium.options.cilium;
  assert portableOptionTree longhorn.options.longhorn;
  assert packageRequests disabledK3sWorker "k3s-worker" == {};
  assert disabledK3sWorker.config.aos.abilities.requirementTemplates == k3sWorker.config.aos.abilities.requirementTemplates;
  assert packageRequests disabledCilium "cilium" == {};
  assert packageRequests disabledLonghorn "longhorn-manager" == {};
  assert disabledCilium.config.aos.abilities.requirementTemplates == cilium.config.aos.abilities.requirementTemplates;
  assert disabledLonghorn.config.aos.abilities.requirementTemplates == longhorn.config.aos.abilities.requirementTemplates;
  assert k3sWorker.config.k3s.role == "worker";
  assert k3sControlPlane.config.k3s.role == "control-plane";
  assert k3sCombined.config.k3s.role == "combined";
  assert (requests k3sControlPlane)."k3s-control-plane:k3s-environment".parameters.variables
  == {
    K3S_CLUSTER_INIT = "true";
    K3S_DISABLE = "servicelb,traefik";
    K3S_KUBECONFIG_MODE = "0640";
    K3S_TLS_SAN = "api.example.test";
  };
  assert (requests k3sControlPlane)."k3s-control-plane:token-source".parameters.name
  == "k3s-token";
  assert (requests k3sCombined)."k3s-combined:configuration-base".parameters.base.flannel_backend
  == "wireguard-native";
  assert (requests k3sWorker)."k3s-worker:kernel-modules".parameters.modules
  == [
    "br_netfilter"
    "vxlan"
    "ip_set"
  ];
  assert (requests k3sWorker)."k3s-worker:kernel-tunables".parameters
  == {
    values = {
      "net.bridge.bridge-nf-call-ip6tables" = "1";
      "net.bridge.bridge-nf-call-iptables" = "1";
      "net.ipv4.ip_forward" = "1";
      "net.ipv6.conf.all.forwarding" = "1";
    };
    dependencies = [];
  };
  assert builtins.elem
  (outputReference "k3s-worker:kernel-tunables" "readiness-resource")
  (requests k3sWorker)."k3s-worker:k3s-dependencies".parameters.requires;
  assert let
    requirement = k3sWorkerPackageAbilities.requirementTemplates.kernel-tunables;
    interface = builtins.head requirement.accepted_interfaces;
  in
    {
      inherit (interface) name abi descriptor;
    }
    == lib.abilities.interfaces.kernelTunables.interface.identity;
  assert (requests k3sWorker)."k3s-worker:ingress-policy".parameters.endpoints
  == [
    {
      transport = "tcp";
      port = 10250;
    }
    {
      transport = "udp";
      port = 8472;
    }
  ];
  assert (requests k3sWorker)."k3s-worker:forwarding-policy".parameters.policy == "accept";
  assert (builtins.head (commandFor k3sWorker "k3s-worker:k3s-lifecycle")).executable
  == {
    artifact = lib.abilities.packageOutput {package = "k3s-worker";};
    entry_point = "bin/k3s-role-start";
    arguments = [
      {
        _type = "aos-request-output-reference";
        request = "k3s-worker:configuration-base";
        output = "planned-path";
      }
      {
        _type = "aos-request-output-reference";
        request = "k3s-worker:token";
        output = "credential-path";
      }
    ];
  };
  assert (requests k3sCombined)."k3s-combined:cluster-objects".parameters.cluster.prerequisites
  == [
    {
      _type = "aos-request-output-reference";
      request = "k3s-combined:lifecycle";
      output = "retained-resource";
    }
  ];
  assert builtins.any
  (directory:
    directory.path
    == "rancher/k3s"
    && directory.purpose == "configuration"
    && directory.mode == "0755"
    && directory.retention == "persistent")
  (requests k3sCombined)."k3s-combined:k3s-directories".parameters.managed;
  assert k3sCombined.config.aos.abilities.implementations."k3s-combined:kubernetes-object-set".interface
  == objectControllerIdentity;
  assert builtins.attrNames k3sPackageAbilities.interfaces
  == [
    "k3s-configuration"
    "k3s-configuration-effects"
    "k3s-integration"
    "kubernetes-object-effects"
    "kubernetes-object-set"
    "kubernetes-objects"
  ];
  assert k3sPackageAbilities.implementations.kubernetes-object-set.interface
  == objectControllerIdentity;
  assert k3sPackageAbilities.implementations.kubernetes-objects.interface
  == objectContributionIdentity;
  assert objectControllerDeclaration.lifecycle.persistentDeleteMethod == null;
  assert objectContributionDeclaration.lifecycle.persistentDeleteMethod == null;
  assert objectControllerDeclaration.methods.release.semantics
  == {
    requiredTargetAccess = "exclusive-write";
    stopsProvider = true;
  };
  assert builtins.attrNames objectControllerDeclaration.outputs
  == [
    "cluster-readiness-resource"
    "kubeconfig-resource"
    "readiness-resource"
  ];
  assert k3sPackageAbilities.implementations.kubernetes-object-set ? provider_module;
  assert !(k3sPackageAbilities.implementations.kubernetes-object-set ? handler);
  assert k3sPackageAbilities.implementations.kubernetes-objects ? provider_module;
  assert !(k3sPackageAbilities.implementations.kubernetes-objects ? handler);
  assert !(k3sPackageAbilities.implementations.kubernetes-object-effects ? provider_module);
  assert k3sPackageAbilities.implementations.kubernetes-object-effects ? handler;
  assert k3sPackageAbilities.implementations.k3s-configuration ? provider_module;
  assert !(k3sPackageAbilities.implementations.k3s-configuration ? handler);
  assert k3sPackageAbilities.implementations.k3s-integration ? provider_module;
  assert !(k3sPackageAbilities.implementations.k3s-integration ? handler);
  assert !(k3sPackageAbilities.implementations.k3s-configuration-effects ? provider_module);
  assert k3sPackageAbilities.implementations.k3s-configuration-effects ? handler;
  assert (requests kubelet)."kubelet:kubelet-supervision".parameters.startup_protocol == "notification";
  assert let
    configuration = builtins.fromJSON (
      builtins.unsafeDiscardStringContext (sourceFor kubelet "kubelet").content
    );
  in
    configuration.apiVersion
    == "kubelet.config.k8s.io/v1beta1"
    && configuration.maxPods == 80
    && configuration.containerRuntimeEndpoint == "unix:///run/containerd/containerd.sock";
  assert lib.elem "worker-a" (builtins.head (commandFor kubelet "kubelet:kubelet-lifecycle")).executable.arguments;
  assert (requests kubelet)."kubelet:kubeconfig-source".parameters.name == "kubelet";
  assert (requests kubelet)."kubelet:ingress-policy".parameters.endpoints
  == [
    {
      transport = "tcp";
      port = 10250;
    }
  ];
  assert (requests kubelet)."kubelet:kubelet-linux_device_policy".parameters.rules
  == [
    {
      selector = {
        kind = "class";
        device_type = "character";
        class = "kernel-message";
      };
      read = true;
      write = true;
      create_node = false;
    }
  ];
  assert (builtins.head (commandFor kubelet "kubelet:kubelet-lifecycle")).executable.artifact
  == lib.abilities.packageOutput {package = "kubelet";};
  assert (cilium.config.aos.abilities.requirementTemplates."cilium:kubernetes-objects".descriptor or null) == null;
  assert (cilium.config.aos.abilities.requirementTemplates."cilium:k3s-integration".descriptor or null) == null;
  assert (decodedObject cilium "cilium").spec.version == "1.17.3";
  assert builtins.fromJSON (decodedObject cilium "cilium").spec.valuesContent
  == {
    kubeProxyReplacement = true;
    operator.replicas = 2;
  };
  assert (longhorn.config.aos.abilities.requirementTemplates."longhorn-manager:kubernetes-objects".descriptor or null) == null;
  assert (longhorn.config.aos.abilities.requirementTemplates."longhorn-manager:k3s-integration".descriptor or null) == null;
  assert (decodedObject longhorn "longhorn-manager").spec.version == "1.8.1";
  assert builtins.fromJSON (decodedObject longhorn "longhorn-manager").spec.valuesContent
  == {
    defaultSettings.defaultReplicaCount = "2";
    persistence.defaultClassReplicaCount = 2;
  };
  assert (requests longhorn)."longhorn-manager:configuration".parameters.node_labels
  == {"node.longhorn.io/create-default-disk" = "true";};
  assert builtins.attrNames ciliumPackageAbilities.interfaces == [];
  assert builtins.attrNames longhornPackageAbilities.interfaces == [];
  assert !(cloudcore.config.cloudcore ? config) && !(cloudcore.config.cloudcore ? credentials);
  assert !(edgecore.config.edgecore ? config) && !(edgecore.config.edgecore ? credentials);
  assert !(kubelet.config.kubelet ? config) && !(kubelet.config.kubelet ? credentials); true
