##! Fixed-point checks for package-owned Kubernetes service declarations.
{lib}: let
  evaluate = name: version: module: configuration:
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
      packageModules = [{inherit name version module;}];
    };
  requests = evaluated: evaluated.config.aos.abilities.requests;
  cloudcore = evaluate "cloudcore" "1.21.0" ../../pkgs/kubernetes/_cloudcore-config/module.nix {
    cloudcore = {
      enable = true;
      advertiseAddresses = ["192.0.2.20"];
      kubeApi.kubeconfig.ref = "system-credential:kubeconfig";
      tls = {
        caCertificate.ref = "system-credential:ca";
        caPrivateKey.ref = "system-credential:ca-key";
        serverCertificate.ref = "system-credential:server";
        serverPrivateKey.ref = "system-credential:server-key";
      };
    };
  };
  edgecore = evaluate "edgecore" "1.21.0" ../../pkgs/kubernetes/_edgecore-config/module.nix {
    edgecore = {
      enable = true;
      nodeName = "edge-01";
      cloudHub = {
        httpServer = "https://cloud.example.test";
        server = "cloud.example.test:10000";
      };
      tls = {
        caCertificate.ref = "system-credential:ca";
        clientCertificate.ref = "system-credential:client";
        clientPrivateKey.ref = "system-credential:client-key";
      };
    };
  };
  kubelet = evaluate "kubelet" "1.34.0" ../../pkgs/kubernetes/_kubelet-config/module.nix {
    kubelet = {
      enable = true;
      nodeName = "worker-a";
      maxPods = 80;
      registerNode = true;
      kubeconfig.ref = "system-credential:kubelet";
    };
  };
  disabledCloudcore = evaluate "cloudcore" "1.21.0" ../../pkgs/kubernetes/_cloudcore-config/module.nix {};
  disabledEdgecore = evaluate "edgecore" "1.21.0" ../../pkgs/kubernetes/_edgecore-config/module.nix {
    edgecore.cloudHub = {
      httpServer = "https://cloud.example.test";
      server = "cloud.example.test:10000";
    };
  };
  disabledKubelet = evaluate "kubelet" "1.34.0" ../../pkgs/kubernetes/_kubelet-config/module.nix {};
  k3sWorker = evaluate "k3s-worker" "1.34.1" ../../pkgs/kubernetes/_k3s-config/module.nix {
    k3s = {
      enable = true;
      serverUrl = "https://control.example.test:6443";
      token.ref = "system-credential:k3s-token";
    };
  };
  disabledK3sWorker = evaluate "k3s-worker" "1.34.1" ../../pkgs/kubernetes/_k3s-config/module.nix {
    k3s = {
      serverUrl = "https://control.example.test:6443";
      token.ref = "system-credential:k3s-token";
    };
  };
  commandFor = evaluated: key: (requests evaluated).${key}.parameters.start;
  sourceFor = evaluated: package: (requests evaluated)."${package}:configuration".parameters.source;
  literalConfiguration = evaluated: package:
    lib.concatMapStrings (
      fragment:
        if fragment.kind == "literal"
        then fragment.text
        else "<credential-path>"
    )
    (sourceFor evaluated package).fragments;
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
  assert commandFor cloudcore "cloudcore:cloudcore-lifecycle"
  == [
    {
      executable = {
        artifact = lib.abilities.packageOutput {};
        entry_point = "bin/cloudcore";
        arguments = [
          "--config"
          {
            _type = "aos-request-output-reference";
            request = "cloudcore:configuration";
            output = "execution-path";
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
  assert requests disabledCloudcore == {};
  assert requests disabledEdgecore == {};
  assert requests disabledKubelet == {};
  assert disabledCloudcore.config.aos.abilities.requirementTemplates == cloudcore.config.aos.abilities.requirementTemplates;
  assert disabledEdgecore.config.aos.abilities.requirementTemplates == edgecore.config.aos.abilities.requirementTemplates;
  assert disabledKubelet.config.aos.abilities.requirementTemplates == kubelet.config.aos.abilities.requirementTemplates;
  assert portableOptionTree cloudcore.options.cloudcore;
  assert portableOptionTree edgecore.options.edgecore;
  assert portableOptionTree kubelet.options.kubelet;
  assert requests disabledK3sWorker == {};
  assert disabledK3sWorker.config.aos.abilities.requirementTemplates == k3sWorker.config.aos.abilities.requirementTemplates;
  assert k3sWorker.config.k3s.role == "worker";
  assert (requests k3sWorker)."k3s-worker:kernel-modules".parameters.modules
  == [
    "br_netfilter"
    "vxlan"
    "ip_set"
  ];
  assert (builtins.head (commandFor k3sWorker "k3s-worker:k3s-lifecycle")).executable
  == {
    artifact = lib.abilities.packageOutput {};
    entry_point = "bin/k3s-role-start";
    arguments = [
      {
        _type = "aos-request-output-reference";
        request = "k3s-worker:addons";
        output = "execution-path";
      }
      {
        _type = "aos-request-output-reference";
        request = "k3s-worker:token";
        output = "credential-path";
      }
    ];
  };
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
  == lib.abilities.packageOutput {};
  assert !(cloudcore.config ? systemd) && !(edgecore.config ? systemd) && !(kubelet.config ? systemd) && !(k3sWorker.config ? systemd);
  assert !(cloudcore.config.cloudcore ? config) && !(cloudcore.config.cloudcore ? credentials);
  assert !(edgecore.config.edgecore ? config) && !(edgecore.config.edgecore ? credentials);
  assert !(kubelet.config.kubelet ? config) && !(kubelet.config.kubelet ? credentials); true
