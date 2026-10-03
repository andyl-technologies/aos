##! Preserves exposed-package resource groups through consumer-owned native effects.
{
  lib,
  pkgs,
}: let
  root = ../..;
  specifications = [
    {
      name = "containerd";
      source = /pkgs/containers/_containerd-config;
      enable = ["containerd" "enable"];
      settings = {};
    }
    {
      name = "k3s-control-plane";
      source = /pkgs/kubernetes/_k3s-config;
      enable = ["k3s" "enable"];
      settings.k3s.token.name = "join-token";
    }
    {
      name = "k3s-combined";
      source = /pkgs/kubernetes/_k3s-config;
      enable = ["k3s" "enable"];
      settings.k3s.token.name = "join-token";
    }
    {
      name = "k3s-worker";
      source = /pkgs/kubernetes/_k3s-config;
      enable = ["k3s" "enable"];
      settings.k3s = {
        serverUrl = "https://control.example.test:6443";
        token.name = "join-token";
      };
    }
    {
      name = "cloudcore";
      source = /pkgs/kubernetes/_cloudcore-config;
      enable = ["aos" "services" "cloudcore" "enable"];
      settings.aos.cloudcore = {
        kubeApi.kubeconfig.name = "kubeconfig";
        tls = lib.genAttrs ["caCertificate" "caPrivateKey" "serverCertificate" "serverPrivateKey"] (name: {inherit name;});
      };
    }
    {
      name = "edgecore";
      source = /pkgs/kubernetes/_edgecore-config;
      enable = ["aos" "services" "edgecore" "enable"];
      settings.aos.edgecore = {
        cloudHub.httpServer = "https://cloud.example.test:10002";
        cloudHub.server = "wss://cloud.example.test:10000";
        tls = lib.genAttrs ["caCertificate" "clientCertificate" "clientPrivateKey"] (name: {inherit name;});
      };
    }
    {
      name = "kubelet";
      source = /pkgs/kubernetes/_kubelet-config;
      enable = ["aos" "services" "kubelet" "enable"];
      settings.aos.kubelet.kubeconfig.name = "kubeconfig";
    }
    {
      name = "nginx";
      source = /pkgs/networking/_nginx;
      enable = ["aos" "services" "nginx" "enable"];
      settings.aos.services.nginx.virtualHosts.default.locations."/"."return".code = 200;
    }
    {
      name = "envoy";
      source = /pkgs/networking/_envoy;
      enable = ["aos" "envoy" "enable"];
      settings.aos.envoy.listeners.http = {
        port = 8080;
        filterChains.http.virtualHosts.default.routes.root.directResponse.status = 200;
      };
    }
    {
      name = "openldap";
      source = /pkgs/networking/_openldap;
      enable = ["aos" "openldap" "enable"];
      settings.aos.openldap.rootPassword.name = "ldap-root";
    }
    {
      name = "etcd";
      source = /pkgs/db/_etcd-config;
      enable = ["aos" "etcd" "enable"];
      settings = {};
    }
    {
      name = "krb5";
      source = /pkgs/security/_krb5-kdc;
      enable = ["aos" "krb5Kdc" "enable"];
      settings.aos.krb5Kdc = {
        enableAdminServer = true;
        masterPassword.name = "kdc-master";
      };
    }
    {
      name = "garage";
      source = /pkgs/storage/_garage-config;
      enable = ["aos" "garage" "enable"];
      settings.aos.garage.rpc.secret.name = "garage-rpc";
    }
    {
      name = "mariadb";
      source = /pkgs/storage/_mariadb;
      enable = ["aos" "mariadb" "enable"];
      settings = {};
    }
    {
      name = "postgresql";
      source = /pkgs/storage/_postgresql;
      enable = ["aos" "postgresql" "enable"];
      settings.aos.postgresql.bootstrap.password.name = "postgres-password";
    }
    {
      name = "conntrack-tools";
      source = /pkgs/tools/_conntrackd;
      enable = ["aos" "conntrackd" "enable"];
      settings = {};
    }
    {
      name = "rsync";
      source = /pkgs/tools/_rsyncd;
      enable = ["aos" "rsyncd" "enable"];
      settings.aos.rsyncd.modules.public.path = "/var/lib/rsync-public";
    }
  ];
  sourceRoots = {
    service-management = /pkgs/system/_service-management;
    systemd = /pkgs/system/_systemd-abilities;
    aos-host-policy = /pkgs/system/_aos-host-policy;
    aos-configuration-provider = /pkgs/system/_aos-configuration-provider;
    aos-configuration-lower = /pkgs/boot/_aos-configuration-lower;
    aos-metadata-provider = /pkgs/tools/_aos-metadata-provider;
    glibc-locales = /pkgs/data/_glibc-locales;
    linux-pam = /pkgs/security/_linux-pam;
    kmod = /pkgs/system/_kmod-abilities;
    aos-kernel-tunable-provider = /pkgs/tools/_aos-kernel-tunable-provider;
    kernel-interface = /pkgs/kernel/_kernel-interface;
    kubernetes-interface = /pkgs/kubernetes/_kubernetes-interface;
    aos-kubernetes-provider = /pkgs/kubernetes/_aos-kubernetes-provider;
    aos-runtime-checks = /pkgs/system/_aos-runtime-checks;
    aos-filesystem-provider = /pkgs/filesystem/_aos-filesystem-provider;
    nftables = /pkgs/networking/_nftables;
    aos-network-ruleset-provider = /pkgs/networking/_aos-network-ruleset-provider;
  };
  evaluate = specification: enabled: let
    package = pkgs.${specification.name};
    packages = [package pkgs.systemd pkgs.aos-network-ruleset-provider];
    records = lib.packageModules.closure packages;
    roots = sourceRoots // {${specification.name} = specification.source;};
  in
    lib.evalPackageModules {
      scope = ["test" "package-resource-groups" specification.name];
      inherit packages;
      packageImportRoots = builtins.listToAttrs (map (record: {
          name = builtins.unsafeDiscardStringContext record.configRoot;
          value = toString (root + roots.${record.name});
        })
        records);
      operatorModules = [
        (lib.recursiveUpdate specification.settings (lib.setAttrByPath specification.enable enabled))
      ];
    };
  key = identity: builtins.hashString "sha256" (builtins.toJSON identity);
  indexOf = value: values: let
    find = index: remaining:
      if remaining == []
      then throw "Expected resource dependency is absent from activation order"
      else if builtins.head remaining == value
      then index
      else find (index + 1) (builtins.tail remaining);
  in
    find 0 values;
  serviceNames = {
    containerd = ["containerd"];
    k3s-control-plane = ["k3s"];
    k3s-combined = ["k3s"];
    k3s-worker = ["k3s"];
    cloudcore = ["cloudcore"];
    edgecore = ["edgecore"];
    kubelet = ["kubelet"];
    nginx = ["nginx"];
    envoy = ["envoy.main"];
    openldap = ["openldap.main"];
    etcd = ["etcd.main"];
    krb5 = ["krb5.initialize" "krb5.kdc" "krb5.administration"];
    garage = ["garage.main"];
    mariadb = ["mariadb.initialize" "mariadb.main"];
    postgresql = ["postgresql.initialize" "postgresql.main"];
    conntrack-tools = ["conntrack-tools.main"];
    rsync = ["rsyncd.main"];
  };
  check = specification: let
    evaluation = evaluate specification true;
    graph = evaluation.config.aos.activation.graph;
    groups = evaluation.config.aos.abilities.serviceManagement.operations.resourceGroup.effects;
    group = groups.${specification.name};
    groupKey = key group.contract.identity;
    serviceEffects = evaluation.config.aos.abilities.serviceManagement.operations.realize.effects;
    groupedEffects = map (name: serviceEffects.${name}) serviceNames.${specification.name};
    grouped = map (effect: graph.nodes.${key effect.contract.identity}) groupedEffects;
    disabled = evaluate specification false;
  in {
    oneConsumerOwnedGroup = builtins.attrNames groups == [specification.name] && group.contract.owner == specification.name && group.input.name == "aos-pkg-${specification.name}";
    resultSchemaIsTyped = group.outputs.name._type == "aos-effect-output" && group.outputs.name.schema == group.contract.results.name;
    servicesConsumeGroup = builtins.all (effect: effect.input.resources.resource_group == group.outputs.name) groupedEffects && builtins.all (node: builtins.elem groupKey node.dependencies) grouped;
    managerOwnsDerivedServices = builtins.all (node: node.owner == "service-management") grouped;
    ordinaryGroupsDoNotBootstrap = !group.input.bootstrap;
    groupPrecedesServices = builtins.all (node: indexOf groupKey graph.order < indexOf (key node.identity) graph.order) grouped;
    disabledPackageHasNoGroup = disabled.config.aos.abilities.serviceManagement.operations.resourceGroup.effects == {};
  };
in
  builtins.listToAttrs (map (specification: {
      name = specification.name;
      value = check specification;
    })
    specifications)
