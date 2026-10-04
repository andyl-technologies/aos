##! Checks enabled native package services and shared manager ownership.
let
  lib = import ../../lib {system = "x86_64-linux";};
  artifactLib = import ../../lib/packages/artifacts.nix {};
  fixturePayload = import ./_fixture-payload.nix;
  artifact = name: {
    inherit name;
    version = "1";
    path = toString (fixturePayload name);
    outputs =
      {out = toString (fixturePayload name);}
      // lib.optionalAttrs (name == "openssh") {server = toString (fixturePayload "openssh-server");};
    mainProgram = name;
  };
  record = name: source: dependencies: let
    retained = builtins.path {
      path = source;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1";
    configRoot = toString retained;
    module = "${retained}/module.nix";
    artifacts = {
      package = artifact name;
      inherit dependencies;
    };
  };
  dependenciesFor = names:
    builtins.listToAttrs (builtins.map (name: {
        inherit name;
        value = artifact name;
      })
      names);
  evaluationArgs = {
    scope = ["test" "native-daemons"];
    packageModules = [
      (record "aos-runtime-checks" ../../pkgs/system/_aos-runtime-checks {})
      (record "service-management" ../../pkgs/system/_service-management {})
      (record "filesystem" ../../pkgs/filesystem/_aos-filesystem-provider {})
      (record "docker-engine" ../../pkgs/containers/_docker-engine {})
      (record "tailscale" ../../pkgs/networking/_tailscale (dependenciesFor ["getent" "iproute2" "iptables" "procps-ng"]))
      (record "chrony" ../../pkgs/networking/_chrony-abilities {})
      (record "nginx" ../../pkgs/networking/_nginx {})
      (record "openldap" ../../pkgs/networking/_openldap {})
      (record "envoy" ../../pkgs/networking/_envoy {})
      (record "etcd" ../../pkgs/db/_etcd-config {})
    ];
    operatorModules = [
      {
        aos.services = {
          docker.enable = true;
          tailscale.enable = true;
          chrony.enable = true;
          nginx = {
            enable = true;
            virtualHosts.default.locations."/"."return".code = 200;
          };
        };
        aos.openldap = {
          enable = true;
          rootPassword.name = "ldap-root";
        };
        aos.envoy = {
          enable = true;
          listeners.http = {
            port = 8080;
            filterChains.http.virtualHosts.default.routes.root.directResponse.status = 200;
          };
        };
        aos.etcd.enable = true;
        aos.abilities = builtins.listToAttrs (builtins.map (ability: {
            name = ability.name;
            value.operations = builtins.listToAttrs (builtins.map (operation: {
                name = operation;
                value.handler.program = artifactLib.value (artifact "${ability.name}-handler");
              })
              ability.operations);
          }) [
            {
              name = "serviceManagement";
              operations = ["realize" "resourceGroup"];
            }
            {
              name = "identity";
              operations = ["group" "principal"];
            }
            {
              name = "network";
              operations = ["ready"];
            }
            {
              name = "device";
              operations = ["present"];
            }
            {
              name = "configuration";
              operations = ["file"];
            }
            {
              name = "credential";
              operations = ["deliver"];
            }
          ]);
      }
    ];
  };
  evaluated = lib.evalPackageModules evaluationArgs;
  nodes = builtins.attrValues evaluated.deployment.graph.nodes;
  services = builtins.filter (node: builtins.elem "serviceManagement" node.identity && builtins.elem "realize" node.identity) nodes;
  inputFiles = evaluated.config.aos.abilities.configuration.operations.file.effects;
  evaluateOpkssh = enabled:
    lib.evalPackageModules {
      scope = ["test" "opkssh"];
      packageModules = [
        (record "aos-runtime-checks" ../../pkgs/system/_aos-runtime-checks {})
        (record "service-management" ../../pkgs/system/_service-management {})
        (record "filesystem" ../../pkgs/filesystem/_aos-filesystem-provider {})
        (record "nftables" ../../pkgs/networking/_nftables {})
        (record "linux-pam" ../../pkgs/security/_linux-pam {})
        (record "openssh" ../../pkgs/networking/_openssh {})
        (record "opkssh" ../../pkgs/security/_opkssh {})
      ];
      operatorModules = [
        {
          aos.security.opkssh.enable = enabled;
          aos.services.ssh.enable = enabled;
          aos.abilities = {
            serviceManagement.operations.realize.handler.program = artifactLib.value (artifact "service-handler");
            configuration.operations.file.handler.program = artifactLib.value (artifact "file-handler");
            identity.operations.group.handler.program = artifactLib.value (artifact "identity-handler");
            identity.operations.principal.handler.program = artifactLib.value (artifact "identity-handler");
            network.operations.ready.handler.program = artifactLib.value (artifact "network-handler");
            networkPolicy.operations.ruleset.handler.program = artifactLib.value (artifact "firewall-handler");
          };
        }
      ];
    };
  opkssh = evaluateOpkssh true;
  disabledOpkssh = evaluateOpkssh false;
  opksshLog = opkssh.config.aos.abilities.filesystem.operations.entry.effects.opkssh-log;
  opksshLogNode = builtins.head (builtins.filter (node: builtins.elem "opkssh-log" node.identity) (builtins.attrValues opkssh.deployment.graph.nodes));
  opksshLogId = builtins.head (builtins.attrNames (lib.filterAttrs (_: node: builtins.elem "opkssh-log" node.identity) opkssh.deployment.graph.nodes));
  opksshSshNode = builtins.head (builtins.filter (node: builtins.elem "serviceManagement" node.identity && builtins.elem "realize" node.identity && builtins.elem "ssh" node.identity) (builtins.attrValues opkssh.deployment.graph.nodes));
  nixDaemon = lib.evalPackageModules {
    scope = ["profile" "system"];
    packageModules = [
      (record "service-management" ../../pkgs/system/_service-management {})
      (record "filesystem" ../../pkgs/filesystem/_aos-filesystem-provider {})
      (record "aos-nix-store-provider" ../../pkgs/tools/_aos-nix-store-provider {})
      (record "nix-daemon" ../../pkgs/tools/_nix-daemon-config (dependenciesFor ["nix" "bash" "coreutils" "systemd"]))
    ];
    operatorModules = [
      {
        nix-daemon.enable = false;
        aos.abilities = builtins.listToAttrs (map (ability: {
            name = ability.name;
            value.operations = builtins.listToAttrs (map (name: {
                inherit name;
                value.handler.program = artifactLib.value (artifact "${ability.name}-handler");
              })
              ability.operations);
          }) [
            {
              name = "serviceManagement";
              operations = ["realize"];
            }
            {
              name = "identity";
              operations = ["group" "principal" "membership"];
            }
            {
              name = "configuration";
              operations = ["file"];
            }
            {
              name = "mount";
              operations = ["ensure"];
            }
          ]);
      }
    ];
  };
  nixDaemonLower =
    (import ../../pkgs/system/_aos-host-policy/configuration-lower.nix {
      inherit lib;
      config = nixDaemon.config;
    }).config._value.aos.configurationLower;
  nixDaemonPersistentFiles = ["nix-daemon-slice" "nix-daemon-resources"];
  nixDaemonFile = name: nixDaemon.config.aos.abilities.configuration.operations.file.effects.${name};
  nixDaemonNodeId = name: builtins.hashString "sha256" (builtins.toJSON (nixDaemonFile name).contract.identity);
in {
  nixDaemonFilesRemainPersistent = assert builtins.all
  (name: let
    effect = nixDaemonFile name;
    node = nixDaemon.deployment.graph.nodes.${nixDaemonNodeId name};
  in
    effect.lifetime
    == "persistent"
    && node.lifetime == "persistent"
    && node.input.path == effect.input.path)
  nixDaemonPersistentFiles; true;
  nixDaemonLowerRetainsExactFileEffects = assert builtins.all
  (name: let
    effect = nixDaemonFile name;
    path = lib.removePrefix "/etc/" effect.input.path;
  in
    nixDaemonLower.files.${path}.text
    == effect.input.content
    && nixDaemonLower.ownership.files.${path} == effect.contract.owner
    && nixDaemonLower.fileEffects.${path}
    == {
      id = nixDaemonNodeId name;
      lifetime = "persistent";
    })
  nixDaemonPersistentFiles; true;
  nixDaemonPersistentFilesHaveOneProducer = assert builtins.all
  (name:
    builtins.length (builtins.filter
      (node:
        builtins.elem "configuration" node.identity
        && builtins.elem "file" node.identity
        && node.input.path == (nixDaemonFile name).input.path)
      (builtins.attrValues nixDaemon.deployment.graph.nodes))
    == 1)
  nixDaemonPersistentFiles; true;
  dynamicStorageHasOneOwner = assert builtins.all
  (name:
    evaluated.config.aos.services.${name}.identity.ephemeral
    && builtins.all (mount: mount.ownership == "service-identity" && mount.directory_mode != null)
    evaluated.config.aos.services.${name}.storage.mounts)
  ["nginx" "envoy.main" "etcd.main"];
  assert !(builtins.any
    (node:
      builtins.elem "filesystem" node.identity
      && builtins.elem node.owner ["nginx" "envoy" "etcd"])
    nodes); true;
  staticStorageKeepsProviderPermissions = assert builtins.all
  (mount: mount.ownership == "provider" && mount.directory_mode == null)
  evaluated.config.aos.services."openldap.main".storage.mounts;
  assert evaluated.config.aos.abilities.filesystem.operations.directory.effects.openldap-data.input.mode == "0700";
  assert evaluated.config.aos.abilities.filesystem.operations.directory.effects.openldap-data.input.owner != null; true;
  nginxPathsRejectEscapes = assert builtins.all (root:
    !(builtins.tryEval (builtins.deepSeq
      (lib.evalPackageModules (evaluationArgs // {operatorModules = evaluationArgs.operatorModules ++ [{aos.services.nginx.virtualHosts.default.root = lib.mkForce root;}];})).deployment.graph
      true)).success)
  ["/outside" "../outside" "www/../outside" "www//outside" "www/./outside"]; true;
  nginxPathsRemainLexical = assert lib.hasInfix "/var/lib/aos-pkg-nginx/www" (lib.concatStringsSep "" inputFiles.nginx.input.fragments);
  assert lib.hasInfix "/run/aos-pkg-nginx/nginx.pid" (lib.concatStringsSep "" inputFiles.nginx.input.fragments); true;
  exposeProfilesReturnPermissionDenied = assert builtins.all (name: evaluated.config.aos.services.${name}.policy.hardening.denied_operation_action == "return-permission-denied") ["nginx" "openldap.main" "envoy.main" "etcd.main"]; true;
  chronyPreservesBlacklistWithoutBaseAllowlist = assert evaluated.config.aos.services.chrony.policy.hardening.operation_profile == "privileged";
  assert evaluated.config.aos.services.chrony.policy.hardening.denied_operation_action == "kill-process";
  assert evaluated.config.aos.services.chrony.policy.hardening.operation_deny != [];
  assert evaluated.config.aos.services.chrony.policy.hardening.operation_allow != []; true;
  opksshPreservesMutableLog = assert opksshLog.input.kind == "empty-file";
  assert opksshLog.input.path == "/var/log/opkssh.log";
  assert opksshLog.input.mode == "0660";
  assert opksshLog.input.owner == "root";
  assert opksshLog.input.group == opkssh.config.aos.abilities.identity.operations.group.effects.opkssh.outputs.name;
  assert opksshLog.input.sourcePath == null;
  assert opksshLogNode.lifetime == "persistent"; true;
  opksshSshWaitsForLog = assert builtins.elem opksshLogId opksshSshNode.dependencies;
  assert builtins.elem opksshLog.outputs.resource opkssh.config.aos.services.ssh.dependencies.prerequisites; true;
  disabledOpksshDoesNotCreateLog = assert disabledOpkssh.config.aos.abilities.filesystem.operations.entry.effects == {};
  assert !(builtins.any (node: node.owner == "opkssh") (builtins.attrValues disabledOpkssh.deployment.graph.nodes)); true;
  stableManagerIdentities = assert evaluated.config.aos.abilities.serviceManagement.operations.realize.effects.chrony.input.service == "chronyd";
  assert evaluated.config.aos.abilities.serviceManagement.operations.realize.effects.tailscale.input.service == "tailscaled"; true;
  chronyPreservesStateIdentity = assert evaluated.config.aos.abilities.identity.operations.group.effects.chrony.input.requested_id == 994;
  assert evaluated.config.aos.abilities.identity.operations.principal.effects.chrony.input.requested_id == 994; true;
  chronyConfigurationChangesReconcile = assert builtins.any (reference: reference == evaluated.config.aos.abilities.configuration.operations.file.effects.chrony.outputs.resource) evaluated.config.aos.services.chrony.dependencies.prerequisites; true;
  dockerWaitsForConfiguredAddress = assert evaluated.config.aos.abilities.network.operations.ready.effects.docker.input.scope == "address-configured"; true;
  protectedHomeDirectories = assert evaluated.config.aos.services.chrony.isolation.home_access == "inaccessible";
  assert evaluated.config.aos.services.tailscale.isolation.home_access == "inaccessible"; true;
  sharedServiceManager = assert builtins.length services == 7;
  assert builtins.all (node: node.owner == "service-management") services;
  assert builtins.all (node: node.dependencies != []) services; true;
  retainedExecutables = assert lib.hasSuffix "/bin/dockerd" (builtins.head evaluated.config.aos.services.docker.lifecycle.start).executable.path;
  assert lib.hasSuffix "/bin/tailscaled" (builtins.head evaluated.config.aos.services.tailscale.lifecycle.start).executable.path; true;
  materializedStructuredPaths = assert inputFiles.etcd.input.format == "json";
  assert inputFiles.envoy.input.format == "json";
  assert inputFiles.etcd.input.value."data-dir" == "/var/lib/aos-pkg-etcd"; true;
  protectedCredentialContents = assert inputFiles.openldap.input.mode == "0600";
  assert builtins.any (fragment: builtins.isAttrs fragment && fragment ? credentialPath) inputFiles.openldap.input.fragments; true;
}
