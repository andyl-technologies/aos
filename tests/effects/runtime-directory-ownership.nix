##! Checks native allocation boundaries against bootstrap service directory owners.
let
  lib = import ../../lib {system = "x86_64-linux";};
  artifactLib = import ../../lib/packages/artifacts.nix {};
  payload = import ./_fixture-payload.nix;
  artifact = name: {
    inherit name;
    version = "1";
    path = toString (payload name);
    outputs = lib.genAttrs ["out" "apm" "packageRuntime"] (_: toString (payload name));
    mainProgram = "handler";
  };
  record = name: source: module: let
    retained = builtins.path {
      path = source;
      name = "${name}-module";
    };
  in {
    inherit name;
    version = "1";
    configRoot = toString retained;
    module = "${retained}/${module}";
    artifacts = {
      package = artifact name;
      dependencies.nix = artifact "nix";
    };
  };
  evaluation = lib.evalPackageModules {
    scope = ["test" "runtime-directory-ownership"];
    packageModules = [
      (record "runtime-checks" ../../pkgs/system/_aos-runtime-checks "module.nix")
      (record "linux-pam" ../../pkgs/security/_linux-pam "module.nix")
      (record "openssh" ../../pkgs/networking/_openssh "module.nix")
      (record "nftables" ../../pkgs/networking/_nftables "module.nix")
      (record "filesystem" ../../pkgs/filesystem/_aos-filesystem-provider "module.nix")
      (record "services" ../../pkgs/system/_service-management "module.nix")
      (record "configuration" ../../pkgs/system/_aos-configuration-provider "module.nix")
      (record "aos" ../../pkgs/tools/aos/_abilities "module.nix")
      (record "nix-store" ../../pkgs/tools/_aos-nix-store-provider "module.nix")
    ];
    operatorModules = [
      {
        aos.abilities.serviceManagement.operations.realize.handler.program = artifactLib.value (artifact "service-handler");
        aos.services.ssh = {
          enable = true;
          usePAM = false;
          authorizedKeysFile = "/var/lib/operator-keys/%u";
        };
        aos.networkPolicy.enable = lib.mkForce false;
        aos.abilities.network.operations.ready.handler.program = artifactLib.value (artifact "network-handler");
        aos.abilities.identity.operations.group.handler.program = artifactLib.value (artifact "identity-handler");
        aos.abilities.identity.operations.principal.handler.program = artifactLib.value (artifact "identity-handler");
        aos.abilities.mount.operations.ensure.handler.program = artifactLib.value (artifact "mount-handler");
        aos.packageRuntime.configurationEvaluation.enable = true;
        aos.packageRuntime.packageProfile.enable = true;
      }
    ];
  };
  nodes = lib.mapAttrsToList (id: node: node // {inherit id;}) evaluation.deployment.graph.nodes;
  allocations = builtins.filter (node: builtins.elem "filesystem" node.identity && (builtins.elem "allocate" node.identity || builtins.elem "persistentAllocate" node.identity)) nodes;
  privateAllocations = builtins.filter (node: lib.hasPrefix "aos-runtime-" (lib.last node.identity)) allocations;
  find = name: lib.findFirst (node: lib.last node.identity == name) (throw "missing effect ${name}") nodes;
  parent = find "aos-runtime-var-lib-aos-ability-runtime";
  runApm = find "aos-runtime-run-apm";
  children = builtins.filter (node: node.input.path != parent.input.path && lib.hasPrefix "${parent.input.path}/" node.input.path) allocations;
  order = evaluation.deployment.graph.order;
  position = id: builtins.head (builtins.filter (index: builtins.elemAt order index == id) (builtins.genList (index: index) (builtins.length order)));
  precedes = before: after: position before < position after;
  registry = evaluation.config.aos.services."configuration-evaluation.registry-synchronization";
  quote = evaluation.config.aos.services."package-attestation-quote.aos-attest";
in {
  bootstrapDirectoriesHaveNoNativeAllocation = builtins.all (node: !(builtins.elem node.input.path ["/var/lib/apm" "/var/lib/apm/config" "/var/lib/apm/config/registries.d" "/run/aos-attest" "/etc/aos/packages.d" "/var/lib/profiles"])) allocations;
  registryOwnsConfigurationSubtree = map (directory: directory.path) registry.directories.managed == ["apm" "apm/config" "apm/config/registries.d"] && builtins.all (directory: directory.mode == "0755" && directory.retention == "persistent" && directory.owner == "root" && directory.group == "root") registry.directories.managed && registry.isolation.host_paths == [];
  privateChildrenDependOnExactParent = builtins.length children == 5 && builtins.all (node: node.input.parentResource.identity == parent.identity && node.input.parentResource.output == "resource" && builtins.elem parent.id node.dependencies && precedes parent.id node.id) children;
  privatePathsHaveDistinctOwners = builtins.length privateAllocations == 7 && builtins.length (lib.unique (map (node: node.input.path) privateAllocations)) == 7;
  generatedProfileFollowsOwnedRuntimeDirectory = builtins.elem runApm.id (find "package-profile-specification").dependencies && precedes runApm.id (find "package-profile-specification").id;
  profileBridgeConsumesBootstrapStorage = let
    profiles = find "nix-profiles";
  in
    builtins.elem "view" profiles.identity && profiles.input.sourcePath == "/var/lib/profiles" && builtins.any (node: builtins.elem "mount" node.identity && builtins.elem profiles.id node.dependencies) nodes;
  sshPrivateDirectoriesPrecedeTheirConsumers = let
    keys = find "ssh-host-keys";
    privilegeSeparation = find "ssh-privilege-separation";
    keygen = find "ssh.sshd-keygen";
  in
    keys.input.path
    == "/var/etc/ssh"
    && keys.input.mode == "0755"
    && privilegeSeparation.input.path == "/var/empty"
    && privilegeSeparation.input.mode == "0755"
    && builtins.elem keys.id keygen.dependencies
    && precedes keys.id keygen.id;
  sshPublicKeysHaveOnePreservingOwner = let
    ssh = evaluation.config.aos.services.ssh;
  in
    !(evaluation.config.aos.abilities.filesystem.operations.directory.effects ? ssh-authorized-keys)
    && builtins.any (directory: directory.path == "ssh/authorized_keys" && directory.purpose == "configuration" && directory.mode == "0755" && directory.retention == "persistent") ssh.directories.managed
    && builtins.any (view: view.source == "/etc/ssh/authorized_keys" && !view.optional) ssh.configuration.views
    && lib.hasInfix "AuthorizedKeysFile /var/lib/operator-keys/%u" (builtins.concatStringsSep "" evaluation.config.aos.abilities.configuration.operations.file.effects.ssh.input.fragments);
  attestationUsesManagerRuntimeDirectory = builtins.any (directory: directory.path == "aos-attest" && directory.purpose == "runtime" && directory.mode == "0700") quote.directories.managed;
}
