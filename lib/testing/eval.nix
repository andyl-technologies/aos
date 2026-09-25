# lib/testing/eval.nix — Focused evaluation and rendered-artifact checks
#
# No VMs and no host tools. Instantiation forces the module graph to resolve;
# the derivation then runs AOS-built tools over evaluated artifacts that need
# command-line validation.
#
# Each returned derivation forces only the fixtures used by its assertions.
{
  pkgs,
  lib,
  system,
  mkSystem,
  mkDeployableSystem,
}: let
  mkPureCheck = name: assertions:
    builtins.derivation {
      name = "aos-eval-${name}-0";
      system = lib.system;
      builder = "${pkgs.bash}/bin/bash";
      args = [
        "-c"
        ''
          set -euo pipefail
          ${assertions}
          echo PASS > "$out"
        ''
      ];
    };

  baseLib = system.config.aos.config.evalAtBoot.baseLib;
  abilityRequests = system.config.aos.abilities.requests;
  imageBootCommitLifecycle = abilityRequests."aos:image-boot-commit-lifecycle".parameters;
  imageBootCommitDependencies = abilityRequests."aos:image-boot-commit-dependencies".parameters;
  initrdAbilityRequests = system.config.system.build.initrdAbilityGraph.requests;
  initrdAbilityImplementations = system.config.system.build.initrdAbilityGraph.implementations;
  initrdTrustAnchors =
    builtins.filter
    (root:
      builtins.match
      "/nix/store/[a-z0-9]+-aos-initrd-runtime-files-aos-metadata-provider"
      root
      != null)
    system.config.aos.boot.initrd.runtimeRoots;
  hostAbilityResources = builtins.attrValues system.config.aos.abilities.resolvedResources;
  serviceResource = managerName: let
    matches =
      builtins.filter
      (resource:
        resource.kind
        == "aos.service.instance"
        && (resource.value.manager_identity.name or resource.value.service) == managerName)
      hostAbilityResources;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "the host fixed point must contain one service resource managed as '${managerName}'";
  resultOfAos = request: {
    _type = "aos-request-output-reference";
    request = "aos:${request}";
    output = "resource";
  };
  aosEvalService = serviceResource "aos-eval";
  registrySyncService = serviceResource "aos-registry-sync";
  activationPreflightService = serviceResource "aos-graph-compile";
  activationService = serviceResource "aos-activate";
  aosEvalCommand = builtins.head aosEvalService.value.lifecycle.start;
  registrySyncCommand = builtins.head registrySyncService.value.lifecycle.start;
  activationPreflightCommand = builtins.head activationPreflightService.value.lifecycle.start;
  activationCommand = builtins.head activationService.value.lifecycle.start;
  initrdRequest = package: name: initrdAbilityRequests."${package}:${name}".parameters;
  initrdOutput = package: name: output: {
    _type = "aos-request-output-reference";
    request = "${package}:${name}";
    inherit output;
  };
  initrdAbilityResources =
    builtins.attrValues system.config.system.build.initrdAbilityGraph.resolvedResources;
  initrdServiceResource = serviceName: let
    matches =
      builtins.filter
      (resource:
        resource.kind
        == "aos.service.instance"
        && resource.value.service == serviceName)
      initrdAbilityResources;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "the initrd fixed point must contain one '${serviceName}' service resource";
  configSeedService = initrdServiceResource "aos-config-seed";
  configSeedCommand = builtins.head configSeedService.value.lifecycle.start;
  etcOverlayScript = builtins.readFile ../../pkgs/boot/_aos-boot-preparations/etc-overlay-setup.sh;
  abiOverrideSystem = mkDeployableSystem [
    ../../systems/server.nix
    ./fixtures/module-abi-v2.nix
  ];
  inlineAbiOverrideSystem = mkDeployableSystem [
    ../../systems/server.nix
    {aos.system.moduleAbi = 2;}
  ];
  serverRoleSystem = mkSystem [
    ../../systems/server.nix
    {aos.roles.server.enable = true;}
  ];
  serverRoleResources =
    builtins.attrValues serverRoleSystem.config.aos.abilities.resolvedResources;
  serverRoleService = serviceName: let
    matches =
      builtins.filter
      (resource:
        resource.kind
        == "aos.service.instance"
        && resource.value.service == serviceName)
      serverRoleResources;
  in
    if builtins.length matches == 1
    then builtins.head matches
    else throw "the server role must contain one '${serviceName}' service resource";
  sshReadyService = serverRoleService "aos-ssh-ready";
  sshDaemonService = serverRoleService "sshd";
  sshReadyCommand = builtins.head sshReadyService.value.lifecycle.start;
  sshReadyReference = {
    _type = "aos-request-output-reference";
    request = "openssh:aos-ssh-ready-lifecycle";
    output = "resource";
  };
  baseLibFollowsImageAbi =
    if abiOverrideSystem.config.aos.config.evalAtBoot.baseLib.passthru.moduleAbi == 2
    then "2"
    else throw "the base library ABI must follow source-backed image module overrides";
  inlineAbiBaseLib =
    builtins.tryEval inlineAbiOverrideSystem.config.aos.config.evalAtBoot.baseLib.drvPath;
  inlineImageModuleRejected =
    if !inlineAbiBaseLib.success
    then "yes"
    else throw "the base library must reject inline image modules it cannot replay";
  serverSshWaitsForLiveHostPolicy =
    if
      !(builtins.elem sshReadyReference sshDaemonService.value.dependencies.after)
      || !(builtins.elem sshReadyReference sshDaemonService.value.dependencies.wants)
    then throw "server sshd must wait for the host-policy readiness gate"
    else if
      sshReadyCommand.executable.entry_point
      != "libexec/aos-openssh-host-policy-wait"
    then throw "the SSH readiness gate must use the package-owned policy observer"
    else if
      builtins.elem
      (resultOfAos "aos-graph-compile-lifecycle")
      sshDaemonService.value.dependencies.after
    then throw "server sshd must not form a cycle with graph activation"
    else "package-owned readiness resource";
  verityDisablesGenericLuks = let
    occurrences = builtins.length (builtins.filter (parameter: parameter == "rd.luks=0") system.config.aos.boot.kernelParams);
  in
    if occurrences != 1
    then throw "the verity image must disable generic initrd LUKS discovery exactly once"
    else "ok";

  namedOutputPropagationProbe = pkgs.mkDerivation {
    pname = "named-output-propagation-probe";
    version = "0";
    src = null;
    outputs = ["out" "dev"];
    propagatedDeps = [pkgs.pcre2];
    phases = [];
  };
  namedOutputsPreservePackageMetadata =
    if
      builtins.map builtins.toString namedOutputPropagationProbe.dev.propagatedDeps
      != [(builtins.toString pkgs.pcre2)]
    then throw "named derivation outputs must preserve propagated dependencies"
    else if namedOutputPropagationProbe.dev.pname != namedOutputPropagationProbe.pname
    then throw "named derivation outputs must preserve the package identity"
    else "propagated dependencies and package identity";

  mergeImageManifest = import ../build/merge-image-manifest.nix {inherit lib;};
  activationImageOverride = let
    hostnameUnit = "aos-hostname.service";
    hostnamePath = "systemd/system/${hostnameUnit}";
    hostnameScript = "${hostnameUnit}:ExecStart.0";
    firewallUnit = "nftables.service";
    firewallPath = "systemd/system/${firewallUnit}";
    firewallWant = "systemd/system/multi-user.target.wants/${firewallUnit}";
    emptyOwnership = {
      etc = {};
      jobScripts = {};
      users = {};
      storePaths = {};
    };
    baseline = {
      etc = {
        ${hostnamePath} = {
          kind = "text";
          text = "candidate unit\n#aos-jobscript:${hostnameScript}#";
          mode = "0644";
        };
        ${firewallPath} = {
          kind = "text";
          text = "firewall";
          mode = "0644";
        };
        ${firewallWant} = {
          kind = "symlink";
          target = "../${firewallUnit}";
        };
      };
      jobScripts.${hostnameScript} = {
        text = "hostname aos";
        mode = "0755";
        name = "hostname";
      };
      users = [];
      storePaths = [];
      ownership =
        emptyOwnership
        // {
          etc = builtins.mapAttrs (_: _: "@base") baseline.etc;
          jobScripts.${hostnameScript} = "@base";
        };
    };
    imageManifest =
      baseline
      // {
        etc =
          baseline.etc
          // {
            ${hostnamePath} = {
              kind = "text";
              text = "image unit";
              mode = "0644";
            };
          };
      };
    candidate =
      baseline
      // {
        etc = builtins.removeAttrs baseline.etc [firewallPath firewallWant];
        jobScripts.${hostnameScript} = {
          text = "hostname node-1";
          mode = "0755";
          name = "hostname";
        };
        ownership =
          baseline.ownership
          // {
            etc = builtins.removeAttrs baseline.ownership.etc [firewallPath firewallWant];
          };
      };
    merged = mergeImageManifest {inherit imageManifest baseline candidate;};
  in
    if merged.etc.${hostnamePath}.text != "candidate unit\n#aos-jobscript:${hostnameScript}#"
    then throw "a changed generated job script must select its candidate unit body"
    else if merged.ownership.etc.${hostnamePath} != "@host"
    then throw "a changed generated job script must make its candidate unit host-owned"
    else if merged.removedEtc != [firewallWant firewallPath]
    then throw "explicitly removed image artifacts must become deterministic overlay removals"
    else if builtins.hasAttr firewallPath merged.etc
    then throw "explicitly removed image artifacts must not survive manifest merging"
    else "ok";

  activationStaticImageOwner = let
    path = "/nix/store/00000000000000000000000000000000-static-package";
    shipped = {
      etc."systemd/journald.conf" = {
        kind = "text";
        text = "image";
        mode = "0644";
      };
      jobScripts = {};
      users = [];
      storePaths = [path];
      packages = [];
      ownership = {
        etc."systemd/journald.conf" = "systemd";
        jobScripts = {};
        users = {};
        storePaths.${path} = "systemd";
      };
    };
    unchanged = mergeImageManifest {
      imageManifest = shipped;
      baseline = shipped;
      candidate = shipped;
    };
    changed = mergeImageManifest {
      imageManifest = shipped;
      baseline = shipped;
      candidate = shipped // {etc."systemd/journald.conf".text = "host";};
    };
  in
    if unchanged.ownership.etc."systemd/journald.conf" != "@base"
    then throw "static package files shipped by the image must be base-owned at runtime"
    else if unchanged.ownership.storePaths.${path} != "@base"
    then throw "static package paths shipped by the image must be base-owned at runtime"
    else if changed.ownership.etc."systemd/journald.conf" != "@host"
    then throw "host changes to static image files must be host-owned"
    else "ok";

  activationStructuralReplacement = let
    ownershipFor = etc: {
      etc = builtins.mapAttrs (_: _: "@base") etc;
      jobScripts = {};
      users = {};
      storePaths = {};
    };
    manifestWithEtc = etc: {
      inherit etc;
      jobScripts = {};
      users = [];
      storePaths = [];
      ownership = ownershipFor etc;
    };
    oldFile = {
      "service" = {
        kind = "text";
        text = "old";
        mode = "0644";
      };
    };
    newSubtree = {
      "service/config" = {
        kind = "text";
        text = "new";
        mode = "0644";
      };
    };
    oldSubtree = {
      "service/config" = {
        kind = "text";
        text = "old";
        mode = "0644";
      };
    };
    newFile = {
      "service" = {
        kind = "text";
        text = "new";
        mode = "0644";
      };
    };
    fileToDirectory = mergeImageManifest {
      imageManifest = manifestWithEtc oldFile;
      baseline = manifestWithEtc oldFile;
      candidate = manifestWithEtc newSubtree;
    };
    directoryToFile = mergeImageManifest {
      imageManifest = manifestWithEtc oldSubtree;
      baseline = manifestWithEtc oldSubtree;
      candidate = manifestWithEtc newFile;
    };
  in
    if fileToDirectory.removedEtc != [] || !(builtins.hasAttr "service/config" fileToDirectory.etc)
    then throw "a candidate subtree must structurally hide the image file it replaces"
    else if directoryToFile.removedEtc != [] || !(builtins.hasAttr "service" directoryToFile.etc)
    then throw "a candidate file must structurally hide the image subtree it replaces"
    else "ok";

  assertRecurringLifecycleUnit = name: unit:
    if unit.unitConfig ? ConditionFirstBoot
    then throw "${name} must not be guarded by ConditionFirstBoot"
    else if unit.unitConfig ? ConditionNeedsUpdate
    then throw "${name} must not be guarded by ConditionNeedsUpdate"
    else "ok";
  assertOptionalRecurringLifecycleUnit = name:
    if builtins.hasAttr name system.config.systemd.services
    then assertRecurringLifecycleUnit name system.config.systemd.services.${name}
    else "not-present";
  rfcLifecycleRecurrence =
    builtins.seq
    (assertOptionalRecurringLifecycleUnit "systemd-tmpfiles-setup")
    (builtins.seq
      (assertOptionalRecurringLifecycleUnit "systemd-tmpfiles-setup-dev")
      (assertOptionalRecurringLifecycleUnit "systemd-sysusers"));

  # Provisioning and configuration are structural. The stock system always
  # emits every stage.
  structuralConfiguration =
    if aosEvalService.value.service != "configuration-evaluation"
    then throw "the stock fixed point must contain package-owned host configuration evaluation"
    else if registrySyncService.value.service != "registry-synchronization"
    then throw "the stock fixed point must contain package-owned registry synchronization"
    else if
      !(builtins.elem
        (resultOfAos "registry-synchronization-lifecycle")
        aosEvalService.value.dependencies.wants)
    then throw "host evaluation must request the signed registry snapshot refresh"
    else if
      builtins.elem
      (resultOfAos "registry-synchronization-lifecycle")
      aosEvalService.value.dependencies.requires
    then throw "registry refresh failure must not suppress registry-independent host evaluation"
    else if
      !(builtins.elem
        (resultOfAos "registry-synchronization-lifecycle")
        aosEvalService.value.dependencies.after)
    then throw "the signed registry snapshot refresh must precede host evaluation"
    else if
      registrySyncCommand.executable.entry_point
      != "bin/apm"
      || registrySyncCommand.executable.arguments != ["update" "--system"]
    then throw "the registry refresh must update the system-scope snapshot"
    else if
      !(builtins.elem
        (resultOfAos "network-readiness")
        registrySyncService.value.dependencies.after)
    then throw "the registry refresh must wait for a routable managed interface"
    else if (registrySyncService.value.conditions.all or []) != []
    then throw "registry refresh must not depend on an ambient host-policy path"
    else if activationPreflightService.value.isolation.filesystem != "read-only-system"
    then throw "activation preflight must run with ProtectSystem=strict"
    else if
      activationPreflightCommand.executable.arguments
      != ["__ability-activation-preflight" "--manifest" "/run/aos/manifest.json"]
    then throw "activation preflight must consume the checked host manifest"
    else if imageBootCommitLifecycle.service != "image-boot-commit"
    then throw "the stock system must author typed image-transition finalization"
    else if
      aosEvalService.value.environment.variables.XDG_CACHE_HOME
      != "/var/cache/aos/nix-eval"
    then throw "aos-eval.service must direct Nix client caches to its writable cache directory"
    else if
      builtins.any
      (entry: containsStr "/run/aos-metadata" entry.source)
      aosEvalService.value.isolation.host_paths
    then throw "aos-eval.service must not bind an ambient metadata carrier"
    else if (aosEvalService.value.conditions.all or []) != []
    then throw "aos-eval.service must evaluate the image-default empty module when operator input is absent"
    else if !(builtins.elem "__eval-service" aosEvalCommand.executable.arguments)
    then throw "aos-eval.service must resolve retained manifest inputs through the package runtime"
    else if
      !(builtins.elem
        {
          _type = "aos-request-output-reference";
          request = "aos:aos-activate-lifecycle";
          output = "resource";
        }
        imageBootCommitDependencies.after)
    then throw "image boot success must wait for configuration activation"
    else if
      !(builtins.elem
        {
          _type = "aos-request-output-reference";
          request = "aos:aos-graph-compile-lifecycle";
          output = "resource";
        }
        imageBootCommitDependencies.requires)
    then throw "image boot assessment must wait for successful no-input or operator-input evaluation"
    else if
      (builtins.head imageBootCommitLifecycle.start).executable.entry_point
      != "libexec/aos-image-rollout-boot"
    then throw "image boot success must use the package-owned compiled finalizer"
    else if
      !(containsStr
        "readlink /sysroot/aos-toplevel"
        etcOverlayScript)
    then throw "the boot /etc lower must come from the image that actually booted"
    else if
      configSeedCommand.executable.entry_point
      != "bin/aos-boot-preparations"
      || configSeedCommand.executable.arguments != ["seed-configuration"]
    then throw "the initrd must restore committed configuration through the package-owned seeding service"
    else if !(builtins.elem pkgs.aos.packageRuntime system.config.aos.boot.initrd.packageRoots)
    then throw "the initrd configuration backend must carry the AOS materializer closure explicitly"
    else if
      !(builtins.elem
        (initrdOutput "aos-boot-preparations" "var" "resource")
        configSeedService.value.dependencies.requires)
      || !(builtins.elem
        (initrdOutput "aos-boot-preparations" "run-etc" "resource")
        configSeedService.value.dependencies.requires)
    then throw "initrd configuration restoration must wait for persistent state and its runtime mount"
    else if !(builtins.elem "__ability-activate" activationCommand.executable.arguments)
    then throw "aos-activate.service must invoke checked native activation"
    else if
      activationService.value.start_policy.restart_preventing_exit_statuses
      != [4]
    then throw "aos-activate.service must reserve failure status for indeterminate commits"
    else if
      builtins.any
      (name: builtins.hasAttr name system.config.boot.initrd.systemd.services)
      ["aos-metadata-fetch" "aos-metadata-authorize" "aos-metadata-network-seed" "aos-provisioning-eval"]
    then throw "metadata provisioning must execute only through the checked initrd ability stage"
    else if
      builtins.length initrdTrustAnchors
      != 1
    then throw "the initrd closure must contain the package-authored provisioning trust anchors"
    else if
      initrdAbilityImplementations."aos-metadata-provider:storage-provisioning-platform-detector".handlerDescriptor.entryPoint
      != "bin/aos-metadata-acquisition-provider"
    then throw "the initrd fixed point must route provisioning detection through the AOS metadata provider"
    else if
      initrdAbilityImplementations."aos-metadata-provider:storage-provisioning-input-authorizer".handlerDescriptor.entryPoint
      != "bin/aos-metadata-policy-provider"
    then throw "the initrd fixed point must route provisioning authorization through the AOS metadata provider"
    else if
      (initrdRequest "aos-boot-preparations" "bootstrap-network").links
      != [
        {
          kind = "ethernet";
          name = "dhcp";
          selector.kind = "ethernet";
          addressing = {
            dhcp = true;
            addresses = [];
            dns = [];
            link_local = "ipv4";
            ipv4_link_local_route = true;
          };
        }
      ]
    then throw "DHCP-less metadata acquisition requires an initrd IPv4 link-local source address"
    else if
      !(builtins.elem
        (initrdOutput "aos-boot-preparations" "initrd-filesystems" "resource")
        (initrdRequest "aos-boot-preparations" "mount-var-dependencies").required_by)
    then throw "initrd-fs.target must require the persistent /var substrate"
    else if (initrdRequest "aos-boot-preparations" "mount-var-dependencies").implicit_dependencies
    then throw "the initrd /var mount must not pull stage-2 default dependencies into switch-root"
    else if (initrdRequest "aos-boot-preparations" "nix-overlay-setup-dependencies").implicit_dependencies
    then throw "the initrd /nix overlay must not pull stage-2 default dependencies into switch-root"
    else if
      abilityRequests."cryptsetup:encrypted-swap".parameters.source
      != {
        _type = "aos-request-output-reference";
        request = "cryptsetup:encrypted-swap-format";
        output = "formatted-path";
      }
    then throw "encrypted swap must depend on the typed storage-format result"
    else "ok";

  # The edge release artifact is an authenticated capability
  # substrate, while its service and tuning defaults are selected by host.nix.
  edgeImage = mkSystem ../../systems/edge.nix;
  edgeHost = mkSystem [
    ../../systems/edge.nix
    {aos.roles.edge.enable = true;}
  ];
  edgeHostCustomized = mkSystem [
    ../../systems/edge.nix
    {
      aos.roles.edge.enable = true;
      aos.services.ssh.enable = false;
      aos.kernel.sysctl."vm.vfs_cache_pressure" = "50";
    }
  ];
  serviceResourceNamed = resources: serviceName:
    builtins.filter
    (resource:
      resource.kind
      == "aos.service.instance"
      && resource.value.service == serviceName)
    resources;
  edgeImageResources = builtins.attrValues edgeImage.config.aos.abilities.resolvedResources;
  edgeHostResources = builtins.attrValues edgeHost.config.aos.abilities.resolvedResources;
  edgeHostChronyServices = serviceResourceNamed edgeHostResources "chronyd";
  edgeHostSshServices = serviceResourceNamed edgeHostResources "sshd";
  edgeCustomizedResources =
    builtins.attrValues edgeHostCustomized.config.aos.abilities.resolvedResources;
  edgeImageHostBoundary =
    if edgeImage.config.aos.roles.edge.enable
    then throw "the production edge image must not preselect its runtime role"
    else if edgeImage.config.aos.services.chrony.enable
    then throw "the production edge image must not bake chrony runtime policy"
    else if edgeImage.config.aos.services.ssh.enable
    then throw "the production edge image must not bake SSH runtime policy"
    else if edgeImage.config.aos.security.level != null
    then throw "the production edge image must not bake a security-level policy"
    else if builtins.hasAttr "vm.vfs_cache_pressure" edgeImage.config.aos.kernel.sysctl
    then throw "the production edge image must not bake edge runtime sysctls"
    else if serviceResourceNamed edgeImageResources "chronyd" != []
    then throw "the production edge image unexpectedly selected the chronyd service resource"
    else if serviceResourceNamed edgeImageResources "sshd" != []
    then throw "the production edge image unexpectedly selected the sshd service resource"
    else if edgeImage.config.aos.filesystems.rootFsType != "erofs"
    then throw "the production edge image must carry an immutable EROFS root"
    else if !edgeImage.config.aos.filesystems.rootReadOnly
    then throw "the production edge image root must be read-only"
    else if !edgeImage.config.aos.security.verity.enable
    then throw "the production edge image must authenticate its root with dm-verity"
    else if edgeImage.config.aos.filesystems.rootDevice != "/dev/mapper/root"
    then throw "the production edge image must boot through the dm-verity mapper"
    else if !(builtins.elem "dm_verity" edgeImage.config.aos.boot.initrd.modules)
    then throw "the production edge image initrd must carry dm_verity"
    else builtins.seq edgeImage.config.system.build.toplevel.name "ok";
  edgeHostRole =
    if !edgeHost.config.aos.services.chrony.enable
    then throw "aos.roles.edge must enable chrony runtime policy"
    else if !edgeHost.config.aos.services.ssh.enable
    then throw "aos.roles.edge must enable SSH runtime policy"
    else if edgeHost.config.aos.security.level != "standard"
    then throw "aos.roles.edge must select the standard security posture"
    else if edgeHost.config.aos.kernel.sysctl."vm.swappiness" != "10"
    then throw "aos.roles.edge must select its low-memory swappiness policy"
    else if edgeHost.config.aos.kernel.sysctl."vm.vfs_cache_pressure" != "200"
    then throw "aos.roles.edge must select its low-memory cache-pressure policy"
    else if builtins.length edgeHostChronyServices != 1
    then throw "aos.roles.edge must select exactly one chronyd service resource"
    else if builtins.length edgeHostSshServices != 1
    then throw "aos.roles.edge must select exactly one sshd service resource"
    else if edgeHost.config.aos.filesystems.rootFsType != edgeImage.config.aos.filesystems.rootFsType
    then throw "aos.roles.edge must not alter the golden-image filesystem"
    else if edgeHost.config.aos.security.verity.enable != edgeImage.config.aos.security.verity.enable
    then throw "aos.roles.edge must not alter golden-image root authentication"
    else if edgeHostCustomized.config.aos.services.ssh.enable
    then throw "explicit host SSH policy must override the edge role default"
    else if serviceResourceNamed edgeCustomizedResources "sshd" != []
    then throw "disabling host SSH policy must remove the sshd service resource"
    else if edgeHostCustomized.config.aos.kernel.sysctl."vm.vfs_cache_pressure" != "50"
    then throw "explicit host sysctl policy must override the edge role default"
    else builtins.seq edgeHost.config.system.build.toplevel.name "ok";

  # The early projection declares only aos.provisioning. An unrelated runtime
  # definition can contain a throw and must remain unforced, while a storage
  # override from the same operator module is visible.
  provisioningProjection = lib.evalModules {
    modules = [
      ../../modules/base/provisioning.nix
      {
        aos.provisioning.storage.partitions.var.sizeMin = "8G";
        services.notPartOfEarlyProjection.enable =
          throw "restricted provisioning evaluation forced an unrelated runtime field";
      }
    ];
    pkgs = {};
    inherit lib;
  };
  provisioningProjectionIsClosed =
    if
      provisioningProjection.config.aos.provisioning.storage.partitions.var.sizeMin
      != "8G"
    then throw "restricted provisioning evaluation did not apply host storage"
    else if
      provisioningProjection.config.aos.provisioning.storage.partitions.swap.type
      != "swap"
    then throw "partial host storage overrides discarded default partition fields"
    else if
      provisioningProjection.config.aos.provisioning.storage.partitions.swap.format
      != "swap"
    then throw "partial host storage overrides discarded the default swap format"
    else "ok";
  provisioningProjectionJson =
    builtins.toJSON
    (builtins.mapAttrs
      (_: partition: {
        inherit
          (partition)
          device
          label
          type
          sizeMin
          sizeMax
          weight
          format
          uuid
          grow
          growFs
          priority
          ;
      })
      provisioningProjection.config.aos.provisioning.storage.partitions);
  provisioningProjectionHasNoModuleInternals =
    if builtins.match ".*_module.*" provisioningProjectionJson != null
    then throw "restricted provisioning JSON leaked module-engine internals"
    else "ok";

  hostSelectionProjection = lib.evalModules {
    modules = [../../modules/base/host-selection.nix];
    pkgs = {};
    inherit lib;
    operatorModules = [
      {
        aos.apm.desiredPackages = ["k3s-worker"];
        networking.notPartOfSelection =
          throw "host package selection forced unrelated runtime policy";
      }
    ];
  };
  hostSelectionProjectionIsClosed =
    if hostSelectionProjection.config.aos.apm.desiredPackages != ["k3s-worker"]
    then throw "closed host selection did not apply desired package names"
    else "ok";

  # --- aos.apm.registries (modules/base/apm-registries.nix) -----------------
  # A registry trust anchor produces the expected /etc contents, and
  # malformed trust keys fail evaluation.
  anchorKey = "example:Ed25519:QUJDREVGR0g=";
  anchorKeyRotated = "example:Ed25519:SUpLTE1OT1A=";
  anchorSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.registries.example = {
        url = "https://registry.example/aos";
        trustKeys = [anchorKey anchorKeyRotated];
        caches = [
          {
            url = "https://cache.example/aos";
            priority = 75;
          }
          {
            url = "file:///var/lib/aos-cache";
          }
        ];
      };
    }
  ];
  expectedRegistryToml = ''
    # /etc/apm/registries.d/example.toml
    # Generated by modules/base/apm-registries.nix - do not edit manually.
    [registry]
    name = "example"
    url = "https://registry.example/aos"
    channel = "stable"
    priority = 50
    enabled = true

    [[registry.caches]]
    url = "https://cache.example/aos"
    priority = 75
    [[registry.caches]]
    url = "file:///var/lib/aos-cache"
    priority = 100

    [registry.signing]
    required = true
    public_key = "${anchorKey}"
  '';
  expectedTrustedKeys = ''
    ${anchorKey}
    ${anchorKeyRotated}
  '';
  actualRegistryToml = anchorSystem.config.environment.etc."apm/registries.d/example.toml".text;
  actualTrustedKeys = anchorSystem.config.environment.etc."apm/trusted-keys.d/example.pub".text;
  apmRegistriesContent =
    if actualRegistryToml != expectedRegistryToml
    then throw "aos.apm.registries generated unexpected registries.d content:\n${actualRegistryToml}"
    else if actualTrustedKeys != expectedTrustedKeys
    then throw "aos.apm.registries generated unexpected trusted-keys.d content:\n${actualTrustedKeys}"
    # Force the anchored system's toplevel so its assertions and /etc
    # assembly evaluate end to end.
    else builtins.seq anchorSystem.config.system.build.toplevel.name "ok";

  # A trust key whose registry prefix doesn't match the attribute name
  # must fail the module assertion when the system is built.
  malformedAnchorSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.registries.example = {
        url = "https://registry.example/aos";
        trustKeys = ["other:Ed25519:QUJDRA=="];
      };
    }
  ];
  apmRegistriesRejectsMalformedKey = let
    forced = builtins.tryEval (malformedAnchorSystem.config.system.build.toplevel.outPath);
  in
    if forced.success
    then throw "aos.apm.registries must reject a trust key whose registry prefix differs from the attribute name"
    else "ok";

  # An empty trustKeys list is rejected by nonEmptyListOf at eval time.
  emptyAnchorSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.registries.example = {
        url = "https://registry.example/aos";
        trustKeys = [];
      };
    }
  ];
  apmRegistriesRejectsEmptyKeys = let
    forced = builtins.tryEval (emptyAnchorSystem.config.environment.etc."apm/trusted-keys.d/example.pub".text);
  in
    if forced.success
    then throw "aos.apm.registries must reject an empty trustKeys list"
    else "ok";

  containsStr = needle: haystack:
    builtins.stringLength (builtins.replaceStrings [needle] [""] haystack)
    != builtins.stringLength haystack;

  nsswitchNoMymachines =
    if containsStr "mymachines" system.config.environment.etc."nsswitch.conf".text
    then throw "modules/base/nsswitch.nix must not rely on nss-mymachines"
    else if !(containsStr "hosts: files myhostname resolve [!UNAVAIL=return] dns" system.config.environment.etc."nsswitch.conf".text)
    then throw "modules/base/nsswitch.nix generated an unexpected hosts lookup order"
    else "ok";

  # --- aos.apm.installAtBoot --------------------------------------------
  # Host-authored package intent bakes into the image /etc:
  # desired.toml plus registry config / trust anchors, as `environment.etc`.
  installAtBootSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.registries.example = {
        url = "https://registry.example/aos";
        trustKeys = [anchorKey];
      };
      aos.apm.installAtBoot = {
        enable = true;
        packages = ["web" "worker"];
        config.web.env.TOKEN = "<tag>|{x}";
      };
    }
  ];
  installAtBootEtc = installAtBootSystem.config.aos.apm.installAtBoot.etc;
  findEtcEntry = path:
    if installAtBootEtc ? ${path}
    then installAtBootEtc.${path}
    else throw "aos.apm.installAtBoot did not bake /etc/${path}";
  installAtBootDesired = findEtcEntry "aos/packages.d/desired.toml";
  installAtBootRegistry = findEtcEntry "apm/registries.d/example.toml";
  installAtBootTrustedKeys = findEtcEntry "apm/trusted-keys.d/example.pub";
  apmInstallAtBootEtc = let
    desiredText = installAtBootDesired.text;
    registryText = installAtBootRegistry.text;
    trustedKeysText = installAtBootTrustedKeys.text;
  in
    if installAtBootDesired.mode != "0600"
    then throw "aos.apm.installAtBoot desired.toml must be mode 0600"
    else if !(containsStr ''packages = ["web", "worker"]'' desiredText)
    then throw "aos.apm.installAtBoot desired.toml is missing the package list: ${desiredText}"
    else if !(containsStr "[config.web.env]" desiredText)
    then throw "aos.apm.installAtBoot desired.toml is missing the config table: ${desiredText}"
    else if !(containsStr ''TOKEN = "<tag>|{x}"'' desiredText)
    then throw "aos.apm.installAtBoot desired.toml is missing the config value: ${desiredText}"
    else if containsStr "[credentials" desiredText
    then throw "aos.apm.installAtBoot desired.toml must not carry credential declarations: ${desiredText}"
    else if !(containsStr ''name = "example"'' registryText)
    then throw "aos.apm.installAtBoot registry file is missing the registry name: ${registryText}"
    else if !(containsStr "example:Ed25519:QUJDREVGR0g=" trustedKeysText)
    then throw "aos.apm.installAtBoot trusted keys file is missing the trust anchor: ${trustedKeysText}"
    else builtins.seq installAtBootSystem.config.system.build.toplevel.name "ok";

  invalidInstallAtBootConfigSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.installAtBoot = {
        enable = true;
        config."bad/name".env.TOKEN = "abc";
      };
    }
  ];
  apmInstallAtBootRejectsInvalidConfigPackage = let
    forced = builtins.tryEval (invalidInstallAtBootConfigSystem.config.system.build.toplevel.outPath);
  in
    if forced.success
    then throw "aos.apm.installAtBoot.config must reject invalid package names"
    else "ok";

  invalidRegistryNameSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.registries."bad/name" = {
        url = "https://registry.example/aos";
        trustKeys = ["bad/name:Ed25519:QUJDRA=="];
      };
    }
  ];
  apmRegistriesRejectsInvalidName = let
    forced = builtins.tryEval (invalidRegistryNameSystem.config.system.build.toplevel.outPath);
  in
    if forced.success
    then throw "aos.apm.registries must reject registry names that are invalid APM path components"
    else "ok";

  firewallUsesTypedRuleset =
    if system.config.environment.etc ? "nftables.conf"
    then throw "the provider-neutral firewall must not publish a backend-specific global nftables.conf"
    else if !(abilityRequests ? "nftables:ruleset")
    then throw "the nftables package must contribute the host firewall through a typed ruleset request"
    else "ok";
  derivationLibForExecutionCompatibility = import ../derivations.nix {
    system = "x86_64-linux";
  };
  executionCompatibilityUsesBuildExecutionSystem = let
    compatible = builtins.tryEval (
      derivationLibForExecutionCompatibility.mkDerivation {
        pname = "execution-compatible-with-build-system";
        buildExecutionSystem = "aarch64-linux";
        meta.execute = {
          cpu = "aarch64";
          os = "linux";
        };
      }
    );
    schedulingSystemOnly = builtins.tryEval (
      derivationLibForExecutionCompatibility.mkDerivation {
        pname = "execution-compatible-only-with-scheduling-system";
        buildExecutionSystem = "aarch64-linux";
        meta.execute = {
          cpu = "x86_64";
          os = "linux";
        };
      }
    );
  in
    if !compatible.success
    then throw "meta.execute must be checked against buildExecutionSystem"
    else if schedulingSystemOnly.success
    then throw "meta.execute must not be checked against the Nix scheduling system"
    else "ok";

  bareMetalStorageSystem = mkSystem [
    ../../systems/server-verity.nix
    {
      aos.profiles.bareMetalZfs = {
        enable = true;
        espDevices = [
          "/dev/disk/by-partlabel/aos-esp-1"
          "/dev/disk/by-partlabel/aos-esp-2"
        ];
      };
    }
  ];
  bareMetalStorageProfile =
    if bareMetalStorageSystem.config.aos.boot.storage.backend != "zfs-zvol"
    then throw "bare-metal storage profile must select ZFS zvol image slots"
    else if builtins.length bareMetalStorageSystem.config.aos.boot.initrd.modulePackages != 1
    then throw "ZFS must be the only external early-boot module package"
    else if builtins.length bareMetalStorageSystem.config.aos.kernel.modulePackages != 1
    then throw "ZFS must be available in the runtime module tree"
    else if
      !(builtins.elem
        {
          _type = "aos-request-output-reference";
          request = "aos:esp-ready";
          output = "resource";
        }
        bareMetalStorageSystem.config.aos.abilities.requests."aos:image-boot-commit-dependencies".parameters.requires)
    then throw "image blessing must require authoritative booted-ESP discovery"
    else if bareMetalStorageSystem.config.system.build.installBundle == null
    then throw "ZFS-backed bare-metal systems must expose an installer bundle"
    else "ok";
in {
  # Use a raw derivation with AOS bash so we don't pull in host tools. The
  # builtins.toJSON calls still force the system config at instantiation time;
  # the builder covers rendered artifacts that require AOS command-line tools.
  rendered-system = builtins.derivation {
    name = "aos-eval-checks-0";
    system = lib.system;
    builder = "${pkgs.bash}/bin/bash";
    args = [
      "-c"
      ''
        set -euo pipefail

        jq=${pkgs.jq}/bin/jq
        systemd_analyze=${pkgs.systemd}/bin/systemd-analyze
        coreutils=${pkgs.coreutils}/bin
        echo "==> AOS Rendered-System Evaluation Checks"
        echo ""

        artifact_count=0
        while IFS=$'\t' read -r artifact_name artifact_path; do
          artifact_root=${baseLib}/artifact-roots/$artifact_name
          if [ ! -L "$artifact_root" ]; then
            echo "frozen config artifact lacks a base-lib closure root: $artifact_name" >&2
            exit 1
          fi
          if [ "$("$coreutils"/readlink "$artifact_root")" != "$artifact_path" ]; then
            echo "frozen config artifact root disagrees with its serialized path: $artifact_name" >&2
            exit 1
          fi
          if [ ! -e "$artifact_path" ]; then
            echo "frozen config artifact closure is not realized: $artifact_name" >&2
            exit 1
          fi
          artifact_count=$((artifact_count + 1))
        done < <("$jq" -r 'to_entries[] | [.key, .value] | @tsv' ${baseLib}/frozen-artifacts.json)
        if [ "$artifact_count" -eq 0 ]; then
          echo "base-lib did not retain any frozen config artifacts" >&2
          exit 1
        fi

        case "$("$coreutils"/cat ${system.config.environment.etc."os-release".source})" in
          *$'\nAOS_CONFIG_INPUT_ABI=2\n'*) ;;
          *) echo "os-release lacks config input ABI 2" >&2; exit 1 ;;
        esac
        test "$("$coreutils"/cat ${system.config.system.build.toplevel}/meta/config-input-abi)" = 2

        echo "config keys:    ${builtins.toJSON (builtins.attrNames system.config.aos)}"
        echo "config artifacts: $artifact_count frozen closure root(s) verified"
        echo "config input ABI: advertised in os-release and toplevel metadata (2)"
        echo "verity LUKS gate: exact (${verityDisablesGenericLuks})"
        echo "configuration pipeline: structural default (${structuralConfiguration}), closed early projection (${provisioningProjectionIsClosed}), pure JSON (${provisioningProjectionHasNoModuleInternals}), closed package selection (${hostSelectionProjectionIsClosed})"
        echo "activation overlay: changed job scripts and removed image artifacts (${activationImageOverride}), static image ownership (${activationStaticImageOwner}), structural replacements (${activationStructuralReplacement})"
        echo "lifecycle units: recurrent provisioning/tmpfiles/sysusers (${rfcLifecycleRecurrence})"
        echo "nsswitch:       explicit hosts/DNS, no nss-mymachines (${nsswitchNoMymachines})"
        echo "firewall:       package-owned typed ruleset (${firewallUsesTypedRuleset})"
        echo "derivations:    meta.execute uses build execution identity (${executionCompatibilityUsesBuildExecutionSystem})"
        echo "named outputs:  preserve ${namedOutputsPreservePackageMetadata}"

        # Force the build attributes to ensure they evaluate
        echo "toplevel:       ${system.config.system.build.toplevel.name}"
        echo "kernel:         ${system.config.system.build.kernel.name}"
        echo "initrd:         ${system.config.system.build.initrd.name}"
        echo "systemPkgs:     ${builtins.toString (builtins.length system.config.environment.systemPackages)}"

        echo ""
        echo "==> Rendered-system eval checks passed."
        echo "PASS" > $out
      ''
    ];
  };

  module-abi = mkPureCheck "module-abi" ''
    echo "base-lib ABI: follows source-backed image module overrides (${baseLibFollowsImageAbi})"
    echo "inline modules: rejected for image/base-lib outputs (${inlineImageModuleRejected})"
  '';

  runtime-roles = mkPureCheck "runtime-roles" ''
    echo "server SSH: waits for live host policy (${serverSshWaitsForLiveHostPolicy})"
    echo "edge boundary: image capability only (${edgeImageHostBoundary}), host-selectable runtime role (${edgeHostRole})"
  '';

  registry-policy = mkPureCheck "registry-policy" ''
    echo "apm registries: content (${apmRegistriesContent}), malformed key (${apmRegistriesRejectsMalformedKey}), empty keys (${apmRegistriesRejectsEmptyKeys})"
    echo "apm install boot: etc (${apmInstallAtBootEtc}), invalid config (${apmInstallAtBootRejectsInvalidConfigPackage}), invalid registry (${apmRegistriesRejectsInvalidName})"
  '';

  storage-profile = mkPureCheck "storage-profile" ''
    echo "bare metal: encrypted ZFS zvol slots and authoritative ESPs (${bareMetalStorageProfile})"
  '';
}
