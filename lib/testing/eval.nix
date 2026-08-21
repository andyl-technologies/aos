# lib/testing/eval.nix — Layer 1: Evaluation and rendered-artifact checks
#
# No VMs and no host tools. Instantiation forces the module graph to resolve;
# the derivation then runs AOS-built tools over evaluated artifacts that need
# command-line validation.
#
# Usage:
#   nix-build -A checks.eval
{
  pkgs,
  lib,
  system,
  mkSystem,
  packagesWithExpose,
}: let
  exposeRenderer = import ../../pkgs/build-support/_expose-renderer.nix {
    inherit lib pkgs;
  };
  baseLib = system.config.aos.config.evalAtBoot.baseLib;
  abiOverrideSystem = mkSystem [
    ../../systems/server.nix
    {aos.system.moduleAbi = 2;}
  ];
  serverRoleSystem = mkSystem [
    ../../systems/server.nix
    {aos.roles.server.enable = true;}
  ];
  baseLibFollowsImageAbi =
    if abiOverrideSystem.config.aos.config.evalAtBoot.baseLib.passthru.moduleAbi == 2
    then "2"
    else throw "the base library ABI must follow inline image module overrides";
  serverSshWaitsForLiveHostPolicy =
    if !(builtins.hasAttr "aos-ssh-ready" serverRoleSystem.config.systemd.services)
    then throw "server SSH must emit a host-policy readiness gate"
    else if
      !(builtins.elem
        "aos-ssh-ready.service"
        serverRoleSystem.config.systemd.services.sshd.after)
    then throw "server sshd must wait for the host-policy readiness gate"
    else if
      !(builtins.elem
        "aos-eval.service"
        serverRoleSystem.config.systemd.services.aos-ssh-ready.after)
    then throw "the SSH readiness gate must wait for host evaluation"
    else if
      !(containsStr
        "/run/aos/host-policy-live"
        serverRoleSystem.config.systemd.services.aos-ssh-ready.script)
    then throw "the SSH readiness gate must observe the post-swap policy marker"
    else if
      !(containsStr
        "/run/aos/host-policy-live"
        (builtins.readFile ../../modules/base/activate.sh.in))
    then throw "host activation must publish the SSH readiness marker"
    else if
      builtins.elem
      "aos-graph-compile.service"
      serverRoleSystem.config.systemd.services.sshd.after
    then throw "server sshd must not form a cycle with graph activation"
    else "post-swap marker";
  # The kernel-lockdown option was removed: SECURITY_LOCKDOWN_LSM selects
  # MODULE_SIG, whose default key generation breaks third-party
  # bit-reproducibility of the public base image. Fail loudly at eval time
  # if the option declaration ever reappears.
  noKernelLockdown =
    if system.options.aos.security.hardening ? kernelLockdown
    then throw "aos.security.hardening.kernelLockdown must not exist; kernel lockdown pulls in module signing and is not part of the reproducible public base"
    else "ok";
  verityDisablesGenericLuks = let
    occurrences = builtins.length (builtins.filter (parameter: parameter == "rd.luks=0") system.config.aos.boot.kernelParams);
  in
    if occurrences != 1
    then throw "the verity image must disable generic initrd LUKS discovery exactly once"
    else "ok";

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
      units = {};
      jobScripts = {};
      users = {};
      presets = {};
      storePaths = {};
    };
    baseline = {
      etc = {
        ${hostnamePath} = {
          kind = "text";
          text = "candidate unit";
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
      units = {
        ${hostnameUnit} = {action = "restart";};
        ${firewallUnit} = {action = "restart";};
      };
      jobScripts.${hostnameScript} = {
        text = "hostname aos";
        mode = "0755";
        name = "hostname";
      };
      users = [];
      presets = [];
      storePaths = [];
      ownership =
        emptyOwnership
        // {
          etc = builtins.mapAttrs (_: _: "@base") baseline.etc;
          units = builtins.mapAttrs (_: _: "@base") baseline.units;
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
        units =
          baseline.units
          // {
            ${hostnameUnit} = {action = "image";};
          };
      };
    candidate =
      baseline
      // {
        etc = builtins.removeAttrs baseline.etc [firewallPath firewallWant];
        units = builtins.removeAttrs baseline.units [firewallUnit];
        jobScripts.${hostnameScript} = {
          text = "hostname node-1";
          mode = "0755";
          name = "hostname";
        };
        ownership =
          baseline.ownership
          // {
            etc = builtins.removeAttrs baseline.ownership.etc [firewallPath firewallWant];
            units = builtins.removeAttrs baseline.ownership.units [firewallUnit];
          };
      };
    merged = mergeImageManifest {inherit imageManifest baseline candidate;};
  in
    if merged.etc.${hostnamePath}.text != "candidate unit"
    then throw "a changed generated job script must select its candidate unit body"
    else if merged.units.${hostnameUnit}.action != "restart"
    then throw "a changed generated job script must select its candidate unit action"
    else if merged.ownership.etc.${hostnamePath} != "@host"
    then throw "a changed generated job script must make its candidate unit host-owned"
    else if merged.ownership.units.${hostnameUnit} != "@host"
    then throw "a changed generated job script must make its unit action host-owned"
    else if merged.removedEtc != [firewallWant firewallPath]
    then throw "explicitly removed image artifacts must become deterministic overlay removals"
    else if builtins.hasAttr firewallPath merged.etc || builtins.hasAttr firewallUnit merged.units
    then throw "explicitly removed image units must not survive manifest merging"
    else "ok";

  activationStructuralReplacement = let
    ownershipFor = etc: {
      etc = builtins.mapAttrs (_: _: "@base") etc;
      units = {};
      jobScripts = {};
      users = {};
      presets = {};
      storePaths = {};
    };
    manifestWithEtc = etc: {
      inherit etc;
      units = {};
      jobScripts = {};
      users = [];
      presets = [];
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
    (assertRecurringLifecycleUnit
      "aos-repart.service"
      system.config.boot.initrd.systemd.services.aos-repart)
    (builtins.seq
      (assertOptionalRecurringLifecycleUnit "systemd-tmpfiles-setup")
      (builtins.seq
        (assertOptionalRecurringLifecycleUnit "systemd-tmpfiles-setup-dev")
        (assertOptionalRecurringLifecycleUnit "systemd-sysusers")));

  # Provisioning and configuration are structural, not optional paths. Their
  # former enable switches must stay deleted and
  # the stock system must always emit every stage.
  structuralConfiguration =
    if system.options.aos.config.evalAtBoot ? enable
    then throw "aos.config.evalAtBoot.enable must not exist"
    else if system.options.aos.provisioning.metadataAgent ? enable
    then throw "aos.provisioning.metadataAgent.enable must not exist"
    else if system.options.aos.provisioning ? repart
    then throw "aos.provisioning.repart must not exist"
    else if system.options.aos.config.unitGraph ? enable
    then throw "aos.config.unitGraph.enable must not exist"
    else if !(builtins.hasAttr "aos-eval" system.config.systemd.services)
    then throw "the stock system must emit aos-eval.service"
    else if !(builtins.hasAttr "aos-registry-sync" system.config.systemd.services)
    then throw "the stock system must refresh signed registry metadata before host evaluation"
    else if
      !(builtins.elem
        "aos-registry-sync.service"
        system.config.systemd.services.aos-eval.wants)
    then throw "host evaluation must request the signed registry snapshot refresh"
    else if
      builtins.elem
      "aos-registry-sync.service"
      system.config.systemd.services.aos-eval.requires
    then throw "registry refresh failure must not suppress registry-independent host evaluation"
    else if
      !(builtins.elem
        "aos-eval.service"
        system.config.systemd.services.aos-registry-sync.before)
    then throw "the signed registry snapshot refresh must precede host evaluation"
    else if
      !(containsStr
        "${pkgs.aos}/bin/apm update --system"
        system.config.systemd.services.aos-registry-sync.script)
    then throw "the registry refresh must update the system-scope snapshot"
    else if
      !(containsStr
        "${pkgs.systemd}/lib/systemd/systemd-networkd-wait-online --any"
        system.config.systemd.services.aos-registry-sync.serviceConfig.ExecStartPre)
    then throw "the registry refresh must wait for a routable managed interface"
    else if
      system.config.systemd.services.aos-registry-sync.unitConfig.ConditionPathExists
      != system.config.aos.config.evalAtBoot.hostNix
    then throw "registry refresh must run only when operator host policy is present"
    else if !(builtins.hasAttr "aos-graph-compile" system.config.systemd.services)
    then throw "the stock system must emit aos-graph-compile.service"
    else if !(builtins.hasAttr "aos-activate" system.config.systemd.services)
    then throw "the stock system must emit aos-activate.service"
    else if !(builtins.hasAttr "aos-credential-recovery" system.config.systemd.services)
    then throw "the stock system must recover interrupted credential publication"
    else if
      !(builtins.hasAttr
        "aos-credential-recovery"
        system.config.boot.initrd.systemd.services)
    then throw "the initrd must recover interrupted credential publication before restoring /etc"
    else if
      !(builtins.elem
        "aos-credential-recovery.service"
        system.config.systemd.services.aos-eval.requires)
    then throw "host evaluation must require credential transaction recovery"
    else if
      !(builtins.elem
        "aos-credential-recovery.service"
        system.config.boot.initrd.systemd.services."aos-config-seed".requires)
    then throw "the initrd config lower must wait for credential transaction recovery"
    else if
      builtins.elem
      "aos-seed-profiles.service"
      system.config.systemd.services.aos-firstboot-reeval.requires
    then throw "stage-2 re-evaluation must not require a vanished initrd unit"
    else if
      !(builtins.elem
        "local-fs.target"
        system.config.systemd.services.aos-firstboot-reeval.requires)
    then throw "stage-2 re-evaluation must require the durable local filesystem substrate"
    else if
      !(containsStr
        "AOS_ROOT=/sysroot"
        system.config.boot.initrd.systemd.services."aos-credential-recovery".script)
    then throw "initrd credential recovery must rebase transaction paths beneath /sysroot"
    else if system.config.systemd.services."aos-pkg-install@".serviceConfig.ProtectSystem != "strict"
    then throw "package config rendering must run with ProtectSystem=strict"
    else if
      system.config.systemd.services."aos-pkg-install@".serviceConfig.ReadWritePaths
      != ["/run/aos"]
    then throw "package config rendering must write only beneath /run/aos"
    else if system.config.systemd.services.aos-graph-compile.serviceConfig.ProtectSystem != "strict"
    then throw "the graph compiler must run with ProtectSystem=strict"
    else if
      system.config.systemd.services.aos-graph-compile.serviceConfig.ReadWritePaths
      != ["/run/aos" "/run/systemd/system"]
    then throw "the graph compiler must write only its transaction and runtime unit roots"
    else if !system.config.systemd.services.aos-graph-compile.serviceConfig.NoNewPrivileges
    then throw "the graph compiler must not gain privileges"
    else if !(builtins.hasAttr "aos-image-boot-commit" system.config.systemd.services)
    then throw "the stock system must commit or demote pending image transitions after configuration rebind"
    else if system.config.systemd.services.aos-eval.serviceConfig ? SuccessExitStatus
    then throw "aos-eval failures must remain visible as failed units"
    else if
      system.config.systemd.services.aos-eval.environment.XDG_CACHE_HOME
      != "/var/cache/aos/nix-eval"
    then throw "aos-eval.service must direct Nix client caches to its writable cache directory"
    else if
      !(builtins.elem
        "@system-service"
        system.config.systemd.services.aos-eval.serviceConfig.SystemCallFilter)
    then throw "aos-eval.service must have an allowlisted system-call baseline"
    else if
      !(builtins.elem
        "-${system.config.aos.config.evalAtBoot.hostNix}"
        system.config.systemd.services.aos-eval.serviceConfig.ReadOnlyPaths)
    then throw "aos-eval.service must bind the delivered host.nix read-only"
    else if system.config.systemd.services.aos-eval.unitConfig ? ConditionPathExists
    then throw "aos-eval.service must evaluate the image-default empty module when operator input is absent"
    else if
      !(containsStr
        "image_default_arg=\"--image-default-host\""
        system.config.systemd.services.aos-eval.script)
    then throw "aos-eval.service must enter the authenticated no-input fallback arm"
    else if
      !(builtins.elem
        "aos-activate.service"
        system.config.systemd.services.aos-image-boot-commit.after)
    then throw "image boot success must wait for configuration activation"
    else if
      !(builtins.elem
        "aos-graph-compile.service"
        system.config.systemd.services.aos-image-boot-commit.requires)
    then throw "image boot assessment must wait for successful no-input or operator-input evaluation"
    else if
      !(containsStr
        "gen-$current/manifest.json"
        system.config.systemd.services.aos-image-boot-commit.script)
    then throw "image boot success must require a durable committed configuration manifest"
    else if
      !(containsStr
        "${system.config.aos.config.artifacts.esp-sync}/bin/aos-sync-esps"
        system.config.systemd.services.aos-image-boot-commit.script)
    then throw "image boot success must invoke ESP synchronization by its immutable store path"
    else if
      !(builtins.elem
        (toString system.config.aos.config.evalAtBoot.baseLib)
        system.config.systemd.services.aos-eval.serviceConfig.ReadOnlyPaths)
    then throw "aos-eval.service must bind the immutable base library read-only"
    else if
      !(containsStr
        "readlink /sysroot/aos-toplevel"
        system.config.boot.initrd.systemd.services."etc-overlay-setup".script)
    then throw "the boot /etc lower must come from the image that actually booted"
    else if
      !(containsStr
        ".apm-unwrapped __materialize"
        system.config.boot.initrd.systemd.services."aos-config-seed".script)
    then throw "the initrd must restore the committed non-base configuration lower before mounting /etc"
    else if !(builtins.elem pkgs.aos system.config.aos.boot.initrd.extraPackages)
    then throw "the initrd configuration backend must carry the AOS materializer closure explicitly"
    else if
      !(containsStr
        ''generation="/sysroot/var/lib/profiles/system/gen-$AOS_PROFILE_GEN"''
        system.config.boot.initrd.systemd.services."aos-config-seed".script)
    then throw "initrd configuration restoration must select the current retained generation"
    else if
      !(containsStr
        ''manifest="$generation/manifest.json"''
        system.config.boot.initrd.systemd.services."aos-config-seed".script)
    then throw "initrd configuration restoration must read the selected generation manifest"
    else if
      !(containsStr
        ''"$generation/config-lower/etc.erofs"''
        system.config.boot.initrd.systemd.services."aos-config-seed".script)
    then throw "initrd configuration restoration must mount the selected generation lower"
    else if
      !(builtins.elem
        "aos-activate.service"
        system.config.systemd.targets.aos-config.requires)
    then throw "aos-config.target must pull in the atomic activation commit"
    else if
      !(builtins.elem
        "aos-activate.service"
        system.config.systemd.targets.aos-config.after)
    then throw "aos-config.target must wait for the atomic activation commit"
    else if
      !(builtins.elem
        "aos-activate.service"
        system.config.systemd.services.aos-preset.after)
    then throw "package presets must run after host configuration activation"
    else if
      !(containsStr
        "__activate-config"
        system.config.systemd.services.aos-activate.script)
    then throw "aos-activate.service must invoke the configuration-generation commit"
    else if
      system.config.systemd.services.aos-activate.serviceConfig.RestartPreventExitStatus
      != "4"
    then throw "aos-activate.service must reserve failure status for indeterminate commits"
    else if
      !(containsStr
        ''if [ "$rc" -eq 6 ]; then''
        system.config.systemd.services.aos-activate.script)
    then throw "aos-activate.service must settle after a committed degraded transaction"
    else if !(builtins.hasAttr "aos-metadata-fetch" system.config.boot.initrd.systemd.services)
    then throw "the stock system must emit aos-metadata-fetch.service"
    else if !(builtins.hasAttr "aos-metadata-authorize" system.config.boot.initrd.systemd.services)
    then throw "the stock system must emit aos-metadata-authorize.service"
    else if !(builtins.hasAttr "aos-metadata-network-seed" system.config.boot.initrd.systemd.services)
    then throw "the stock system must emit aos-metadata-network-seed.service"
    else if !(builtins.hasAttr "aos-provisioning-eval" system.config.boot.initrd.systemd.services)
    then throw "the stock system must emit aos-provisioning-eval.service"
    else if !(builtins.hasAttr "aos-repart" system.config.boot.initrd.systemd.services)
    then throw "the stock system must emit aos-repart.service"
    else if !(builtins.hasAttr "aos-provisioning-persist" system.config.systemd.services)
    then throw "the stock system must persist provisioning audit evidence"
    else if !(builtins.hasAttr "aos-host-config-restore" system.config.systemd.services)
    then throw "the stock system must restore its last fully evaluated host input"
    else if !(builtins.hasAttr "aos-host-config-cache" system.config.systemd.services)
    then throw "the stock system must cache fully evaluated host input"
    else if
      system.config.boot.initrd.systemd.services."aos-metadata-fetch".unitConfig
      ? ConditionPathExists
    then throw "metadata acquisition must run on provisioned boots"
    else if
      system.config.boot.initrd.systemd.services."aos-provisioning-eval".unitConfig
      ? ConditionPathExists
    then throw "the restricted storage projection must remain available as a post-commit advisory check"
    else if
      !(builtins.elem
        "mount-var.service"
        system.config.boot.initrd.systemd.services."aos-metadata-network-seed".requires)
    then throw "the static metadata network seed must wait for the persistent /var mount"
    else if
      !(builtins.elem
        "aos-metadata-fetch.service"
        system.config.boot.initrd.systemd.services."aos-metadata-network-seed".after)
    then throw "the static metadata network seed must run after acquisition"
    else if
      !(builtins.elem
        "etc-overlay-setup.service"
        system.config.boot.initrd.systemd.services."aos-metadata-network-seed".before)
    then throw "the static metadata network seed must precede /etc overlay assembly"
    else if
      !(containsStr
        "/sysroot/var/etc/systemd/network/10-aos-seed.network"
        system.config.boot.initrd.systemd.services."aos-metadata-network-seed".script)
    then throw "the static metadata network seed must be installed into the persistent gen-0 lower"
    else if
      system.config.boot.initrd.systemd.network."80-dhcp".networkConfig.LinkLocalAddressing
      != "ipv4"
    then throw "DHCP-less metadata acquisition requires an initrd IPv4 link-local source address"
    else if !system.config.boot.initrd.systemd.network."80-dhcp".networkConfig.IPv4LLRoute
    then throw "DHCP-less metadata acquisition requires an initrd route to link-local IMDS"
    else if
      !(builtins.elem
        "aos-host-config-restore.service"
        system.config.systemd.services.aos-eval.requires)
    then throw "aos-eval.service must restore the last known-good input before full evaluation"
    else if
      !(builtins.elem
        "aos-eval.service"
        system.config.systemd.services."aos-host-config-cache".after)
    then throw "host input may only be cached after successful full evaluation"
    else if
      !(containsStr
        "pending provisioning marker found; refusing automatic replay"
        system.config.boot.initrd.systemd.services.aos-repart.script)
    then throw "aos-repart.service must fail closed on a pending marker"
    else if
      !(containsStr
        "--dry-run=yes"
        system.config.boot.initrd.systemd.services.aos-repart.script)
    then throw "committed storage must be compared without mutation"
    else if
      !(containsStr
        "storage-coherence"
        system.config.boot.initrd.systemd.services.aos-repart.script)
    then throw "committed storage comparison must publish an observable result"
    else if
      !(containsStr
        (builtins.toString pkgs.dosfstools)
        system.config.boot.initrd.systemd.services.aos-repart.environment.PATH)
    then throw "every admitted vfat format must have its AOS-built initrd tool"
    else if
      !(builtins.elem
        "initrd-root-fs.target"
        system.config.boot.initrd.systemd.services.aos-metadata-authorize.requiredBy)
    then throw "initrd-root-fs.target must require provisioning authorization"
    else if
      !(builtins.elem
        "initrd-root-fs.target"
        system.config.boot.initrd.systemd.services.aos-repart.requiredBy)
    then throw "initrd-root-fs.target must require repartitioning"
    else if
      !(builtins.elem
        "initrd-fs.target"
        system.config.boot.initrd.systemd.services."mount-var".requiredBy)
    then throw "initrd-fs.target must require the persistent /var substrate"
    else if
      !(builtins.elem
        "aos-provisioning-eval.service"
        system.config.boot.initrd.systemd.services.aos-repart.requires)
    then throw "aos-repart.service must require restricted provisioning evaluation"
    else if
      !(builtins.elem
        "aos-provisioning-eval.service"
        system.config.boot.initrd.systemd.services.aos-repart.after)
    then throw "aos-repart.service must run after restricted provisioning evaluation"
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
  edgeImageHostBoundary =
    if !(edgeImage.options.aos.roles.edge ? enable)
    then throw "the base library must expose aos.roles.edge.enable to host.nix"
    else if edgeImage.options.aos.profiles ? edge
    then throw "the image-coupled aos.profiles.edge compatibility option must not remain"
    else if edgeImage.config.aos.roles.edge.enable
    then throw "the production edge image must not preselect its runtime role"
    else if edgeImage.config.aos.services.chrony.enable
    then throw "the production edge image must not bake chrony runtime policy"
    else if edgeImage.config.aos.services.ssh.enable
    then throw "the production edge image must not bake SSH runtime policy"
    else if edgeImage.config.aos.security.level != null
    then throw "the production edge image must not bake a security-level policy"
    else if builtins.hasAttr "vm.vfs_cache_pressure" edgeImage.config.aos.kernel.sysctl
    then throw "the production edge image must not bake edge runtime sysctls"
    else if builtins.hasAttr "chronyd" edgeImage.config.systemd.services
    then throw "the production edge image unexpectedly rendered chronyd.service"
    else if builtins.hasAttr "sshd" edgeImage.config.systemd.services
    then throw "the production edge image unexpectedly rendered sshd.service"
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
    else if !(builtins.hasAttr "chronyd" edgeHost.config.systemd.services)
    then throw "aos.roles.edge must render chronyd.service"
    else if !(builtins.hasAttr "sshd" edgeHost.config.systemd.services)
    then throw "aos.roles.edge must render sshd.service"
    else if edgeHost.config.aos.filesystems.rootFsType != edgeImage.config.aos.filesystems.rootFsType
    then throw "aos.roles.edge must not alter the golden-image filesystem"
    else if edgeHost.config.aos.security.verity.enable != edgeImage.config.aos.security.verity.enable
    then throw "aos.roles.edge must not alter golden-image root authentication"
    else if edgeHostCustomized.config.aos.services.ssh.enable
    then throw "explicit host SSH policy must override the edge role default"
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
    else if !(containsStr "hosts:          files myhostname resolve [!UNAVAIL=return] dns" system.config.environment.etc."nsswitch.conf".text)
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
        credentials.web.join-token = {
          source = "/etc/credstore.encrypted/web/join-token";
          ref = "desired-toml";
        };
        systemCredentials.worker.join-token = "bootstrap-token";
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
    else if containsStr "[credentials.web]" desiredText
    then throw "aos.apm.installAtBoot desired.toml must not serialize opaque references as values: ${desiredText}"
    else if !(containsStr "[credentials.worker.join-token]" desiredText)
    then throw "aos.apm.installAtBoot desired.toml is missing the system credential table: ${desiredText}"
    else if !(containsStr ''system-credential = "bootstrap-token"'' desiredText)
    then throw "aos.apm.installAtBoot desired.toml is missing the system credential reference: ${desiredText}"
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

  invalidInstallAtBootCredentialSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.installAtBoot = {
        enable = true;
        credentials.web."bad/name" = {
          source = "/etc/credstore/bad";
          ref = "desired-toml";
        };
      };
    }
  ];
  apmInstallAtBootRejectsInvalidCredentialName = let
    forced = builtins.tryEval (invalidInstallAtBootCredentialSystem.config.system.build.toplevel.outPath);
  in
    if forced.success
    then throw "aos.apm.installAtBoot.credentials must reject invalid credential names"
    else "ok";

  plaintextInstallAtBootCredentialSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.installAtBoot.credentials.web.join-token = {
        ref = "desired-toml";
        value = "must-not-enter-the-value-graph";
      };
    }
  ];
  apmInstallAtBootRejectsPlaintextCredential = let
    forced = builtins.tryEval (plaintextInstallAtBootCredentialSystem.config.system.build.toplevel.outPath);
  in
    if forced.success
    then throw "aos.apm.installAtBoot.credentials secretRef must reject plaintext value fields"
    else "ok";

  invalidInstallAtBootSystemCredentialSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.installAtBoot = {
        enable = true;
        systemCredentials.web.join-token = "bad/name";
      };
    }
  ];
  apmInstallAtBootRejectsInvalidSystemCredentialName = let
    forced = builtins.tryEval (invalidInstallAtBootSystemCredentialSystem.config.system.build.toplevel.outPath);
  in
    if forced.success
    then throw "aos.apm.installAtBoot.systemCredentials must reject invalid system credential names"
    else "ok";

  conflictingInstallAtBootCredentialSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.apm.installAtBoot = {
        enable = true;
        credentials.web.join-token = {
          source = "/etc/credstore.encrypted/web/join-token";
          ref = "desired-toml";
        };
        systemCredentials.web.join-token = "bootstrap-token";
      };
    }
  ];
  apmInstallAtBootRejectsCredentialConflicts = let
    forced = builtins.tryEval (conflictingInstallAtBootCredentialSystem.config.system.build.toplevel.outPath);
  in
    if forced.success
    then throw "aos.apm.installAtBoot must reject credentials/systemCredentials conflicts"
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

  firewallNoNftablesDropin =
    if containsStr "nftables.d" system.config.environment.etc."nftables.conf".text
    then throw "modules/security/firewall.nix must not include /etc/nftables.d drop-ins"
    else "ok";
  scanDirStorageRejected = let
    forced = builtins.tryEval (
      exposeRenderer.assertNoGlobalScanDirStorage "bad-package" [
        {
          path = "/etc/sysctl.d/70-bad-package.conf";
          target = "/nix/store/bad-package-sysctl.conf";
          overwrite = true;
        }
      ]
    );
  in
    if forced.success
    then throw "expose renderer must reject storage links under global scan dirs"
    else "ok";

  exposedPackageNames = builtins.attrNames packagesWithExpose;
  exposedPackagePathsJson = builtins.toJSON (
    builtins.map (name: packagesWithExpose.${name}.expose.outPath) exposedPackageNames
  );
  packageExposeSecurityGateEntries = builtins.toJSON (
    builtins.map (name: {
      inherit name;
      expose = builtins.toString packagesWithExpose.${name}.expose;
    })
    exposedPackageNames
  );
  exposeEnumeration =
    if !(builtins.elem "expose-smoke" exposedPackageNames)
    then throw "packagesWithExpose must include pkgs.expose-smoke"
    else if !(builtins.elem "test-http-server" exposedPackageNames)
    then throw "packagesWithExpose must include pkgs.test-http-server"
    else exposedPackagePathsJson;

  packagePolicySystem = mkSystem [
    ../../systems/server.nix
    {
      aos.packages.expose-smoke = {
        package = pkgs.expose-smoke;
        bundle = true;
        preset = false;
      };
      aos.packages.test-http-server = {
        package = pkgs.test-http-server;
        bundle = true;
        preset = true;
      };
    }
  ];
  packagePolicySystemPackageStrings =
    builtins.map builtins.toString packagePolicySystem.config.environment.systemPackages;
  packagePolicyModule =
    if !(builtins.elem (builtins.toString pkgs.test-http-server) packagePolicySystemPackageStrings)
    then throw "aos.packages must add bundled package payloads to environment.systemPackages"
    else if !(builtins.elem (builtins.toString pkgs.test-http-server.expose) packagePolicySystemPackageStrings)
    then throw "aos.packages must add bundled expose artifacts to environment.systemPackages"
    else if !(builtins.elem (builtins.toString pkgs.expose-smoke) packagePolicySystemPackageStrings)
    then throw "aos.packages must add preset=false bundled package payloads to environment.systemPackages"
    else if !(builtins.elem (builtins.toString pkgs.expose-smoke.expose) packagePolicySystemPackageStrings)
    then throw "aos.packages must add preset=false bundled expose artifacts to environment.systemPackages"
    # k3s operator tools were intentionally dropped from the base system PATH
    # when the image was slimmed (server profile no longer adds
    # `k3sCommon.runtimePath` to environment.systemPackages); units reference
    # k3s by absolute store path, and the role payload ships the CLI when its
    # package is bundled. The old "must keep k3s operator tools on PATH"
    # assertion contradicted that decision and is gone.
    else if !(builtins.elem "enable aos-pkg-test-http-server.target" packagePolicySystem.config.systemd.systemPresetRules)
    then throw "aos.packages must emit image preset enablement for preset=true packages"
    else if builtins.elem "enable aos-pkg-expose-smoke.target" packagePolicySystem.config.systemd.systemPresetRules
    then throw "aos.packages must not emit image preset enablement for preset=false packages"
    else if
      !(builtins.elem
        "aos-seed-baked-packages.service"
        packagePolicySystem.config.systemd.services.aos-eval.requires)
    then throw "host evaluation must wait for the bundled package profile seed"
    else if
      !(builtins.elem
        "aos-seed-baked-packages.service"
        packagePolicySystem.config.systemd.services.aos-eval.after)
    then throw "host evaluation must order after the bundled package profile seed"
    else builtins.seq packagePolicySystem.config.system.build.aosPackageProfileSeed.name "ok";

  packagePolicyBadPresetSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.packages.expose-smoke = {
        package = pkgs.expose-smoke;
        preset = true;
      };
    }
  ];
  packagePolicyRejectsPresetWithoutBundle = let
    forced = builtins.tryEval (packagePolicyBadPresetSystem.config.system.build.toplevel.outPath);
  in
    if forced.success
    then throw "aos.packages must reject preset=true when bundle=true is not set"
    else "ok";

  packagePolicyBadTargetSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.packages.wrong-name = {
        package = pkgs.test-http-server;
        bundle = true;
      };
    }
  ];
  packagePolicyRejectsWrongTarget = let
    forced = builtins.tryEval (packagePolicyBadTargetSystem.config.system.build.toplevel.outPath);
  in
    if forced.success
    then throw "aos.packages must reject policy names that do not match the package target"
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
    else if !(builtins.elem "aos-mount-esp.service" bareMetalStorageSystem.config.systemd.services.aos-image-boot-commit.requires)
    then throw "image blessing must require authoritative booted-ESP discovery"
    else if bareMetalStorageSystem.config.system.build.installBundle == null
    then throw "ZFS-backed bare-metal systems must expose an installer bundle"
    else "ok";
in
  # Use a raw derivation with AOS bash so we don't pull in host tools. The
  # builtins.toJSON calls still force the system config at instantiation time;
  # the builder covers rendered artifacts that require AOS command-line tools.
  builtins.derivation {
    name = "aos-eval-checks-0";
    system = lib.system;
    builder = "${pkgs.bash}/bin/bash";
    inherit packageExposeSecurityGateEntries;
    passAsFile = ["packageExposeSecurityGateEntries"];
    args = [
      "-c"
      ''
        set -euo pipefail

        jq=${pkgs.jq}/bin/jq
        systemd_analyze=${pkgs.systemd}/bin/systemd-analyze
        coreutils=${pkgs.coreutils}/bin
        security_threshold=55
        security_units=0
        security_skipped=0
        security_skipped_names=
        security_failed=0

        is_allowed_unconfined_package() {
          case "$1" in
            aos-test-agent|k3s-combined|k3s-control-plane|k3s-worker)
              return 0
              ;;
            *)
              return 1
              ;;
          esac
        }

        is_side_effect_unit() {
          package_name=$1
          unit_name=$2
          case "$unit_name" in
            aos-pkg-"$package_name"-host-paths.service|aos-pkg-"$package_name"-modules.service|aos-pkg-"$package_name"-sysctl.service|aos-pkg-"$package_name"-firewall.service|aos-pkg-"$package_name"-netns.service|aos-pkg-"$package_name"-ebpf.service)
              return 0
              ;;
            *)
              return 1
              ;;
          esac
        }

        check_package_security() {
          entry=$1
          package_name=$(printf '%s\n' "$entry" | "$jq" -r '.name')
          expose_path=$(printf '%s\n' "$entry" | "$jq" -r '.expose')
          manifest="$expose_path/manifest.json"
          confinement_class=$("$jq" -r '.permissions.confinement.class // "sandboxed"' "$manifest")
          if [ "$confinement_class" = unconfined ]; then
            if ! is_allowed_unconfined_package "$package_name"; then
              echo "systemd security gate found unexpected unconfined package: $package_name" >&2
              security_failed=1
              return 0
            fi
            security_skipped=$((security_skipped + 1))
            security_skipped_names="$security_skipped_names''${security_skipped_names:+,}$package_name"
            return 0
          fi

          tmp=$("$coreutils"/mktemp -d)
          "$coreutils"/mkdir -p "$tmp/etc/systemd/system"
          "$coreutils"/cp -a "$expose_path/units/." "$tmp/etc/systemd/system/"

          shopt -s nullglob
          for service_path in "$expose_path"/units/*.service; do
            unit_name=''${service_path##*/}
            if is_side_effect_unit "$package_name" "$unit_name"; then
              continue
            fi
            security_units=$((security_units + 1))
            report="$tmp/$unit_name.security"
            if ! "$systemd_analyze" security --offline=yes --threshold="$security_threshold" --root="$tmp" "$unit_name" >"$report" 2>&1; then
              echo "systemd security gate failed for $package_name:$unit_name" >&2
              "$coreutils"/cat "$report" >&2
              security_failed=1
            fi
          done
          shopt -u nullglob

          "$coreutils"/chmod -R u+w "$tmp" 2>/dev/null || true
          "$coreutils"/rm -rf "$tmp" 2>/dev/null || true
        }

        while IFS= read -r entry; do
          check_package_security "$entry"
        done < <("$jq" -c '.[]' "$packageExposeSecurityGateEntriesPath")

        if [ "$security_units" -eq 0 ]; then
          echo "systemd security gate did not check any workload services" >&2
          exit 1
        fi

        if [ "$security_failed" -ne 0 ]; then
          exit 1
        fi

        echo "==> AOS Evaluation Checks"
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

        echo "config keys:    ${builtins.toJSON (builtins.attrNames system.config.aos)}"
        echo "config artifacts: $artifact_count frozen closure root(s) verified"
        echo "base-lib ABI:    follows image module overrides (${baseLibFollowsImageAbi})"
        echo "kernelLockdown: removed (${noKernelLockdown})"
        echo "verity LUKS gate: exact (${verityDisablesGenericLuks})"
        echo "configuration pipeline: structural default (${structuralConfiguration}), closed early projection (${provisioningProjectionIsClosed}), pure JSON (${provisioningProjectionHasNoModuleInternals}), closed package selection (${hostSelectionProjectionIsClosed})"
        echo "server SSH:      waits for live host policy (${serverSshWaitsForLiveHostPolicy})"
        echo "activation overlay: changed job scripts and removed image artifacts (${activationImageOverride}), structural replacements (${activationStructuralReplacement})"
        echo "lifecycle units: recurrent provisioning/tmpfiles/sysusers (${rfcLifecycleRecurrence})"
        echo "edge boundary:   image capability only (${edgeImageHostBoundary}), host-selectable runtime role (${edgeHostRole})"
        echo "apm registries: content (${apmRegistriesContent}), malformed key (${apmRegistriesRejectsMalformedKey}), empty keys (${apmRegistriesRejectsEmptyKeys})"
        echo "apm install boot: etc (${apmInstallAtBootEtc}), invalid config (${apmInstallAtBootRejectsInvalidConfigPackage}), invalid credential (${apmInstallAtBootRejectsInvalidCredentialName}), plaintext credential (${apmInstallAtBootRejectsPlaintextCredential}), invalid system credential (${apmInstallAtBootRejectsInvalidSystemCredentialName}), credential conflict (${apmInstallAtBootRejectsCredentialConflicts}), invalid registry (${apmRegistriesRejectsInvalidName})"
        echo "nsswitch:       explicit hosts/DNS, no nss-mymachines (${nsswitchNoMymachines})"
        echo "firewall:       no package drop-in include (${firewallNoNftablesDropin}), scan-dir storage rejected (${scanDirStorageRejected})"
        echo "package expose: enumerated ${builtins.toJSON exposedPackageNames} (${exposeEnumeration})"
        echo "systemd gate:   $security_units workload services under threshold $security_threshold; $security_skipped allowlisted unconfined package(s) skipped: ''${security_skipped_names:-none}"
        echo "package policy: baked profile (${packagePolicyModule}), preset requires bundle (${packagePolicyRejectsPresetWithoutBundle}), target mismatch (${packagePolicyRejectsWrongTarget})"
        echo "derivations:    meta.execute uses build execution identity (${executionCompatibilityUsesBuildExecutionSystem})"
        echo "bare metal:    encrypted ZFS zvol slots and authoritative ESPs (${bareMetalStorageProfile})"

        # Force the build attributes to ensure they evaluate
        echo "toplevel:       ${system.config.system.build.toplevel.name}"
        echo "kernel:         ${system.config.system.build.kernel.name}"
        echo "initrd:         ${system.config.system.build.initrd.name}"
        echo "systemPkgs:     ${builtins.toString (builtins.length system.config.environment.systemPackages)}"

        echo ""
        echo "==> All eval checks passed."
        echo "PASS" > $out
      ''
    ];
  }
