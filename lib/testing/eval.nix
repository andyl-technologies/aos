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
  # The kernel-lockdown option was removed: SECURITY_LOCKDOWN_LSM selects
  # MODULE_SIG, whose default key generation breaks third-party
  # bit-reproducibility of the public base image. Fail loudly at eval time
  # if the option declaration ever reappears.
  noKernelLockdown =
    if system.options.aos.security.hardening ? kernelLockdown
    then throw "aos.security.hardening.kernelLockdown must not exist; kernel lockdown pulls in module signing and is not part of the reproducible public base"
    else "ok";

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
    else if !(builtins.hasAttr "aos-graph-compile" system.config.systemd.services)
    then throw "the stock system must emit aos-graph-compile.service"
    else if !(builtins.hasAttr "aos-activate" system.config.systemd.services)
    then throw "the stock system must emit aos-activate.service"
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
        "/sysroot/var/lib/profiles/system/gen-$AOS_PROFILE_GEN/manifest.json"
        system.config.boot.initrd.systemd.services."aos-config-seed".script)
    then throw "initrd configuration restoration must use the current retained generation manifest"
    else if
      !(builtins.elem
        "aos-activate.service"
        system.config.systemd.targets.aos-config.wants)
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
    else if
      !system.config.boot.initrd.systemd.network."80-dhcp".networkConfig.IPv4LLRoute
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
        "aos-provisioning-eval.service"
        system.config.boot.initrd.systemd.services.aos-repart.requires)
    then throw "aos-repart.service must require restricted provisioning evaluation"
    else if
      !(builtins.elem
        "aos-provisioning-eval.service"
        system.config.boot.initrd.systemd.services.aos-repart.after)
    then throw "aos-repart.service must run after restricted provisioning evaluation"
    else "ok";

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
    if provisioningProjection.config.aos.provisioning.storage.partitions.var.sizeMin
    != "8G"
    then throw "restricted provisioning evaluation did not apply host storage"
    else if provisioningProjection.config.aos.provisioning.storage.partitions.swap.type
    != "swap"
    then throw "partial host storage overrides discarded default partition fields"
    else if provisioningProjection.config.aos.provisioning.storage.partitions.swap.format
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
      };
    }
  ];
  expectedRegistryToml = ''
    # /etc/apm/registries.d/example.toml
    # Generated by modules/base/apm-registries.nix - do not edit manually.
    [registry]
    name = "example"
    url = "https://registry.example/aos"
    priority = 50
    enabled = true

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

        echo "config keys:    ${builtins.toJSON (builtins.attrNames system.config.aos)}"
        echo "kernelLockdown: removed (${noKernelLockdown})"
        echo "configuration pipeline: structural default (${structuralConfiguration}), closed early projection (${provisioningProjectionIsClosed}), pure JSON (${provisioningProjectionHasNoModuleInternals}), closed package selection (${hostSelectionProjectionIsClosed})"
        echo "apm registries: content (${apmRegistriesContent}), malformed key (${apmRegistriesRejectsMalformedKey}), empty keys (${apmRegistriesRejectsEmptyKeys})"
        echo "apm install boot: etc (${apmInstallAtBootEtc}), invalid config (${apmInstallAtBootRejectsInvalidConfigPackage}), invalid credential (${apmInstallAtBootRejectsInvalidCredentialName}), plaintext credential (${apmInstallAtBootRejectsPlaintextCredential}), invalid system credential (${apmInstallAtBootRejectsInvalidSystemCredentialName}), credential conflict (${apmInstallAtBootRejectsCredentialConflicts}), invalid registry (${apmRegistriesRejectsInvalidName})"
        echo "nsswitch:       explicit hosts/DNS, no nss-mymachines (${nsswitchNoMymachines})"
        echo "firewall:       no package drop-in include (${firewallNoNftablesDropin}), scan-dir storage rejected (${scanDirStorageRejected})"
        echo "package expose: enumerated ${builtins.toJSON exposedPackageNames} (${exposeEnumeration})"
        echo "systemd gate:   $security_units workload services under threshold $security_threshold; $security_skipped allowlisted unconfined package(s) skipped: ''${security_skipped_names:-none}"
        echo "package policy: baked profile (${packagePolicyModule}), preset requires bundle (${packagePolicyRejectsPresetWithoutBundle}), target mismatch (${packagePolicyRejectsWrongTarget})"

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
