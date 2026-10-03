##! modules/sandbox/policy-authority.nix — signed deployment policy input custody
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.policyAuthority;
  controller = config.aos.sandbox.controller;
  confined = config.aos.security.selinux.enable && config.aos.security.selinux.bootMode == "immutable-stage0";
  normalUnit = config.systemd.services.aos-sandbox-policy-authorityd;
  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  # Replace only the explicit profile self-reference. All other final selected
  # service bytes (including global environment and external overrides) remain
  # committed without a profile→unit→profile derivation cycle.
  normalizedNormalUnit =
    normalUnit
    // {
      environment = config.systemd.globalEnvironment // normalUnit.environment;
      serviceConfig =
        normalUnit.serviceConfig
        // {
          OpenFile = [
            "/proc/1/exe:aos-normal-root-pid1-image:read-only"
            "@AOS_NORMAL_ROOT_PROFILE@:aos-normal-root-profile:read-only"
          ];
        };
    };
  renderedNormalUnit = systemdLib.serviceToUnit normalizedNormalUnit;
  # Match makeUnit's existing build-side substitution for actual job scripts.
  # Committing eval-only placeholders would not bind the installed unit bytes.
  materializedNormalUnit =
    builtins.replaceStrings
    (builtins.map (job: job.placeholder) renderedNormalUnit.jobScripts)
    (builtins.map (job: job.path) renderedNormalUnit.jobScripts)
    renderedNormalUnit.text;
  normalRootProfile = pkgs.aosNormalRootStartupProfileWith {
    aos-sandboxd = cfg.package;
    systemd = config.systemd.package;
    aos-selinux-production-policy = config.aos.security.selinux._productionPolicy;
    aos-selinux-kernel-policy-readback = config.aos.security.selinux._canonicalReadback;
    unitContract = materializedNormalUnit;
    identities = [controller.uid controller.gid cacheSignerUid sourceSignerUid];
  };
  preparer = import ./_view-preparer.nix {inherit config pkgs;};
  cacheRecovery = config.systemd.services.aos-sandbox-policy-cache-recovery;
  cacheRecoveryConfig = cacheRecovery.serviceConfig;
  cacheSignerView = config.aos.sandbox.cacheSignerView or {enable = false;};
  sourceSignerView = config.aos.sandbox.sourceSignerView or {enable = false;};
  cacheSignerService = config.aos.sandbox.cacheSignerService or {enable = false;};
  sourceSignerService = config.aos.sandbox.sourceSignerService or {enable = false;};
  cacheSignerUid =
    if cacheSignerView.enable && cacheSignerService.enable
    then cacheSignerView.uid
    else 0;
  sourceSignerUid =
    if sourceSignerView.enable && sourceSignerService.enable
    then sourceSignerView.uid
    else 0;
  requiredCredentials = {
    deploymentPublicKey = "deployment-public-key";
    deploymentHeadPacket = "deployment-head.packet";
    nodePolicy = "node-policy.json";
    sitePolicy = "site-policy.json";
    backendCapabilities = "backend-capabilities.json";
    catalogs = "catalogs.json";
    projectPublicKey = "project-public-key";
  };
  projectCredentials = {
    projectHeadPacket = "project-head.packet";
    projectLayer = "project-layer.json";
    projectHeadPacketV2 = "project-head-v2.packet";
    projectLayerV2 = "project-layer-v2.json";
  };
  cacheCredentials = {
    cacheOwnerReadbackPublicKey = "cache-owner-readback-public-key";
  };
  controllerCredentials = {
    controllerHoldPublicKey = "controller-hold-public-key";
  };
  sourceCredentials = {
    sourceHoldPublicKey = "source-hold-public-key";
  };
  genesisCredentials = {
    sourceTreeSeedIssuer = "controller-source-tree-seed-issuer-v1";
    projectAuthorizationIssuer = "project-authorization-issuer-v2";
  };
  gitEvidenceCredentials = {
    gitEvidenceProvision = "git-evidence-provision-v1";
  };
  credentialFiles = requiredCredentials // projectCredentials // cacheCredentials // controllerCredentials // sourceCredentials // genesisCredentials // gitEvidenceCredentials;
  cacheJournalSource = "/var/lib/aos/sandbox/cache-residency-journals";
  cacheJournalView = "/run/aos/sandbox-policy-cache-journals";
  prepareCacheJournalView = preparer.writeScript "aos-sandbox-cache-journal-view" ''
    set -eu

    source=${cacheJournalSource}
    view=${cacheJournalView}
    controller_uid=${toString controller.uid}
    controller_gid=${toString controller.gid}

    require_root_directory() {
      test "$(${preparer.coreutils}/stat --format='%F:%u:%g' "$1")" = directory:0:0
      mode="$(${preparer.coreutils}/stat --format='%a' "$1")"
      test $((8#$mode & 022)) -eq 0
    }

    for directory in /var /var/lib /var/lib/aos /var/lib/aos/sandbox; do
      if ! test -e "$directory"; then
        ${preparer.coreutils}/mkdir --mode=0755 "$directory"
      fi
      require_root_directory "$directory"
    done

    # Unexpected old-path journal names must never initialize the new view.
    legacy=/var/lib/aos/sandbox/cache-residency
    # The parent was checked as root-owned, so the Controller cannot rename
    # this root after the check. An alias to the empty new root is never safe.
    if test -L "$legacy"; then
      exit 1
    fi
    if test -e "$legacy"; then
      test "$(${preparer.coreutils}/stat --format='%F' "$legacy")" = directory
    fi
    for name in state.journal authority.journal clock.journal policy-hold.journal; do
      for suffix in "" .lock .compact.tmp; do
        if test -e "$legacy/$name$suffix" || test -L "$legacy/$name$suffix"; then
          exit 1
        fi
      done
    done

    if ! test -e "$source"; then
      ${preparer.coreutils}/mkdir --mode=0700 "$source"
      ${preparer.coreutils}/chown "$controller_uid:$controller_gid" "$source"
    fi
    test "$(${preparer.coreutils}/stat --format='%F:%u:%g:%a' "$source")" = "directory:$controller_uid:$controller_gid:700"

    # Reject unexpected initial contents. This is not a live filename filter;
    # a future reader must still open only fixed names and verify currentness.
    for entry in "$source"/* "$source"/.[!.]* "$source"/..?*; do
      if ! test -e "$entry" && ! test -L "$entry"; then
        continue
      fi
      case "$entry" in
        "$source"/state.journal|"$source"/state.journal.lock|"$source"/state.journal.compact.tmp|\
        "$source"/authority.journal|"$source"/authority.journal.lock|"$source"/authority.journal.compact.tmp|\
        "$source"/clock.journal|"$source"/clock.journal.lock|"$source"/clock.journal.compact.tmp|\
        "$source"/policy-hold.journal|"$source"/policy-hold.journal.lock|"$source"/policy-hold.journal.compact.tmp) ;;
        *) exit 1 ;;
      esac
      test "$(${preparer.coreutils}/stat --format='%F:%u:%g:%a' "$entry")" = "regular file:$controller_uid:$controller_gid:600"
    done

    if ! test -e /run/aos; then
      ${preparer.coreutils}/mkdir --mode=0755 /run/aos
    fi
    require_root_directory /run
    require_root_directory /run/aos
    if ! test -e "$view"; then
      ${preparer.coreutils}/mkdir --mode=0700 "$view"
    fi
    test "$(${preparer.coreutils}/stat --format='%F:%u:%g:%a' "$view")" = directory:0:0:700
    if ${preparer.utilLinux}/findmnt --mountpoint "$view" --noheadings >/dev/null; then
      exit 1
    fi

    ${preparer.utilLinux}/mount --internal-only --no-mtab --bind \
      --map-users "$controller_uid:0:1" \
      --map-groups "$controller_gid:0:1" \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      "$source" "$view"
    trap '${preparer.utilLinux}/umount --internal-only --no-mtab --no-canonicalize ${cacheJournalView}' EXIT

    test "$(${preparer.coreutils}/stat --format='%F:%u:%g:%a' "$view")" = directory:0:0:700
    test "$(${preparer.coreutils}/stat --format='%d:%i' "$source")" = \
      "$(${preparer.coreutils}/stat --format='%d:%i' "$view")"
    mount_options="$(${preparer.utilLinux}/findmnt --noheadings --mountpoint "$view" --output VFS-OPTIONS)"
    for option in ro nosuid nodev noexec nosymfollow; do
      case ",$mount_options," in
        *,$option,*) ;;
        *) exit 1 ;;
      esac
    done
    trap - EXIT
  '';
in {
  options.aos.sandbox.policyAuthority = {
    _preparerPackage = lib.mkOption {
      type = lib.types.package;
      internal = true;
      readOnly = true;
      default = prepareCacheJournalView;
      description = "Exact immutable checked cache view entrypoint selected by the production policy.";
    };
    _normalStartupProfile = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      internal = true;
      readOnly = true;
      default =
        if confined
        then normalRootProfile
        else null;
      description = "Selected-image server-local normal Root startup inputs, never a client or FUSE read grant.";
    };
    enable = lib.mkEnableOption "the root-owned signed deployment policy input authority";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandboxd;
      defaultText = "pkgs.aos-sandboxd";
      description = "The package containing the independent policy authority executable.";
    };

    credentials = lib.mapAttrs (option: _:
      lib.mkOption {
        type = lib.types.nullOr lib.serviceTypes.credentialName;
        default = null;
        description =
          if option == "deploymentPublicKey"
          then "Externally provisioned 80-byte AOSPDK01 deployment signer pin (nonzero generation and public key). Raw 32-byte keys are rejected."
          else if option == "projectPublicKey"
          then "Externally provisioned 80-byte AOSPPK01 project signer pin (nonzero generation and public key). Raw 32-byte keys are rejected."
          else if option == "cacheOwnerReadbackPublicKey"
          then "Optional 80-byte AOSCPK01 Cache-only signer pin for nonauthorizing V2 settlement and Q04 held-flight readback; first CAS and Create remain closed."
          else if option == "controllerHoldPublicKey"
          then "Optional 80-byte AOSCTK01 Controller-only hold signer pin. Root persists exact replay but Q04 does not consume receipts or publish Create."
          else if option == "sourceHoldPublicKey"
          then "Optional 80-byte AOSSPK01 Source-only hold signer pin for nonauthorizing Q04 held-flight readback; first CAS and Create remain closed."
          else if option == "sourceTreeSeedIssuer"
          then "Optional existing 80-byte AOSCSK01 administrative Source Tree seed issuer pin. Genesis requires this and the independent project authorization issuer together; this is not a readback key."
          else if option == "projectAuthorizationIssuer"
          then "Optional existing 80-byte AOSPAK02 administrative project authorization issuer pin for exact signed seven-limit genesis inputs; no readback role or inferred grant is added."
          else if option == "gitEvidenceProvision"
          then "Optional bounded AOSGEP01 trusted Root-administration Git evidence instruction, not a dynamic validator attestation or Git activation."
          else if option == "projectHeadPacketV2" || option == "projectLayerV2"
          then "Optional AOSPPH02/AOSPPL02 project source; both credentials are required for the closed AOSPHQ04 path."
          else "Externally provisioned signed deployment policy authority input.";
      })
    credentialFiles;
  };

  config = lib.mkIf cfg.enable {
    assertions =
      lib.mapAttrsToList (option: _: {
        assertion = cfg.credentials.${option} != null;
        message = "aos.sandbox.policyAuthority.credentials.${option} is required";
      })
      requiredCredentials
      ++ [
        {
          assertion = cfg.credentials.gitEvidenceProvision == null || (confined && cfg.package == pkgs.aos-sandboxd);
          message = "Git evidence provisioning requires the selected confined normal Root package";
        }
        {
          assertion = !(config.aos.security.selinux.enable && config.aos.security.selinux.bootMode == "immutable-stage0") || cfg.package == pkgs.aos-sandboxd;
          message = "confined normal policy authority requires the exact policy-labelled AOS package; the same-ELF recovery invocation remains outside the normal role";
        }
        {
          assertion =
            (cfg.credentials.sourceTreeSeedIssuer == null)
            == (cfg.credentials.projectAuthorizationIssuer == null);
          message = "Source genesis administrative seed and project authorization issuer pins must be provisioned together";
        }
        {
          assertion =
            (cfg.credentials.projectHeadPacket == null)
            == (cfg.credentials.projectLayer == null);
          message = "aos.sandbox.policyAuthority V1 project packet and input credentials must be provisioned together";
        }
        {
          assertion =
            (cfg.credentials.projectHeadPacketV2 == null)
            == (cfg.credentials.projectLayerV2 == null);
          message = "aos.sandbox.policyAuthority V2 project packet and input credentials must be provisioned together";
        }
        {
          assertion =
            (cfg.credentials.projectHeadPacket != null)
            != (cfg.credentials.projectHeadPacketV2 != null);
          message = "aos.sandbox.policyAuthority requires exactly one project source version";
        }
        {
          assertion =
            cacheRecoveryConfig.ExecStart
            == "${cfg.package}/bin/aos-sandbox-policy-authorityd --serve-cache-signer-recovery ${toString controller.uid} ${toString controller.gid}"
            && cacheRecoveryConfig.Type == "simple"
            && cacheRecoveryConfig.User == "root"
            && cacheRecoveryConfig.Group == "aos-sandboxd"
            && cacheRecoveryConfig.UMask == "0007"
            && cacheRecoveryConfig.RuntimeDirectory == "aos/sandbox-policy-cache-recovery"
            && cacheRecoveryConfig.RuntimeDirectoryMode == "0710"
            && cacheRecoveryConfig.StateDirectory == "aos/sandbox/policy-compiler"
            && cacheRecoveryConfig.StateDirectoryMode == "0700";
          message = "Cache recovery must retain its fixed executable, root identity, and private socket and journal directories";
        }
        {
          assertion =
            (cacheRecoveryConfig.LoadCredential or [])
            == []
            && (cacheRecoveryConfig.ReadWritePaths or []) == []
            && (cacheRecoveryConfig.BindPaths or []) == []
            && cacheRecoveryConfig.ProtectSystem == "strict"
            && cacheRecoveryConfig.CapabilityBoundingSet == ""
            && cacheRecoveryConfig.NoNewPrivileges
            && cacheRecoveryConfig.RestrictAddressFamilies == ["AF_UNIX"]
            && (cacheRecovery.requires or []) == []
            && (cacheRecovery.wants or []) == []
            && cacheRecovery.after == ["local-fs.target"]
            && cacheRecovery.unitConfig.RequiresMountsFor == ["/var/lib/aos/sandbox/policy-compiler"]
            && (cacheRecovery.unitConfig.BindsTo or []) == [];
          message = "Cache recovery must not depend on policy credentials, normal authority, Cache views, or broad write access";
        }
      ];

    systemd.services.aos-sandbox-cache-journal-view = {
      description = "AOS root-only idmapped Cache journal view";
      wantedBy = ["multi-user.target"];
      before = ["aos-sandboxd.service" "aos-sandbox-policy-authorityd.service"];
      after = ["local-fs.target"];
      unitConfig.RequiresMountsFor = ["/var/lib/aos/sandbox"];
      serviceConfig =
        preparer.serviceConfig
        // {
          Type = "oneshot";
          RemainAfterExit = true;
          SELinuxContext = lib.mkIf preparer.confined "system_u:system_r:aos_sandbox_cache_view_preparer_t";
          # Keep the script's exact labelled package independent of the policy
          # and provisioner that label it. Both fixed commands use this unit's
          # reviewed preparation role; neither accepts a caller-selected path.
          ExecStartPre = lib.mkIf preparer.confined "${config.aos.security.selinux._runtimeRootsProvisioner}/bin/aos-selinux-runtime-roots --root / --prepare-sandbox-view-roots";
          ExecStart = "${prepareCacheJournalView}/bin/aos-sandbox-cache-journal-view";
          ExecStop = "${preparer.utilLinux}/umount --internal-only --no-mtab --no-canonicalize ${cacheJournalView}";
          User = "root";
          Group = "root";
          UMask = "0077";
          CapabilityBoundingSet = [
            "CAP_CHOWN"
            "CAP_DAC_READ_SEARCH"
            "CAP_SETGID"
            "CAP_SETUID"
            "CAP_SYS_ADMIN"
          ];
          RestrictAddressFamilies = ["AF_UNIX"];
        };
    };

    systemd.services.aos-sandbox-policy-authorityd = {
      description = "AOS signed deployment policy input authority";
      wantedBy = ["multi-user.target"];
      requires =
        ["aos-sandbox-cache-journal-view.service"]
        ++ lib.optional cacheSignerView.enable "aos-sandbox-cache-signer-views.service"
        ++ lib.optional sourceSignerView.enable "aos-sandbox-source-signer-view.service";
      after =
        ["local-fs.target" "aos-sandbox-cache-journal-view.service"]
        ++ lib.optional cacheSignerView.enable "aos-sandbox-cache-signer-views.service"
        ++ lib.optional sourceSignerView.enable "aos-sandbox-source-signer-view.service";
      unitConfig.BindsTo =
        ["aos-sandbox-cache-journal-view.service"]
        ++ lib.optional cacheSignerView.enable "aos-sandbox-cache-signer-views.service"
        ++ lib.optional sourceSignerView.enable "aos-sandbox-source-signer-view.service";
      serviceConfig = {
        Type = "simple";
        # Recovery CLI uses the same ELF but never inherits this normal role.
        SELinuxContext = lib.mkIf confined "system_u:system_r:aos_sandbox_policy_authority_t";
        OpenFile = lib.mkIf confined [
          "/proc/1/exe:aos-normal-root-pid1-image:read-only"
          "${normalRootProfile}/profile.json:aos-normal-root-profile:read-only"
        ];
        # Zero identities disable signer flights unless their separate services and views are enabled.
        ExecStart = "${cfg.package}/bin/aos-sandbox-policy-authorityd ${toString controller.uid} ${toString controller.gid} ${toString cacheSignerUid} ${toString sourceSignerUid}";
        LoadCredential =
          lib.mapAttrsToList (option: name: "${name}:/run/credentials/@system/${cfg.credentials.${option}}")
          (lib.filterAttrs (option: _: cfg.credentials.${option} != null) credentialFiles);
        StateDirectory = "aos/sandbox/policy-compiler";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-policy-authority";
        RuntimeDirectoryMode = "0710";
        User = "root";
        Group = "aos-sandboxd";
        UMask = "0007";

        CapabilityBoundingSet = "";
        InaccessiblePaths =
          lib.optionals cacheSignerView.enable [
            "/run/aos/sandbox-cache-signer-journals"
            "/run/aos/sandbox-cache-signer-objects"
          ]
          ++ lib.optional sourceSignerView.enable "/run/aos/sandbox-source-signer-journal";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProcSubset = "all";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        # Administration must preprovision this exact labelled Root directory.
        ReadWritePaths = lib.mkIf (cfg.credentials.gitEvidenceProvision != null) [
          "/var/lib/aos/sandbox/source-evidence"
        ];
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
      };
    };

    # Historical V7 replay must remain reachable when signed current inputs or
    # the normal authority's credential loading fail before it binds a socket.
    systemd.services.aos-sandbox-policy-cache-recovery = {
      description = "AOS root-only Cache signer settlement recovery";
      wantedBy = ["multi-user.target"];
      after = ["local-fs.target"];
      unitConfig.RequiresMountsFor = ["/var/lib/aos/sandbox/policy-compiler"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/aos-sandbox-policy-authorityd --serve-cache-signer-recovery ${toString controller.uid} ${toString controller.gid}";
        StateDirectory = "aos/sandbox/policy-compiler";
        StateDirectoryMode = "0700";
        RuntimeDirectory = "aos/sandbox-policy-cache-recovery";
        RuntimeDirectoryMode = "0710";
        User = "root";
        Group = "aos-sandboxd";
        # Rust binds recovery.sock as root:aos-sandboxd with mode 0770.
        UMask = "0007";

        CapabilityBoundingSet = "";
        DevicePolicy = "closed";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProcSubset = "pid";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
      };
    };
  };
}
