##! modules/sandbox/policy-authority.nix — signed deployment policy input custody
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.policyAuthority;
  controller = config.aos.sandbox.controller;
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
  credentialFiles = requiredCredentials // projectCredentials // cacheCredentials;
  cacheJournalSource = "/var/lib/aos/sandbox/cache-residency-journals";
  cacheJournalView = "/run/aos/sandbox-policy-cache-journals";
  prepareCacheJournalView = pkgs.writeShellScriptBin "aos-sandbox-cache-journal-view" ''
    set -eu

    source=${cacheJournalSource}
    view=${cacheJournalView}
    controller_uid=${toString controller.uid}
    controller_gid=${toString controller.gid}

    require_root_directory() {
      test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g' "$1")" = directory:0:0
      mode="$(${pkgs.coreutils}/bin/stat --format='%a' "$1")"
      test $((8#$mode & 022)) -eq 0
    }

    for directory in /var /var/lib /var/lib/aos /var/lib/aos/sandbox; do
      if ! test -e "$directory"; then
        ${pkgs.coreutils}/bin/mkdir --mode=0755 "$directory"
      fi
      require_root_directory "$directory"
    done

    # Unexpected old-path journal names must never initialize the new view.
    legacy=/var/lib/aos/sandbox/cache-residency
    for name in state.journal authority.journal clock.journal policy-hold.journal; do
      for suffix in "" .lock .compact.tmp; do
        if test -e "$legacy/$name$suffix" || test -L "$legacy/$name$suffix"; then
          exit 1
        fi
      done
    done

    if ! test -e "$source"; then
      ${pkgs.coreutils}/bin/mkdir --mode=0700 "$source"
      ${pkgs.coreutils}/bin/chown "$controller_uid:$controller_gid" "$source"
    fi
    test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' "$source")" = "directory:$controller_uid:$controller_gid:700"

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
      test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' "$entry")" = "regular file:$controller_uid:$controller_gid:600"
    done

    if ! test -e /run/aos; then
      ${pkgs.coreutils}/bin/mkdir --mode=0755 /run/aos
    fi
    require_root_directory /run
    require_root_directory /run/aos
    if ! test -e "$view"; then
      ${pkgs.coreutils}/bin/mkdir --mode=0700 "$view"
    fi
    test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' "$view")" = directory:0:0:700
    if ${pkgs.util-linux}/bin/findmnt --mountpoint "$view" --noheadings >/dev/null; then
      exit 1
    fi

    ${pkgs.util-linux}/bin/mount --bind \
      --map-users "$controller_uid:0:1" \
      --map-groups "$controller_gid:0:1" \
      --options ro,nosuid,nodev,noexec,nosymfollow \
      "$source" "$view"
    trap '${pkgs.util-linux}/bin/umount --no-canonicalize ${cacheJournalView}' EXIT

    test "$(${pkgs.coreutils}/bin/stat --format='%F:%u:%g:%a' "$view")" = directory:0:0:700
    test "$(${pkgs.coreutils}/bin/stat --format='%d:%i' "$source")" = \
      "$(${pkgs.coreutils}/bin/stat --format='%d:%i' "$view")"
    mount_options="$(${pkgs.util-linux}/bin/findmnt --noheadings --mountpoint "$view" --output VFS-OPTIONS)"
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
          then "Optional 80-byte AOSCPK01 Cache-only signer pin. Root persists exact replay but does not accept Cache readbacks or publish Create."
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
      ];

    systemd.services.aos-sandbox-cache-journal-view = {
      description = "AOS root-only idmapped Cache journal view";
      wantedBy = ["multi-user.target"];
      before = ["aos-sandboxd.service" "aos-sandbox-policy-authorityd.service"];
      after = ["local-fs.target"];
      unitConfig.RequiresMountsFor = ["/var/lib/aos/sandbox"];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${prepareCacheJournalView}/bin/aos-sandbox-cache-journal-view";
        ExecStop = "${pkgs.util-linux}/bin/umount --no-canonicalize ${cacheJournalView}";
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
      requires = ["aos-sandbox-cache-journal-view.service"];
      after = ["local-fs.target" "aos-sandbox-cache-journal-view.service"];
      unitConfig.BindsTo = ["aos-sandbox-cache-journal-view.service"];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/aos-sandbox-policy-authorityd ${toString controller.uid} ${toString controller.gid}";
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
