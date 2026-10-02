##! Manual offline Nix candidates and static inspection; no TPM or installation.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.nixOfflinePrepare;
  selinux = config.aos.security.selinux;
  selected = config.systemd.services.aos-sandbox-nix-floor-provision;
  service = selected.serviceConfig;
  program = "${pkgs.aos-sandboxd}/bin/aos-sandbox-nix-floor-provision";
  command = "${program} ${cfg.command}";
  systemdLib = import ../../lib/modules/systemd/lib.nix {inherit lib pkgs;};
  delivery = [
    "node-id:/etc/credstore/node-id"
    "nix-floor-provision-approval-public-key-v3:/etc/credstore/nix-floor-provision-approval-public-key-v3"
  ];
  originalOpenFiles = [
    "/proc/1/exe:aos-nix-offline-prepare-pid1-image:read-only"
    "${profile}/profile.json:aos-nix-offline-prepare-profile:read-only"
  ];

  # Commit the complete final unit, replacing only the profile's self-reference.
  # The profile imports the existing image/loader/closure comparison engine.
  normalized = selected // {
    environment = config.systemd.globalEnvironment // selected.environment;
    serviceConfig = service // {
      OpenFile = [
        "/proc/1/exe:aos-nix-offline-prepare-pid1-image:read-only"
        "@AOS_NIX_OFFLINE_PREPARE_PROFILE@:aos-nix-offline-prepare-profile:read-only"
      ];
    };
  };
  rendered = systemdLib.serviceToUnit normalized;
  materialized = builtins.replaceStrings
    (builtins.map (job: job.placeholder) rendered.jobScripts)
    (builtins.map (job: job.path) rendered.jobScripts)
    rendered.text;
  profile = pkgs.aosNixOfflineStartupProfileWith {
    systemd = config.systemd.package;
    aos-selinux-production-policy = selinux._productionPolicy;
    aos-selinux-kernel-policy-readback = selinux._canonicalReadback;
    unitContract = materialized;
  };
in {
  options.aos.sandbox.nixOfflinePrepare.enable = lib.mkEnableOption
    "the disabled-by-default manual prepare-keys unit, without TPM or runtime installation";

  options.aos.sandbox.nixOfflinePrepare.command = lib.mkOption {
    type = lib.types.enum ["prepare-keys" "inspect-approved-job"];
    default = "prepare-keys";
    description = "Select the manual offline command; inspection authenticates static DATA only.";
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = selinux.enable && selinux.mode == "enforcing"
          && selinux.bootMode == "immutable-stage0";
        message = "Offline preparation requires the selected immutable enforcing production policy.";
      }
      {
        assertion = selected.wantedBy == [] && selected.requiredBy == []
          && (service.ExecStart or null) == command
          && (service.ExecStartPre or []) == [] && (service.ExecStartPost or []) == []
          && (service.User or null) == "root" && (service.Group or null) == "root"
          && (service.SupplementaryGroups or null) == ""
          && (service.DynamicUser or null) == false
          && (service.Slice or null) == "system.slice"
          && (service.SELinuxContext or null) == "system_u:system_r:aos_nix_offline_prepare_t"
          && (service.LoadCredential or []) == delivery
          && (service.LoadCredentialEncrypted or []) == []
          && (service.SetCredential or []) == [] && (service.SetCredentialEncrypted or []) == []
          && (service.ImportCredential or []) == []
          && (service.OpenFile or []) == originalOpenFiles
          && (service.ExtraFileDescriptorNames or []) == []
          && (service.FileDescriptorStoreMax or null) == 0
          && (service.Restart or null) == "no"
          && (service.CapabilityBoundingSet or null) == ["CAP_CHOWN" "CAP_DAC_OVERRIDE"]
          && (service.AmbientCapabilities or null) == ""
          && (service.NoNewPrivileges or null) == true
          && (service.SecureBits or null) == "no-setuid-fixup no-setuid-fixup-locked"
          && (service.ExitType or null) == "cgroup"
          && (service.KillMode or null) == "control-group"
          && (service.TimeoutStopSec or null) == "infinity"
          && (service.DevicePolicy or null) == "closed"
          && (service.DeviceAllow or []) == []
          && (service.PrivateNetwork or null) == true
          && (service.ProtectSystem or null) == "strict"
          && (service.ReadWritePaths or []) == ["/var/lib/aos"]
          && (service.StateDirectory or []) == [] && (service.RuntimeDirectory or []) == []
          && (service.RootDirectory or "") == "" && (service.RootImage or "") == "";
        message = "Offline preparation retains its exact manual root0/cap0x3 launch, public delivery, no-TPM and no-overwrite purpose.";
      }
    ];

    systemd.services.aos-sandbox-nix-floor-provision = {
      description = "Manual unsigned offline Nix key candidate preparation";
      wantedBy = [];
      requiredBy = [];
      requires = ["dbus.service"];
      after = ["dbus.service"];

      serviceConfig = {
        Type = "exec";
        ExecStart = command;
        Restart = "no";
        User = "root";
        Group = "root";
        SupplementaryGroups = "";
        DynamicUser = false;
        Slice = "system.slice";
        SELinuxContext = "system_u:system_r:aos_nix_offline_prepare_t";
        LoadCredential = delivery;
        OpenFile = originalOpenFiles;
        ExtraFileDescriptorNames = [];
        FileDescriptorStoreMax = 0;
        UMask = "0077";

        # This is the manager's parent configuration, not a direct kernel
        # securebits proof. NOROOT would remove the required parent Eff/Prm
        # across ordinary exec. It does not satisfy the future child's 0x0f gate.
        CapabilityBoundingSet = ["CAP_CHOWN" "CAP_DAC_OVERRIDE"];
        AmbientCapabilities = "";
        NoNewPrivileges = true;
        SecureBits = "no-setuid-fixup no-setuid-fixup-locked";
        ExitType = "cgroup";
        KillMode = "control-group";
        TimeoutStopSec = "infinity";
        LimitCORE = 0;
        LimitNOFILE = 2048;
        TasksMax = 8;
        MemoryMax = "1G";
        MemorySwapMax = 0;

        DevicePolicy = "closed";
        DeviceAllow = [];
        PrivateDevices = true;
        PrivateNetwork = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectProc = "invisible";
        ProcSubset = "all";
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectClock = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = ["AF_UNIX"];
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        ReadWritePaths = ["/var/lib/aos"];
        StateDirectory = [];
        RuntimeDirectory = [];
      };
    };
  };
}
