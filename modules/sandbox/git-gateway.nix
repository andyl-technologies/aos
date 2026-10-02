##! Dedicated service-bounded Gateway transport with advisory node-memory admission.
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.gitGatewayTransport;
  inspection = config.aos.sandbox.controllerService.gitReadInspection.enable;
  controller = config.aos.sandbox.controller;
  selinux = config.aos.security.selinux;
  name = "aos-git-gateway";
  program = "${cfg.package}/bin/aos-sandbox-git-gateway";
  policyPath = "${selinux._canonicalReadback}/policy.33";
  residencyProfile = "service-memcg-observed-node-memory-v1";
  selectedProfile = if cfg.residencyProfile == null then "" else cfg.residencyProfile;
  selectedMinimum =
    if cfg.minimumObservedNodeAvailableBytes == null
    then ""
    else toString cfg.minimumObservedNodeAvailableBytes;
  arguments = [program cfg.endpoint (toString cfg.uid) (toString cfg.gid) policyPath selectedProfile selectedMinimum]
    ++ lib.optionals inspection ["--read-scope-inspection" (toString controller.uid) (toString controller.gid)];
  credentialNames = {
    serverCert = "public-api-server-cert";
    serverKey = "public-api-server-key";
    clientCa = "public-api-client-ca";
    principals = "public-api-principals";
  };
  delivery = lib.mapAttrsToList (
    option: credential: "${credential}:/run/credentials/@system/${cfg.credentials.${option}}"
  ) (lib.filterAttrs (option: _: cfg.credentials.${option} != null) credentialNames);
  service = config.systemd.services.aos-sandbox-git-gateway.serviceConfig;
  otherUsers = lib.filterAttrs (user: _: user != name) config.aos.users.users;
  otherGroups = lib.filterAttrs (group: _: group != name) config.aos.users.groups;
in {
  options.aos.sandbox.gitGatewayTransport = {
    enable = lib.mkEnableOption "the dedicated transport-only Gateway without Git backend activation";

    residencyProfile = lib.mkOption {
      type = lib.types.nullOr (lib.types.enum [residencyProfile]);
      default = null;
      description = "Explicit service-memcg and advisory node-memory profile; no hard all-node or per-tenant network residency promise.";
    };

    minimumObservedNodeAvailableBytes = lib.mkOption {
      type = lib.types.nullOr (lib.types.addCheck lib.types.int (value: value >= 1073741824));
      default = null;
      description = "Explicit minimum live MemAvailable estimate before admission, at least the 1 GiB service limit. This load-shedding threshold reserves no node capacity and guarantees no allocation headroom.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-sandboxd;
      defaultText = "pkgs.aos-sandboxd";
      description = "Exact evaluated policy-labelled Gateway executable package.";
    };

    endpoint = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Explicit canonical numeric SocketAddr with port at least 1024; no DNS, fallback or ephemeral port.";
    };

    uid = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value > 0 && value < 65536);
      default = 980;
      description = "Dedicated, collision-checked Gateway UID; no Controller identity reuse.";
    };

    gid = lib.mkOption {
      type = lib.types.addCheck lib.types.int (value: value > 0 && value < 65536);
      default = 980;
      description = "Dedicated, collision-checked Gateway primary GID.";
    };

    credentials = lib.genAttrs (builtins.attrNames credentialNames) (_: lib.mkOption {
      type = lib.types.nullOr lib.serviceTypes.credentialName;
      default = null;
      description = "Independently provisioned TLS credential, not inherited from Controller configuration.";
    });
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        # These are policy coordinates in the exact immutable unit, not an
        # authority Boolean. Startup retains and reads the actual kernel file.
        assertion = cfg.residencyProfile == residencyProfile
          && cfg.minimumObservedNodeAvailableBytes != null;
        message = "Gateway requires the explicit service-memcg/observed-node-memory profile and minimum. Hard tenant or all-node network profiles are unsupported; live startup must independently admit the original service and kernel observation.";
      }
      {
        assertion = selinux.enable && selinux.mode == "enforcing"
          && selinux.bootMode == "immutable-stage0" && cfg.package == pkgs.aos-sandboxd;
        message = "Gateway requires immutable-stage0 enforcing MAC, its selected-kernel canonical readback, and the exact policy-labelled AOS package.";
      }
      {
        assertion = cfg.endpoint != "" && builtins.match "([0-9]+\\.){3}[0-9]+:[0-9]+|\\[[0-9A-Fa-f:.]+\\]:[0-9]+" cfg.endpoint != null;
        message = "Gateway requires an explicitly selected numeric TCP endpoint; startup additionally checks canonical spelling and an unprivileged nonzero port.";
      }
      {
        assertion = lib.all (value: value != null) (builtins.attrValues cfg.credentials)
          && lib.length (lib.unique (builtins.attrValues cfg.credentials)) == 4;
        message = "Gateway requires four distinct, independently provisioned TLS credential selections.";
      }
      {
        assertion = lib.all (user: (user.uid or null) != cfg.uid
          && (user.group or null) != name && !(lib.elem name (user.extraGroups or []))) (builtins.attrValues otherUsers)
          && lib.all (group: (group.gid or null) != cfg.gid) (builtins.attrValues otherGroups)
          && (config.aos.users.users.${name}.uid or null) == cfg.uid
          && (config.aos.users.groups.${name}.gid or null) == cfg.gid
          && (config.aos.users.groups.${name}.members or []) == []
          && (config.aos.users.users.${name}.extraGroups or []) == [];
        message = "Gateway needs its own collision-free UID/GID and no supplementary groups.";
      }
      {
        assertion = (service.Type or null) == "exec"
          && (service.ExecStart or null) == lib.escapeShellArgs arguments
          && (service.ExecStartPre or []) == [] && (service.ExecStartPost or []) == []
          && (service.User or null) == name && (service.Group or null) == name
          && (service.SupplementaryGroups or null) == ""
          && (service.DynamicUser or null) == false
          && (service.SELinuxContext or null) == "system_u:system_r:aos_sandbox_git_gateway_t"
          && (service.Restart or null) == "no" && (service.Slice or null) == "system.slice"
          && (service.MemoryMax or null) == "1G" && (service.MemorySwapMax or null) == 0
          && (service.TasksMax or null) == 8 && (service.LimitNOFILE or null) == 128
          && (service.CPUQuota or null) == "100%" && (service.CPUQuotaPeriodSec or null) == "100ms"
          && (service.CapabilityBoundingSet or null) == "" && (service.AmbientCapabilities or null) == ""
          && (service.NoNewPrivileges or null) == true
          && (service.ProtectSystem or null) == "strict"
          && (service.ProtectControlGroups or null) == true
          && (service.PrivateNetwork or null) == false
          && (service.DevicePolicy or null) == "closed"
          && (service.RestrictNamespaces or null) == true
          && (service.MemoryDenyWriteExecute or null) == true
          && (service.LoadCredential or []) == delivery
          && (service.SetCredential or []) == [] && (service.LoadCredentialEncrypted or []) == []
          && (service.SetCredentialEncrypted or []) == [] && (service.ImportCredential or []) == []
          && (service.OpenFile or []) == [] && (service.ExtraFileDescriptorNames or []) == []
          && (service.FileDescriptorStoreMax or null) == 0
          && (service.ReadWritePaths or []) == [] && (service.BindPaths or []) == []
          && (service.StateDirectory or []) == [] && (service.RuntimeDirectory or []) == []
          && (service.ProtectProc or null) == (if inspection then "default" else "invisible") && (service.ProcSubset or null) == "all"
          && (service.RootDirectory or "") == "" && (service.RootImage or "") == ""
          && (service.RestrictAddressFamilies or []) == ["AF_UNIX" "AF_INET" "AF_INET6"];
        message = "Gateway final unit must retain the fixed dedicated launch, credential delivery, two-slot hard envelope and read-only confinement without owner/helper authority.";
      }
    ];

    aos.users.groups.${name} = {
      gid = cfg.gid;
      members = [];
    };
    aos.users.users.${name} = {
      uid = cfg.uid;
      group = name;
      extraGroups = [];
      home = "/";
      createHome = false;
      shell = "/sbin/nologin";
      description = "AOS transport-only Git Gateway";
    };

    systemd.services.aos-sandbox-git-gateway = {
      description = "AOS transport-only TLS/H2 Git Gateway (no Git effects)";
      wantedBy = ["multi-user.target"];
      requires = ["dbus.service"];
      after = ["dbus.service" "network.target"];
      serviceConfig = {
        Type = "exec";
        ExecStart = lib.escapeShellArgs arguments;
        Restart = "no";
        User = name;
        Group = name;
        SupplementaryGroups = "";
        DynamicUser = false;
        SELinuxContext = "system_u:system_r:aos_sandbox_git_gateway_t";
        Slice = "system.slice";
        LoadCredential = delivery;
        UMask = "0077";

        # These REAL hard limits cover chargeable opaque/runtime/kernel bytes.
        # They are not claims that local Vec funding charges every network or
        # shared allocation, nor evidence of sufficient maximum-body headroom.
        MemoryMax = "1G";
        MemorySwapMax = 0;
        TasksMax = 8;
        LimitNOFILE = 128;
        CPUQuota = "100%";
        CPUQuotaPeriodSec = "100ms";
        LimitCORE = 0;
        FileDescriptorStoreMax = 0;
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        NoNewPrivileges = true;

        DevicePolicy = "closed";
        PrivateDevices = true;
        PrivateNetwork = false;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectProc = if inspection then "default" else "invisible";
        # Original clocks and advisory node-memory reads need global proc files.
        # No proc networking allocator or reservation authority is inferred.
        ProcSubset = "all";
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        RestrictAddressFamilies = ["AF_UNIX" "AF_INET" "AF_INET6"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        ReadWritePaths = [];
        BindPaths = [];
        StateDirectory = [];
        RuntimeDirectory = [];
      };
    };
  };
}
