##! modules/sandbox/source-provider.nix — protected catalog-currentness ingress
{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.aos.sandbox.sourceProvider;
in {
  options.aos.sandbox.sourceProvider = {
    enable = lib.mkEnableOption "the authenticated catalog-currentness SourceProvider ingress";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.aos-source-providerd;
      defaultText = "pkgs.aos-source-providerd";
      description = "The separate SourceProvider service executable; it does not dispatch backend effects.";
    };

    credentials.catalogPublication = lib.mkOption {
      type = lib.types.nullOr lib.serviceTypes.credentialName;
      default = null;
      description = "External canonical 520-byte signed catalog publication installed as a nonauthorizing locator; protected provider custody and journal must be provisioned separately.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.credentials.catalogPublication != null;
        message = "aos.sandbox.sourceProvider.credentials.catalogPublication is required";
      }
    ];

    systemd.sockets.aos-source-providerd = {
      description = "AOS RootMount-facing SourceProvider ingress socket";
      wantedBy = ["sockets.target"];
      socketConfig = {
        ListenSequentialPacket = "/run/aos/source-provider/control.sock";
        FileDescriptorName = "aos-source-provider";
        Service = "aos-source-providerd.service";
        PassCredentials = true;
        PassPIDFD = true;
        SocketUser = "root";
        SocketGroup = "root";
        SocketMode = "0600";
        DirectoryMode = "0710";
        RemoveOnStop = true;
      };
    };

    systemd.services.aos-source-providerd = {
      description = "AOS authenticated catalog-currentness SourceProvider";
      requires = ["aos-source-providerd.socket"];
      after = ["aos-source-providerd.socket" "local-fs.target"];
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "simple";
        Sockets = ["aos-source-providerd.socket"];
        ExecStartPre = "${cfg.package}/bin/aos-source-providerd --install-catalog";
        ExecStart = "${cfg.package}/bin/aos-source-providerd";
        LoadCredential = [
          "current-catalog-publication:/run/credentials/@system/${cfg.credentials.catalogPublication}"
        ];
        Restart = "on-failure";
        RestartSec = "2s";
        StateDirectory = "aos/source-provider";
        StateDirectoryMode = "0700";
        UMask = "0077";

        CapabilityBoundingSet = "";
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
        RestrictAddressFamilies = ["AF_UNIX"];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        Slice = "aos-control.slice";
        TasksMax = 32;
      };
    };
  };
}
