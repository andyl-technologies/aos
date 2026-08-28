##! Typed runtime configuration for the package-owned conntrackd daemon.
{
  config,
  lib,
  ...
}: let
  cfg = config.conntrackd;
  inherit (lib) mkOption types;
  positiveInt = types.addCheck types.int (value: value > 0);
  onOff = value:
    if value
    then "on"
    else "off";
  syncConfig = lib.optionalString (cfg.mode == "sync") ''
    Sync {
      Mode FTFW {
        ResendQueueSize ${toString cfg.sync.resendQueueSize}
        ACKWindowSize ${toString cfg.sync.ackWindowSize}
      }
      UDP {
        IPv4_address ${cfg.sync.localAddress}
        IPv4_Destination_Address ${cfg.sync.peerAddress}
        Port ${toString cfg.sync.port}
        Interface ${cfg.sync.interface}
        Checksum ${onOff cfg.sync.checksum}
      }
    }
  '';
  statsConfig = lib.optionalString (cfg.mode == "stats") ''
    Stats {
      LogFile ${onOff cfg.logConnections}
    }
  '';
  rendered = ''
    General {
      Systemd on
      HashSize ${toString cfg.hashSize}
      HashLimit ${toString cfg.hashLimit}
      LockFile /run/aos-pkg-conntrackd/conntrackd.lock
      UNIX {
        Path /run/aos-pkg-conntrackd/conntrackd.ctl
      }
      NetlinkBufferSize ${toString cfg.netlinkBufferSize}
      NetlinkBufferSizeMaxGrowth ${toString cfg.netlinkBufferSizeMaxGrowth}
      ${lib.optionalString (cfg.pollSeconds != null) "PollSecs ${toString cfg.pollSeconds}"}
      LogFile /var/log/conntrackd/conntrackd.log
    }
    ${statsConfig}
    ${syncConfig}
  '';
in {
  options.conntrackd = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable the package-owned connection tracking daemon.";
    };
    mode = mkOption {
      type = types.enum ["stats" "sync"];
      default = "stats";
      description = "Run as a local statistics collector or an FTFW state replicator.";
    };
    hashSize = mkOption {
      type = positiveInt;
      default = 8192;
      description = "Number of daemon cache hash buckets.";
    };
    hashLimit = mkOption {
      type = positiveInt;
      default = 65535;
      description = "Maximum number of tracked connections in daemon caches.";
    };
    netlinkBufferSize = mkOption {
      type = positiveInt;
      default = 262142;
      description = "Initial netlink receive buffer size in bytes.";
    };
    netlinkBufferSizeMaxGrowth = mkOption {
      type = positiveInt;
      default = 655355;
      description = "Maximum dynamically grown netlink buffer size in bytes.";
    };
    pollSeconds = mkOption {
      type = types.nullOr positiveInt;
      default = null;
      description = "Optional kernel conntrack polling interval.";
    };
    logConnections = mkOption {
      type = types.bool;
      default = false;
      description = "Log destroyed connections in statistics mode.";
    };
    sync = {
      localAddress = mkOption {
        type = types.strMatching "[0-9]{1,3}(\\.[0-9]{1,3}){3}";
        default = "127.0.0.1";
        description = "Local IPv4 address of the dedicated replication link.";
      };
      peerAddress = mkOption {
        type = types.strMatching "[0-9]{1,3}(\\.[0-9]{1,3}){3}";
        default = "127.0.0.1";
        description = "Peer IPv4 address receiving replicated state.";
      };
      interface = mkOption {
        type = types.strMatching "[A-Za-z0-9][A-Za-z0-9_.:-]*";
        default = "lo";
        description = "Dedicated replication network interface.";
      };
      port = mkOption {
        type = types.port;
        default = 3780;
        description = "UDP replication port.";
      };
      checksum = mkOption {
        type = types.bool;
        default = true;
        description = "Verify checksums on state replication messages.";
      };
      resendQueueSize = mkOption {
        type = positiveInt;
        default = 131072;
        description = "Maximum FTFW resend queue length.";
      };
      ackWindowSize = mkOption {
        type = positiveInt;
        default = 300;
        description = "FTFW acknowledgement window size.";
      };
    };
  };

  config = {
    assertions = [
      {
        assertion = cfg.hashLimit >= cfg.hashSize;
        message = "conntrackd.hashLimit must be at least conntrackd.hashSize";
      }
      {
        assertion = cfg.mode != "sync" || cfg.sync.localAddress != cfg.sync.peerAddress;
        message = "conntrackd sync localAddress and peerAddress must differ";
      }
    ];
    conntrackd.config.runtime.CONNTRACKD_ENABLED = cfg.enable;
    environment.etc."aos/packages/conntrackd/conntrackd.conf" = {
      text = rendered;
      mode = "0444";
    };
  };
}
