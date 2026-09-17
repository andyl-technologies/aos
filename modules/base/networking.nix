##! modules/base/networking.nix — Network configuration module
##!
##! Declares provider-neutral link, resolver, and hostname policy.
##!
##! Absorbed TOML config values:
##!   [network] hostname, use_dhcp, nameservers, search_domains
##!   [network.interfaces.*] address, gateway, dns
##!   [network.resolved] enable, dnssec
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.networking;
in {
  options.aos.networking = {
    ## System hostname.
    hostName = lib.mkOption {
      type = lib.types.str;
      default = "aos";
      description = "System hostname written to /etc/hostname and converged through the kernel-tunable provider.";
    };

    ## Use DHCP for all Ethernet interfaces by default.
    useDHCP = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Use DHCP for all Ethernet interfaces by default. When true and no
        static interfaces are defined, a catch-all .network file is generated
        that enables DHCP on all en* interfaces.
      '';
    };

    ## Per-interface network configuration.
    ##
    ## # Examples
    ## ```nix
    ## aos.networking.interfaces.eth0 = {
    ##   address = "10.0.0.5/24";
    ##   gateway = "10.0.0.1";
    ## };
    ## ```
    interfaces = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            address = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "Static IPv4/IPv6 address in CIDR notation (e.g. 10.0.0.5/24).";
            };
            gateway = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "Default gateway for this interface.";
            };
            dns = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "DNS server for this interface.";
            };
            matchMACAddress = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Exact MAC address selector, or null to match the interface name.";
            };
          };
        }
      );
      default = {};
      description = ''
        Per-interface network configuration. Each key is the interface name
        (e.g. "eth0", "ens3"). If address is set, static configuration is
        used; otherwise DHCP is used for that interface.
      '';
    };

    ## Global DNS servers for the selected resolver provider.
    nameservers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Global DNS servers for the selected resolver provider.";
    };

    ## DNS search domains.
    search = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "DNS search domains.";
    };

    ## Default MTU for network interfaces (0 = kernel default).
    mtu = lib.mkOption {
      type = lib.types.int;
      default = 0;
      description = ''
        Default MTU for network interfaces. 0 means use the kernel default
        (typically 1500). Set to 9000 for jumbo frames on 10GbE+ networks.
      '';
    };

    ## VLAN interface definitions.
    vlans = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            id = lib.mkOption {
              type = lib.types.int;
              description = "VLAN ID (1-4094).";
            };
            interface = lib.mkOption {
              type = lib.types.str;
              description = "Parent interface for this VLAN (e.g. eth0).";
            };
            address = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "Static address in CIDR notation, or empty for DHCP.";
            };
          };
        }
      );
      default = {};
      description = ''
        VLAN interface definitions. Each key becomes a netdev and network
        link in the selected network provider. Example:
          vlans.vlan100 = { id = 100; interface = "eth0"; address = "10.100.0.5/24"; };
      '';
    };

    ## Bond interface definitions.
    bonds = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            interfaces = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              description = "Member interfaces for this bond.";
            };
            mode = lib.mkOption {
              type = lib.types.str;
              default = "802.3ad";
              description = "Bond mode (802.3ad, active-backup, balance-rr, etc.).";
            };
            address = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "Static address in CIDR notation, or empty for DHCP.";
            };
          };
        }
      );
      default = {};
      description = ''
        Bond interface definitions. Each key becomes a netdev and network
        link in the selected network provider. Example:
          bonds.bond0 = { interfaces = ["eth0" "eth1"]; mode = "802.3ad"; };
      '';
    };

    ## Network tuning sysctl parameters.
    tuning = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = {};
      description = ''
        Network tuning parameters converged through the kernel-tunable
        provider. Example:
          { "net.core.rmem_max" = "16777216"; }
      '';
    };

    resolved = {
      ## Enable provider-managed DNS resolution.
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Enable DNS resolution through the selected network provider.";
      };

      ## DNSSEC validation mode.
      dnssec = lib.mkOption {
        type = lib.types.str;
        default = "allow-downgrade";
        description = ''
          DNSSEC validation mode. Valid values: "yes", "no",
          "allow-downgrade". The default allows DNSSEC when available
          but does not fail if the upstream does not support it.
        '';
      };
    };
  };

  config = {
    system.checks.networking-base = {
      description = "Base networking checks";
      checks =
        [
          {
            name = "loopback-exists";
            description = "Loopback interface exists";
            script = ''
              vm.succeed("test -d /sys/class/net/lo")
            '';
          }
          {
            name = "loopback-up";
            description = "Loopback interface is up";
            script = ''
              assert "unknown" in vm.succeed("cat /sys/class/net/lo/operstate")
            '';
          }
          {
            name = "proc-net";
            description = "/proc/net is available";
            script = ''
              vm.succeed("test -d /proc/net")
            '';
          }
          {
            name = "hostname-file";
            description = "Configured hostname is active";
            script = ''
              vm.succeed("test -f /etc/hostname")
              vm.succeed("test \"$(cat /etc/hostname)\" = \"$(cat /proc/sys/kernel/hostname)\"")
            '';
          }
        ]
        ++ lib.optionals cfg.resolved.enable [
          {
            name = "resolver-configuration";
            description = "libc resolver configuration is populated";
            script = ''
              vm.succeed("test -s /etc/resolv.conf")
            '';
          }
        ];
    };

    # Minimal /etc/protocols so getprotobyname() works. Network configuration
    # itself is rendered only by the selected package-owned provider above.
    environment.etc.protocols.text = ''
      # /etc/protocols — minimal, generated by modules/base/networking.nix
      ip          0       IP       # internet protocol, pseudo protocol number
      icmp        1       ICMP     # internet control message protocol
      igmp        2       IGMP     # Internet Group Management
      ggp         3       GGP      # gateway-gateway protocol
      ipencap     4       IP-ENCAP # IP encapsulated in IP
      tcp         6       TCP      # transmission control protocol
      egp         8       EGP      # exterior gateway protocol
      udp         17      UDP      # user datagram protocol
      ipv6        41      IPv6     # Internet Protocol, version 6
      ipv6-route  43      IPv6-Route
      ipv6-frag   44      IPv6-Frag
      rsvp        46      RSVP     # Reservation Protocol
      gre         47      GRE      # Generic Routing Encapsulation
      esp         50      ESP      # Encap Security Payload
      ah          51      AH       # Authentication Header
      ipv6-icmp   58      IPv6-ICMP # ICMP for IPv6
      ipv6-nonxt  59      IPv6-NoNxt
      ipv6-opts   60      IPv6-Opts
      eigrp       88      EIGRP    # Cisco EIGRP
      ospf        89      OSPFIGP  # Open Shortest Path First
      pim         103     PIM      # Protocol Independent Multicast
      sctp        132     SCTP     # Stream Control Transmission Protocol
      udplite     136     UDPLite  # UDP-Lite
    '';
  };
}
