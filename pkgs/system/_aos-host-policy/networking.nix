##! Portable link, resolver, hostname, and network-tuning policy.
{lib, ...}: {
  imports = [./network-effects.nix];
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
}
