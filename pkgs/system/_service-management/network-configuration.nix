##! Defines typed host networking policy realized by the selected manager.
{lib, ...}: let
  selector = lib.types.submodule {
    options = {
      kind = lib.mkOption {
        type = lib.types.enum ["name" "mac" "ethernet"];
        description = "Link matching strategy.";
      };
      value = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Exact link name or MAC address; Ethernet selectors optionally restrict names with a trailing wildcard.";
      };
    };
  };
  addressing = lib.types.submodule {
    options = {
      link_local = lib.mkOption {
        type = lib.types.enum ["no" "ipv4" "ipv6" "yes"];
        default = "ipv6";
        description = "Link-local address families enabled for this link.";
      };
      ipv4_link_local_route = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Install an on-link route to the IPv4 metadata address range.";
      };
      dhcp = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Acquire addresses through DHCP.";
      };
      dhcp_use_dns = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        description = "Use DHCPv4 DNS servers, or null to retain the manager default.";
      };
      dhcp_use_ntp = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        description = "Use DHCPv4 NTP servers, or null to retain the manager default.";
      };
      dhcp_use_domains = lib.mkOption {
        type = lib.types.nullOr (lib.types.enum ["yes" "no" "route"]);
        default = null;
        description = "Use DHCPv4 search or routing domains, or null to retain the manager default.";
      };
      addresses = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Static addresses including prefix lengths.";
      };
      gateway = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Static default gateway.";
      };
      dns = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Link-specific DNS servers.";
      };
    };
  };
in {
  aos.abilities.network.operations.configure = {
    input.options = {
      mtu = lib.mkOption {
        type = lib.types.ints.between 0 65535;
        default = 0;
        description = "Default link MTU; zero retains the kernel default.";
      };
      authority = lib.mkOption {
        type = lib.types.enum ["image" "operator"];
        description = "Authority supplying the host networking policy.";
      };
      links = lib.mkOption {
        type = lib.types.listOf (lib.types.submodule {
          options = {
            name = lib.mkOption {
              type = lib.types.str;
              description = "Unique managed link identity.";
            };
            kind = lib.mkOption {
              type = lib.types.enum ["ethernet" "vlan" "bond"];
              description = "Managed link kind.";
            };
            selector = lib.mkOption {
              type = lib.types.nullOr selector;
              default = null;
              description = "Physical link selector.";
            };
            parent = lib.mkOption {
              type = lib.types.nullOr selector;
              default = null;
              description = "Parent link for a VLAN.";
            };
            id = lib.mkOption {
              type = lib.types.nullOr (lib.types.ints.between 1 4094);
              default = null;
              description = "VLAN identifier.";
            };
            members = lib.mkOption {
              type = lib.types.listOf selector;
              default = [];
              description = "Physical members of a bond.";
            };
            mode = lib.mkOption {
              type = lib.types.str;
              default = "";
              description = "Bonding policy.";
            };
            addressing = lib.mkOption {
              type = addressing;
              description = "Addressing policy for this link.";
            };
          };
        });
        description = "Managed physical, VLAN, and bond links.";
      };
      resolver = lib.mkOption {
        type = lib.types.submodule {
          options = {
            enabled = lib.mkOption {
              type = lib.types.bool;
              description = "Enable the selected resolver manager.";
            };
            nameservers = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
              description = "Global DNS servers.";
            };
            search = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
              description = "DNS search suffixes.";
            };
            dnssec = lib.mkOption {
              type = lib.types.enum ["allow-downgrade" "no" "yes"];
              description = "Resolver DNSSEC policy.";
            };
          };
        };
        description = "Global resolver policy.";
      };
    };
    result.options.resource = lib.mkOption {
      type = lib.types.str;
      description = "Established host networking resource identity.";
    };
  };
}
