##! Declares observational host facts shared by metadata and native source replay.
##!
##! Facts are typed configuration inputs, never authorization. The metadata
##! provider and operator modules contribute values through this canonical
##! declaration; retained module sources replay without image build options.
{lib, ...}: let
  inherit (lib) mkOption types;

  ## One network interface, keyed by MAC address. The attrset key is the
  ## canonical MAC and is injected as the submodule `name`, so `mac` defaults
  ## to the key — interfaces are identified by hardware address, stable across
  ## kernel link-name reordering.
  interfaceType = types.submodule ({name, ...}: {
    options = {
      mac = mkOption {
        type = types.nonEmptyStr;
        default = name;
        defaultText = "‹the attribute name›";
        description = "Canonical MAC address of the interface (the attrset key).";
      };
      names = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "Kernel link names observed for this MAC (e.g. `eth0`, `enp1s0`).";
      };
      addresses = mkOption {
        type = types.listOf types.str;
        default = [];
        description = "CIDR addresses assigned to the interface, as gathered on the host.";
      };
    };
  });

  ## One block device, keyed by stable disk id (`/dev/disk/by-id/<id>`).
  diskType = types.submodule ({name, ...}: {
    options = {
      id = mkOption {
        type = types.nonEmptyStr;
        default = name;
        defaultText = "‹the attribute name›";
        description = "Stable disk identifier (the attrset key, e.g. a `by-id` name).";
      };
      device = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Kernel device node the id resolved to at gather time, if known.";
      };
    };
  });

  ## Metadata-delivered static network facts used only to bootstrap a route to
  ## the native evaluator. Keeping the complete normalized input here makes
  ## the recorded facts digest sensitive to gateway and DNS changes as well as
  ## interface addresses.
  staticNetworkType = types.submodule {
    options = {
      mac = mkOption {
        type = types.nullOr types.nonEmptyStr;
        default = null;
        description = "Canonical MAC selector reported by platform metadata.";
      };
      interface_name = mkOption {
        type = types.nullOr types.nonEmptyStr;
        default = null;
        description = "Explicit kernel interface selector used when no MAC was reported.";
      };
      addresses = mkOption {
        type = types.listOf types.nonEmptyStr;
        default = [];
        description = "Static CIDR addresses reported by platform metadata.";
      };
      gateway = mkOption {
        type = types.nullOr types.nonEmptyStr;
        default = null;
        description = "Default gateway reported by platform metadata.";
      };
      dns = mkOption {
        type = types.listOf types.nonEmptyStr;
        default = [];
        description = "DNS server addresses reported by platform metadata.";
      };
    };
  };
in {
  options.host.facts = {
    hostname = mkOption {
      type = types.nonEmptyStr;
      default = "localhost";
      description = ''
        The host's hostname, supplied as a declared fact (from `host.nix` or
        the platform fact-gatherer). A non-empty string; inert default keeps
        a fact-less evaluation valid.
      '';
    };

    instance_id = mkOption {
      type = types.nullOr types.nonEmptyStr;
      default = null;
      description = "Opaque platform instance identifier, when reported by metadata.";
    };

    region = mkOption {
      type = types.nullOr types.nonEmptyStr;
      default = null;
      description = "Cloud region reported by the platform metadata service.";
    };

    availability_zone = mkOption {
      type = types.nullOr types.nonEmptyStr;
      default = null;
      description = "Cloud availability zone reported by the platform metadata service.";
    };

    interfaces = mkOption {
      type = types.attrsOf interfaceType;
      default = {};
      description = ''
        Network interfaces keyed by MAC address. The key is injected as each
        submodule's `name`. Empty by default (no facts gathered yet).
      '';
    };

    static_network = mkOption {
      type = types.nullOr staticNetworkType;
      default = null;
      description = ''
        Normalized metadata-delivered static networking used for DHCP-less
        bootstrap. This is a recorded fact, never an authorization decision.
      '';
    };

    disks = mkOption {
      type = types.attrsOf diskType;
      default = {};
      description = ''
        Block devices keyed by stable disk id. The key is injected as each
        submodule's `name`. Empty by default.
      '';
    };

    ssh_authorized_keys = mkOption {
      type = types.listOf types.str;
      default = [];
      description = ''
        Operator SSH public keys delivered as a declared host fact. Empty by
        default; consumers render keys from this declared input.
      '';
    };
  };

  # Intentionally no `config` block: this module is pure declaration. Values
  # are supplied by host.nix or the platform fact-gatherer.
}
