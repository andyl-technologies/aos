##! modules/base/host-facts.nix — Declared host facts (`host.facts.*`)
##!
##! Host-varying inputs available to configuration modules.
##! (hostname, networking-by-MAC, disk IDs, operator SSH keys) enter the
##! pure on-host evaluation **only** as typed config under a privileged-owned
##! `host.facts.*` root — never via `specialArgs` (which is untyped, unmerged,
##! provenance-less, and absent from the manifest). The P1 stock evaluator
##! combines restricted evaluation with an empty process environment and the
##! image-frozen target system, so `getEnv`/ambient `currentSystem` cannot add
##! host data. Facts are therefore the one declared, typed, assertable input
##! that reconciles determinism with per-host variation: evaluation is a pure
##! function of `(modules + host.nix data + facts)`. The resolved `host.facts.*`
##! subtree is what `manifest.inputs.instance_facts.facts_hash` is taken over.
##!
##! This root is a **base-lib-owned shared root**: the base lib declares the
##! schema and merge semantics; the platform fact-gatherer / operator writes
##! the values. All fields are owner-only (no `contributable` marker) — facts
##! are not a foreign-package contribution surface.
##!
##! Pure declaration. Every option carries an inert default, so a system that
##! does not supply facts evaluates unchanged and nothing here is forced
##! unless a consumer reads it. Consumers (networking-by-MAC, disk wiring) and
##! the platform fact-gatherer that populates this root are wired in CS5.
##!
##! ```text
##! host.facts.hostname            = "web-01"
##! host.facts.interfaces."52:54:00:12:34:56" = { names = [ "eth0" ]; addresses = [ "10.0.0.5/24" ]; }
##! host.facts.disks."nvme-eui.0001"          = { device = "/dev/nvme0n1"; }
##! host.facts.ssh_authorized_keys = [ "ssh-ed25519 AAAA… operator@host" ]
##! ```
{
  config,
  lib,
  ...
}: let
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
  ## the stage-2 evaluator. Keeping the complete normalized input here makes
  ## the manifest facts hash sensitive to gateway and DNS changes as well as
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
        default; consumers (e.g. an `authorized_keys` renderer) are wired in
        CS5.
      '';
    };
  };

  # Intentionally no `config` block: this module is pure declaration. Values
  # are supplied by host.nix / the platform fact-gatherer (CS5).
}
