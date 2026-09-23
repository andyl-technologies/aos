##! Provider-neutral Name Service Switch aggregation.
{
  config,
  lib,
  ...
}: let
  cfg = config.aos.nsswitch;
  databaseNames = [
    "passwd"
    "group"
    "shadow"
    "gshadow"
    "hosts"
    "networks"
    "protocols"
    "services"
    "ethers"
    "rpc"
    "netgroup"
  ];
  actionType = lib.types.submodule {
    config._module.strict = true;
    options = {
      action = lib.mkOption {
        type = lib.types.enum ["continue" "merge" "return"];
        description = "NSS dispatcher action for the matched status.";
      };
      negated = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Whether the action matches every status except the named status.";
      };
      status = lib.mkOption {
        type = lib.types.enum ["success" "notfound" "unavail" "tryagain"];
        description = "NSS lookup status that selects this action.";
      };
    };
  };
  sourceType = lib.types.submodule {
    config._module.strict = true;
    options = {
      actions = lib.mkOption {
        type = lib.types.listOf actionType;
        default = [];
        description = "Typed dispatcher actions emitted after this source.";
      };
      database = lib.mkOption {
        type = lib.types.enum databaseNames;
        description = "NSS database receiving this source.";
      };
      order = lib.mkOption {
        type = lib.types.int;
        description = "Stable ascending source order within the database.";
      };
      source = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9_-]+";
        description = "NSS source module name without an nss_ prefix.";
      };
    };
  };
  baseSource = database: source: order: {
    inherit database source order;
    actions = [];
  };
  baseSources = {
    passwd-files = baseSource "passwd" "files" 100;
    group-files = baseSource "group" "files" 100;
    shadow-files = baseSource "shadow" "files" 100;
    gshadow-files = baseSource "gshadow" "files" 100;
    hosts-files = baseSource "hosts" "files" 100;
    hosts-dns = baseSource "hosts" "dns" 400;
    networks-files = baseSource "networks" "files" 100;
    protocols-files = baseSource "protocols" "files" 100;
    services-files = baseSource "services" "files" 100;
    ethers-files = baseSource "ethers" "files" 100;
    rpc-files = baseSource "rpc" "files" 100;
    netgroup-files = baseSource "netgroup" "files" 100;
  };
  actionText = action: "[${lib.optionalString action.negated "!"}${lib.toUpper action.status}=${action.action}]";
  entriesFor = database:
    builtins.sort
    (left: right: left.order < right.order)
    (builtins.filter
      (entry: entry.database == database)
      (builtins.attrValues cfg.sources));
  renderDatabase = database: let
    entries = entriesFor database;
    orders = builtins.map (entry: entry.order) entries;
    tokens =
      builtins.concatMap
      (entry: [entry.source] ++ builtins.map actionText entry.actions)
      entries;
  in
    if builtins.length orders != builtins.length (lib.unique orders)
    then throw "NSS database '${database}' has conflicting source order values"
    else "${database}: ${builtins.concatStringsSep " " tokens}";
in {
  options.aos.nsswitch = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Whether to publish the aggregated NSS database configuration.";
    };
    sources = lib.mkOption {
      type = lib.types.attrsOf sourceType;
      default = {};
      internal = true;
      contributable = true;
      description = "Package-owned typed NSS source definitions.";
    };
  };

  config = lib.mkMerge [
    {aos.nsswitch.sources = baseSources;}
    (lib.mkIf cfg.enable {
      environment.etc."nsswitch.conf".text = ''
        # Generated from typed NSS source definitions. Do not edit.
        ${builtins.concatStringsSep "\n" (builtins.map renderDatabase databaseNames)}
      '';
    })
  ];
}
