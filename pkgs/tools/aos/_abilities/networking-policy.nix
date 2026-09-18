##! Package-owned host networking and kernel-tuning requests.
{
  config,
  lib,
  options,
  provenance,
  ...
}: let
  cfg =
    lib.attrByPath ["aos" "networking"] {
      hostName = "aos";
      useDHCP = true;
      interfaces = {};
      nameservers = [];
      search = [];
      mtu = 0;
      vlans = {};
      bonds = {};
      tuning = {};
      resolved = {
        enable = true;
        dnssec = "allow-downgrade";
      };
    }
    config;
  configured =
    config.aos.abilities.environment
    != null
    && config.aos.abilities.environment.stage == "host";
  consumerInstance = "networking";
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  kernelTunables = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "network-tunables";
    interface = {
      alias = lib.abilities.interfaces.kernelTunables.interface.alias;
      declaration = lib.abilities.interfaces.kernelTunables.interface.declaration;
    };
    methods = ["apply" "observe" "remove"];
    parameters = {
      values = cfg.tuning // {"kernel.hostname" = cfg.hostName;};
      dependencies = [];
    };
  };
  networkInterface = lib.abilities.interfaces.networkConfiguration.interface;
  networkOptionsDeclared = lib.hasAttrByPath ["aos" "networking" "useDHCP"] options;
  optionOwners =
    if configured && networkOptionsDeclared
    then
      builtins.map provenance.ownerOfOption [
        ["aos" "networking" "useDHCP"]
        ["aos" "networking" "interfaces"]
        ["aos" "networking" "nameservers"]
        ["aos" "networking" "search"]
        ["aos" "networking" "mtu"]
        ["aos" "networking" "vlans"]
        ["aos" "networking" "bonds"]
        ["aos" "networking" "resolved" "enable"]
        ["aos" "networking" "resolved" "dnssec"]
      ]
    else [];
  authority =
    if builtins.elem "@host" optionOwners
    then "operator"
    else "image";
  canonicalStrings = values: lib.unique (lib.sort builtins.lessThan values);
  addressing = value:
    {
      dhcp = value.address == "";
      addresses = lib.optional (value.address != "") value.address;
      dns = lib.optional ((value.dns or "") != "") value.dns;
    }
    // lib.optionalAttrs ((value.gateway or "") != "") {gateway = value.gateway;};
  namedSelector = value: {
    kind = "name";
    inherit value;
  };
  interfaceLinks =
    lib.mapAttrsToList (name: value: {
      kind = "ethernet";
      inherit name;
      selector =
        if value.matchMACAddress == null
        then namedSelector name
        else {
          kind = "mac";
          value = value.matchMACAddress;
        };
      addressing = addressing value;
    })
    cfg.interfaces;
  defaultLinks = lib.optional (cfg.useDHCP && cfg.interfaces == {}) {
    kind = "ethernet";
    name = "default-dhcp";
    selector.kind = "ethernet";
    addressing = {
      dhcp = true;
      addresses = [];
      dns = [];
    };
  };
  vlanLinks =
    lib.mapAttrsToList (name: value: {
      kind = "vlan";
      inherit name;
      parent = namedSelector value.interface;
      inherit (value) id;
      addressing = addressing (value
        // {
          dns = "";
          gateway = "";
        });
    })
    cfg.vlans;
  bondLinks =
    lib.mapAttrsToList (name: value: {
      kind = "bond";
      inherit name;
      members = builtins.map namedSelector (canonicalStrings value.interfaces);
      inherit (value) mode;
      addressing = addressing (value
        // {
          dns = "";
          gateway = "";
        });
    })
    cfg.bonds;
  networkConfiguration = serviceManagement.forProducer {
    inherit consumerInstance;
    key = "host-network";
    interface = networkInterface;
    methods = ["apply" "observe" "remove"];
    parameters = {
      inherit authority;
      links = lib.sort (left: right: left.name < right.name) (
        interfaceLinks ++ defaultLinks ++ vlanLinks ++ bondLinks
      );
      resolver = {
        inherit (cfg.resolved) dnssec;
        nameservers = canonicalStrings cfg.nameservers;
        search = canonicalStrings cfg.search;
        enabled = cfg.resolved.enable;
      };
      prerequisites = [];
    };
  };
  contributions = builtins.map serviceManagement.splitContribution [
    kernelTunables
    networkConfiguration
  ];
in {
  config = lib.mkMerge [
    {aos.abilities = lib.mkMerge (builtins.map (entry: entry.declarations) contributions);}
    (lib.mkIf configured {
      aos.abilities = lib.mkMerge (
        [{instances.${consumerInstance} = {};}]
        ++ builtins.map (entry: entry.configured) contributions
      );
    })
  ];
}
