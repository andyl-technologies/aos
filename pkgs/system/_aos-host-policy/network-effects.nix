##! Derives portable native host networking and kernel-tuning effects.
{
  config,
  lib,
  provenance ? null,
  ...
}: let
  cfg = config.aos.networking;
  optionOwners =
    if provenance != null
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
    selector = {
      kind = "ethernet";
      value = "en*";
    };
    addressing = {
      dhcp = true;
      dhcp_use_dns = true;
      dhcp_use_ntp = true;
      dhcp_use_domains = "yes";
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
  networkConfiguration = {
    inherit authority;
    inherit (cfg) mtu;
    links = lib.sort (left: right: left.name < right.name) (
      interfaceLinks ++ defaultLinks ++ vlanLinks ++ bondLinks
    );
    resolver = {
      inherit (cfg.resolved) dnssec;
      nameservers = canonicalStrings cfg.nameservers;
      search = canonicalStrings cfg.search;
      enabled = cfg.resolved.enable;
    };
  };
in {
  config = lib.mkIf ((config.aos.boot.stage or "host") == "host") {
    aos.kernel.sysctl = cfg.tuning // {"kernel.hostname" = cfg.hostName;};
    aos.abilities.network.operations.configure.effects.host.input = networkConfiguration;
  };
}
