##! Ordinary module types for platform acquisition and whole-input authorization.
{lib}: let
  field = type: description: lib.mkOption {inherit type description;};
  nullableText = lib.types.nullOr lib.types.str;
  strings = lib.types.listOf lib.types.str;
  moduleType = options: lib.types.submodule {inherit options;};
  platformId = lib.types.enum [
    "aos-metadata"
    "nocloud"
    "config-drive"
    "qemu"
    "aws"
    "gcp"
    "azure"
    "digitalocean"
    "openstack"
    "metal"
    "hyperv"
    "vmware"
    "virtualbox"
  ];
  baseLibrary = moduleType {
    store_path = field lib.types.str "Immutable base module library path.";
    nar_hash = field lib.types.str "Expected exact native module library NAR digest.";
  };
  facts = moduleType {
    hostname = field nullableText "Observed instance hostname.";
    ssh_authorized_keys = field strings "Observed keys without login authorization authority.";
    instance_id = field nullableText "Observed platform instance identity.";
    region = field nullableText "Observed cloud region.";
    availability_zone = field nullableText "Observed availability zone.";
    mac_to_iface = field (lib.types.listOf (moduleType {
      mac = field lib.types.str "Observed interface MAC address.";
      iface = field lib.types.str "Observed kernel interface name.";
    })) "Observed interface bindings.";
    disk_ids = field strings "Observed stable disk identities.";
    network = field (lib.types.nullOr (moduleType {
      mac = field nullableText "Exact static network MAC selector.";
      interface_name = field nullableText "Exact static network interface selector.";
      addresses = field strings "Static CIDR addresses.";
      gateway = field nullableText "Static default gateway.";
      dns = field strings "Static DNS servers.";
    })) "Observed static network configuration.";
  };
  authorization = moduleType {
    trust_mode = field (lib.types.enum ["platform" "signed"]) "Configured metadata authorization policy.";
    platform_id = field platformId "Metadata source platform.";
    signer = field nullableText "Authenticated configuration signer in signed mode.";
  };
in {
  inherit baseLibrary facts platformId;
  platform = moduleType {
    schema = field (lib.types.enum ["aos.metadata.provisioning-platform/v1"]) "Detected platform schema.";
    platform_id = field platformId "Detected metadata source.";
    need_network = field lib.types.bool "Whether acquisition needs early network connectivity.";
  };
  acquired = moduleType {
    schema = field (lib.types.enum ["aos.metadata.acquired-provisioning-input/v1"]) "Acquired metadata schema.";
    platform_id = field platformId "Platform supplying the metadata.";
    host_module = field nullableText "Untrusted exact operator module bytes.";
    host_module_signature = field nullableText "Detached signature over the exact operator module.";
    facts = field facts "Unauthenticated observed instance facts.";
  };
  networkBootstrap = moduleType {
    selector = field (moduleType {
      kind = field (lib.types.enum ["name" "mac"]) "Exact link matching strategy.";
      value = field lib.types.str "Exact interface name or MAC address.";
    }) "Exact early network interface selector.";
    addresses = field strings "Early static CIDR addresses.";
    gateway = field nullableText "Early default gateway.";
    dns = field strings "Early DNS servers.";
  };
  authorizationConfiguration = moduleType {
    schema = field (lib.types.enum ["aos.metadata.provisioning-authorization-configuration/v1"]) "Authorization configuration schema.";
    trust_mode = field (lib.types.enum ["platform" "signed"]) "Required metadata trust policy.";
    trusted_config_keys = field (lib.types.listOf (moduleType {
      kind = field (lib.types.enum ["immutable-file"]) "Immutable trust anchor selection.";
      path = field lib.types.str "Immutable trust anchor file.";
      content_sha256 = field lib.types.str "Digest of the exact trust anchor bytes.";
    })) "Configuration signature verification anchors.";
  };
  authorized = moduleType {
    schema = field (lib.types.enum ["aos.metadata.authorized-provisioning-input/v1"]) "Authorized metadata input schema.";
    source = field (lib.types.enum ["operator" "fallback"]) "Source supplying the provisioning configuration.";
    host_module = field nullableText "Authenticated exact operator module bytes.";
    host_module_sha256 = field nullableText "Digest of the authenticated operator module.";
    authorization = field authorization "Authenticated metadata source decision.";
    facts = field (moduleType {
      schema = field (lib.types.enum ["aos.metadata.observed-instance-facts/v1"]) "Observed facts schema.";
      trust = field (lib.types.enum ["unauthenticated-observational"]) "Explicit absence of authorization authority.";
      value = field facts "Observed instance facts.";
      sha256 = field lib.types.str "Canonical digest of the observed facts.";
    }) "Observed facts carried separately from authorization.";
    base_library = field baseLibrary "Retained module library identity.";
  };
}
