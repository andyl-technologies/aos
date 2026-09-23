##! Canonical typed input authorized for complete configuration evaluation.
{types, ...}: let
  optional = type: {
    inherit type;
    optional = true;
  };
  boundedText = types.string {
    maxLength = 131072;
    syntax = null;
  };
  factText = maxLength:
    types.string {
      inherit maxLength;
      syntax = null;
    };
  staticNetworkFacts = types.record {
    fields = {
      mac = types.optional (factText 32);
      interface_name = types.optional (factText 64);
      addresses = types.list {
        element = factText 128;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      gateway = types.optional (factText 128);
      dns = types.list {
        element = factText 128;
        maxItems = 32;
        unique = true;
        canonicalOrder = true;
      };
    };
  };
  instanceFactsValue = types.record {
    fields = {
      hostname = types.optional (factText 253);
      ssh_authorized_keys = types.list {
        element = factText 16384;
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      instance_id = types.optional (factText 1024);
      region = types.optional (factText 256);
      availability_zone = types.optional (factText 256);
      mac_to_iface = types.list {
        element = types.record {
          fields = {
            mac = factText 32;
            iface = factText 64;
          };
        };
        maxItems = 64;
        unique = true;
        canonicalOrder = true;
      };
      disk_ids = types.list {
        element = factText 512;
        maxItems = 256;
        unique = true;
        canonicalOrder = true;
      };
      network = types.optional staticNetworkFacts;
    };
  };
  observedInstanceFacts = types.record {
    fields = {
      schema = types.enum ["aos.metadata.observed-instance-facts/v1"];
      trust = types.enum ["unauthenticated-observational"];
      value = instanceFactsValue;
      sha256 = types.digest;
    };
  };
  baseLibraryIdentity = types.record {
    fields = {
      store_path = types.executionPath;
      abi_hash = types.digest;
    };
  };
  authorizedInput = types.record {
    fields = {
      schema = types.enum ["aos.metadata.authorized-provisioning-input/v1"];
      source = types.enum ["operator" "fallback"];
      host_module = optional boundedText;
      host_module_sha256 = optional types.digest;
      authorization = types.record {
        fields = {
          trust_mode = types.enum ["platform" "signed"];
          platform_id = types.string {
            maxLength = 128;
            syntax = "local-key-v1";
          };
          signer = optional (types.string {
            maxLength = 512;
            syntax = null;
          });
        };
      };
      facts = observedInstanceFacts;
      base_library = baseLibraryIdentity;
    };
  };
in {
  name = "configurationInput";
  readView.types = {
    inherit
      authorizedInput
      baseLibraryIdentity
      boundedText
      instanceFactsValue
      observedInstanceFacts
      ;
  };
  module = {};
}
