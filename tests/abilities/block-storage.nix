##! Checks encrypted mapping and storage-format providers through the fixed point.
{lib}: let
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  storageInterfaces = lib.abilities.interfaces.blockStorage.interfaces;
  controllerKey = implementation: providerInstance: key:
    lib.abilities.compositionRequestKey {
      inherit implementation providerInstance key;
    };
  mappingEffects = controllerKey "aos-cryptsetup-provider:encrypted-block-mapping" "aos-cryptsetup-provider:manager" "mapping";
  formatEffects = controllerKey "aos-storage-format-provider:storage-format" "aos-storage-format-provider:manager" "format";
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "block-storage";
            stage = "host";
          };
          bindings = {
            "test:mapping" = {
              request = "consumer:mapping";
              implementation = "aos-cryptsetup-provider:encrypted-block-mapping";
              providerInstance = "aos-cryptsetup-provider:manager";
              slot = "mapping";
            };
            "test:mapping-effects" = {
              request = mappingEffects;
              implementation = "aos-cryptsetup-provider:encrypted-block-mapping-effects";
              providerInstance = "aos-cryptsetup-provider:manager";
              slot = "mapping";
            };
            "test:format" = {
              request = "consumer:format";
              implementation = "aos-storage-format-provider:storage-format";
              providerInstance = "aos-storage-format-provider:manager";
              slot = "format";
            };
            "test:format-effects" = {
              request = formatEffects;
              implementation = "aos-storage-format-provider:storage-format-effects";
              providerInstance = "aos-storage-format-provider:manager";
              slot = "format";
            };
          };
        };
      }
    ];
    packageModules = [
      {
        name = "aos-cryptsetup-provider";
        module.imports = [
          ../../pkgs/security/_aos-cryptsetup-provider-module.nix
          ../../pkgs/security/_encrypted-block-mapping-provider.nix
          {config.aos.abilities.instances.manager = {};}
        ];
      }
      {
        name = "aos-storage-format-provider";
        module.imports = [
          ../../pkgs/tools/_aos-storage-format-provider-module.nix
          ../../pkgs/tools/_storage-format-provider.nix
          {config.aos.abilities.instances.manager = {};}
        ];
      }
      {
        name = "consumer";
        module.imports = [
          {
            config.aos.abilities = lib.mkMerge [
              (serviceManagement.forProducer {
                consumerInstance = "workload";
                key = "mapping";
                interface = storageInterfaces.encryptedMapping;
                parameters = {
                  name = "cryptswap";
                  enabled = true;
                  source = "/dev/disk/by-partlabel/swap";
                  cipher = "aes-xts-plain64";
                  key_size_bits = 256;
                  key.kind = "ephemeral-random";
                  prerequisites = [];
                };
              })
              (serviceManagement.forProducer {
                consumerInstance = "workload";
                key = "format";
                interface = storageInterfaces.storageFormat;
                parameters = {
                  name = "cryptswap";
                  enabled = true;
                  source = "/dev/mapper/cryptswap";
                  format = "swap";
                  policy = "always";
                  prerequisites = [];
                };
              })
              {instances.workload = {};}
            ];
          }
        ];
      }
    ];
  };
  abilities = evaluated.config.aos.abilities;
  resources = builtins.attrValues abilities.desiredResources;
  resourceByKind = kind:
    builtins.head (builtins.filter (resource: resource.kind == kind) resources);
  mapping = resourceByKind "aos.storage.encrypted-block-mapping";
  format = resourceByKind "aos.storage.format";
in
  assert builtins.length resources == 2;
  assert abilities.compositionRequests.${mappingEffects}.parameters == mapping.value;
  assert abilities.compositionRequests.${formatEffects}.parameters == format.value;
  assert mapping.realization.schema == "aos.storage.encrypted-block-mapping-realization/v1";
  assert mapping.realization.cryptsetup.entry_point == "sbin/cryptsetup";
  assert format.realization.schema == "aos.storage.format-realization/v1";
  assert format.realization.mkswap.entry_point == "sbin/mkswap";
  assert format.realization.blkid.entry_point == "sbin/blkid";
  assert abilities.implementations."aos-cryptsetup-provider:encrypted-block-mapping".handlerDescriptor == null;
  assert builtins.isFunction abilities.implementations."aos-cryptsetup-provider:encrypted-block-mapping".transition;
  assert abilities.implementations."aos-cryptsetup-provider:encrypted-block-mapping-effects".providerModule == null;
  assert abilities.implementations."aos-storage-format-provider:storage-format".handlerDescriptor == null;
  assert builtins.isFunction abilities.implementations."aos-storage-format-provider:storage-format".transition;
  assert abilities.implementations."aos-storage-format-provider:storage-format-effects".providerModule == null; true
