##! Checks encrypted mapping and storage-format providers through the fixed point.
{
  lib,
  pkgs,
}: let
  selectedProvider = package: implementation:
    import ./_selected-package-provider.nix {
      inherit lib package implementation;
    };
  selectedCryptsetupProvider = selectedProvider pkgs.aos-cryptsetup-provider "encrypted-block-mapping";
  selectedFormatProvider = selectedProvider pkgs.aos-storage-format-provider "storage-format";
  selectedPoolProvider = selectedProvider pkgs.aos-zfs-provider "storage-pool";
  selectedDatasetProvider = selectedProvider pkgs.aos-zfs-provider "storage-dataset";
  selectedProvisioningProvider = selectedProvider pkgs.aos-storage-provisioning-provider "storage-provisioning";
  systemdSelector = lib.abilities.packageOutput {};
  selectedNetworkProvider = import ./_selected-package-provider.nix {
    inherit lib;
    package = pkgs.systemd;
    implementation = "network-configuration";
    artifactLocators.${builtins.toJSON {
      package = systemdSelector.package;
      output = systemdSelector.output;
    }} = {
      path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-systemd";
      artifactReference = {
        content = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-systemd";
        nar_hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        closure = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
      };
    };
  };
  serviceManagement = lib.abilities.interfaces.serviceManagement;
  storageInterfaces = lib.abilities.interfaces.blockStorage.interfaces;
  storageTypes = lib.abilities.interfaces.blockStorage.types;
  controllerKey = implementation: providerInstance: key:
    lib.abilities.compositionRequestKey {
      inherit implementation providerInstance key;
    };
  mappingEffects = controllerKey "aos-cryptsetup-provider:encrypted-block-mapping" "aos-cryptsetup-provider:manager" "mapping";
  formatEffects = controllerKey "aos-storage-format-provider:storage-format" "aos-storage-format-provider:manager" "format";
  poolEffects = controllerKey "aos-zfs-provider:storage-pool" "aos-zfs-provider:manager" "pool";
  datasetEffects = controllerKey "aos-zfs-provider:storage-dataset" "aos-zfs-provider:manager" "dataset";
  provisioningEffects = controllerKey "aos-storage-provisioning-provider:storage-provisioning" "aos-storage-provisioning-provider:manager" "provisioning";
  provisioningDetection = controllerKey "aos-storage-provisioning-provider:storage-provisioning" "aos-storage-provisioning-provider:manager" "detect-platform-provisioning";
  provisioningAuthorization = controllerKey "aos-storage-provisioning-provider:storage-provisioning" "aos-storage-provisioning-provider:manager" "authorize-input-provisioning";
  provisioningPlan = controllerKey "aos-storage-provisioning-provider:storage-provisioning" "aos-storage-provisioning-provider:manager" "observe-plan-provisioning";
  provisioningNetwork = controllerKey "aos-storage-provisioning-provider:storage-provisioning" "aos-storage-provisioning-provider:manager" "network-readiness-provisioning";
  provisioningNetworkEffects = controllerKey "aos-storage-provisioning-provider:storage-provisioning" "aos-storage-provisioning-provider:manager" "network-configuration-effects-provisioning";
  networkEffects = controllerKey "systemd:network-configuration" "systemd:manager" "host-network";
  evaluated = lib.evalModules {
    inherit lib;
    modules = [
      lib.abilities.module
      ../../modules/systemd/system.nix
      {
        aos.abilities = {
          environment = {
            authority = "test";
            key = "block-storage";
            stage = "host";
          };
          instances = {
            "aos-cryptsetup-provider:manager" = {};
            "aos-storage-format-provider:manager" = {};
            "aos-storage-provisioning-provider:manager" = {};
            "aos-zfs-provider:manager" = {};
            "network-provider:manager" = {};
            "systemd:manager" = {};
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
            "test:pool" = {
              request = "consumer:pool";
              implementation = "aos-zfs-provider:storage-pool";
              providerInstance = "aos-zfs-provider:manager";
              slot = "pool";
            };
            "test:pool-effects" = {
              request = poolEffects;
              implementation = "aos-zfs-provider:storage-pool-effects";
              providerInstance = "aos-zfs-provider:manager";
              slot = "pool";
            };
            "test:dataset" = {
              request = "consumer:dataset";
              implementation = "aos-zfs-provider:storage-dataset";
              providerInstance = "aos-zfs-provider:manager";
              slot = "dataset";
            };
            "test:dataset-effects" = {
              request = datasetEffects;
              implementation = "aos-zfs-provider:storage-dataset-effects";
              providerInstance = "aos-zfs-provider:manager";
              slot = "dataset";
            };
            "test:provisioning" = {
              request = "consumer:provisioning";
              implementation = "aos-storage-provisioning-provider:storage-provisioning";
              providerInstance = "aos-storage-provisioning-provider:manager";
              slot = "provisioning";
            };
            "test:provisioning-effects" = {
              request = provisioningEffects;
              implementation = "aos-storage-provisioning-provider:storage-provisioning-effects";
              providerInstance = "aos-storage-provisioning-provider:manager";
              slot = "provisioning";
            };
            "test:provisioning-detection" = {
              request = provisioningDetection;
              implementation = "aos:storage-provisioning-platform-detector";
              providerInstance = "aos:storage-provisioning-platform-detector";
              slot = "provisioning";
            };
            "test:provisioning-authorization" = {
              request = provisioningAuthorization;
              implementation = "aos:storage-provisioning-input-authorizer";
              providerInstance = "aos:storage-provisioning-input-authorizer";
              slot = "provisioning";
            };
            "test:provisioning-plan" = {
              request = provisioningPlan;
              implementation = "aos:storage-provisioning-plan-observer";
              providerInstance = "aos:storage-provisioning-plan-observer";
              slot = "provisioning";
            };
            "test:provisioning-network" = {
              request = provisioningNetwork;
              implementation = "network-provider:network-readiness";
              providerInstance = "network-provider:manager";
              slot = "network";
            };
            "test:network-configuration" = {
              request = "consumer:host-network";
              implementation = "systemd:network-configuration";
              providerInstance = "systemd:manager";
              slot = "host-network";
            };
            "test:network-effects" = {
              request = networkEffects;
              implementation = "systemd:network-configuration-effects";
              providerInstance = "systemd:manager";
              slot = "host-network";
            };
            "test:provisioning-network-effects" = {
              request = provisioningNetworkEffects;
              implementation = "systemd:network-configuration-effects";
              providerInstance = "systemd:manager";
              slot = "host-network";
            };
          };
        };
      }
    ];
    packageModules = [
      {
        name = "aos-cryptsetup-provider";
        inherit (pkgs.aos-cryptsetup-provider) version;
        module = pkgs.aos-cryptsetup-provider.module + "/module.nix";
      }
      {
        name = "aos-storage-format-provider";
        inherit (pkgs.aos-storage-format-provider) version;
        module = pkgs.aos-storage-format-provider.module + "/module.nix";
      }
      {
        name = "aos";
        version = pkgs.aos.version;
        module = pkgs.aos.module + "/module.nix";
      }
      {
        name = "network-provider";
        module = {lib, ...}: let
          network = lib.abilities.interfaces.serviceManagement.interfaces.networkReadiness;
        in {
          config.aos.abilities = {
            implementations.network-readiness = {
              description = "Provides the test's exact configured-network observation.";
              interface = "network-readiness";
              artifact = lib.abilities.packageOutput {};
              inherit (network) methods;
              guarantees = [];
              handlerDescriptor = null;
              providerModule = null;
              desiredType = null;
              requiredFeatures = [];
              provide = {
                instance,
                requests,
                ...
              }: {
                requests = {};
                resourceFragments = {};
                outputs = builtins.mapAttrs (_: _: {
                  readiness-resource = {
                    interface = network.identity;
                    resource = {
                      provider = instance.id;
                      key = "network-online";
                    };
                    operations = ["observe"];
                    lifetime = "instance";
                  };
                }) requests;
              };
            };
            instances.manager.implementation = "network-readiness";
          };
        };
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
                key = "provisioning";
                interface = storageInterfaces.provisioning;
                methods = ["commit" "observe"];
                parameters = {
                  name = "first-boot";
                  enabled = true;
                  root_device = "/dev/disk/by-partlabel/root-a";
                  measured_boot = false;
                  policy = {
                    initialize = "if-unprovisioned";
                    committed_divergence = "require-factory-reset";
                  };
                  prerequisites = [];
                };
              })
              (serviceManagement.forProducer {
                consumerInstance = "workload";
                key = "pool";
                interface = storageInterfaces.pool;
                parameters = {
                  name = "pool";
                  enabled = true;
                  pool = "aos-pool";
                  import_policy = "force";
                  properties = {};
                  prerequisites = [];
                };
              })
              (serviceManagement.forProducer {
                consumerInstance = "workload";
                key = "dataset";
                interface = storageInterfaces.dataset;
                parameters = {
                  name = "dataset";
                  enabled = true;
                  pool = "aos-pool";
                  dataset = "var/log";
                  mountpoint = "/var/log";
                  mount_options = ["nodev" "nosuid"];
                  properties = {compression = "zstd-3";};
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
              (serviceManagement.forProducer {
                consumerInstance = "workload";
                key = "host-network";
                interface = lib.abilities.interfaces.networkConfiguration.interface;
                methods = ["apply" "observe" "remove"];
                parameters = {
                  authority = "image";
                  links = [];
                  resolver = {
                    enabled = false;
                    nameservers = [];
                    search = [];
                    dnssec = "allow-downgrade";
                  };
                  prerequisites = [];
                };
              })
              {instances.workload = {};}
            ];
          }
        ];
      }
      {
        name = "aos-zfs-provider";
        inherit (pkgs.aos-zfs-provider) version;
        module = pkgs.aos-zfs-provider.module + "/module.nix";
      }
      {
        name = "aos-storage-provisioning-provider";
        inherit (pkgs.aos-storage-provisioning-provider) version;
        module = pkgs.aos-storage-provisioning-provider.module + "/module.nix";
      }
      {
        name = "systemd";
        inherit (pkgs.systemd) version;
        module = pkgs.systemd.module + "/module.nix";
      }
    ];
    selectedProviderModules = [
      selectedCryptsetupProvider
      selectedFormatProvider
      selectedPoolProvider
      selectedDatasetProvider
      selectedProvisioningProvider
      selectedNetworkProvider
    ];
    specialArgs = {
      inherit pkgs;
      provenance = {
        dependencyOwnersOfAttr = _: _: [];
        ownerOfListAttr = _: _: _: "@test";
      };
    };
  };
  abilities = evaluated.config.aos.abilities;
  resources = builtins.attrValues abilities.desiredResources;
  resourceByKind = kind:
    builtins.head (builtins.filter (resource: resource.kind == kind) resources);
  mapping = resourceByKind "aos.storage.encrypted-block-mapping";
  format = resourceByKind "aos.storage.format";
  pool = resourceByKind "aos.storage.pool";
  dataset = resourceByKind "aos.storage.dataset";
  provisioning = resourceByKind "aos.storage.provisioning";
  hostNetwork = resourceByKind "aos.network.configuration";
  interfaceIdentity = name: let
    matches = builtins.filter (entry: entry.name == name) (builtins.attrValues abilities.interfaces);
  in
    (builtins.head matches).identity;
  authorizedBinding = {
    id,
    request,
    interface,
    method,
    resource,
    access,
  }: {
    authority.role = "desired";
    binding = {
      inherit id interface;
      request = {
        consumer = provisioning.resource.provider;
        key = request;
      };
      caller_grant = {
        methods = [method];
        resources = [
          {
            inherit resource access;
            operations = [method];
          }
        ];
      };
    };
  };
  transition = abilities.implementations."aos-storage-provisioning-provider:storage-provisioning".transition;
  transitionFor = authority:
    transition {
      provider = provisioning.resource.provider;
      operation_scope = ["storage-provisioning"];
      before.resources = [];
      after.resources = [
        provisioning
        (hostNetwork // {value = hostNetwork.value // {inherit authority;};})
      ];
      changes = [
        {
          kind = "create";
          inherit (provisioning) resource;
          current = null;
          desired = null;
        }
      ];
      authorized_bindings = [
        (authorizedBinding {
          id = "detect-platform";
          request = "detect-platform-${provisioning.resource.key}";
          interface = interfaceIdentity "aos.metadata.storage-provisioning-platform-detection";
          method = "detect";
          resource = provisioning.resource;
          access = "read";
        })
        (authorizedBinding {
          id = "authorize-input";
          request = "authorize-input-${provisioning.resource.key}";
          interface = interfaceIdentity "aos.metadata.storage-provisioning-input-authorization";
          method = "authorize";
          resource = provisioning.resource;
          access = "exclusive-write";
        })
        (authorizedBinding {
          id = "observe-plan";
          request = "observe-plan-${provisioning.resource.key}";
          interface = interfaceIdentity "aos.metadata.storage-provisioning-plan";
          method = "observe";
          resource = provisioning.resource;
          access = "exclusive-write";
        })
        (authorizedBinding {
          id = "storage-effects";
          request = provisioning.resource.key;
          interface = storageInterfaces.provisioning.effects.identity;
          method = "commit";
          resource = provisioning.resource;
          access = "exclusive-write";
        })
        (authorizedBinding {
          id = "network-readiness";
          request = "network-readiness-${provisioning.resource.key}";
          interface = serviceManagement.interfaces.networkReadiness.identity;
          method = "observe";
          resource = {
            provider = "network-provider:manager";
            key = "network";
          };
          access = "read";
        })
        (authorizedBinding {
          id = "network-configuration-effects";
          request = "network-configuration-effects-${provisioning.resource.key}";
          interface = lib.abilities.interfaces.networkConfiguration.interface.effects.identity;
          method = "apply";
          resource = hostNetwork.resource;
          access = "exclusive-write";
        })
      ];
      controllers = [
        {
          inherit (provisioning) resource;
          controller = {
            provider = provisioning.resource.provider;
            group = "storage-provisioning";
          };
        }
      ];
    };
  imageTransition = transitionFor "image";
  operatorTransition = transitionFor "operator";
  operationByKey = transitionFragment: key:
    builtins.head (builtins.filter (operation: operation.key.key == key) transitionFragment.operations);
  imageNetworkApply = operationByKey imageTransition "apply-network-bootstrap-${provisioning.resource.key}";
  operatorNetworkApply = operationByKey operatorTransition "apply-network-bootstrap-${provisioning.resource.key}";
  bootstrapEdge = edge:
    edge.from.kind == "merge"
    && edge.from.key.key == "authorized-input-${provisioning.resource.key}"
    && edge.to.kind == "operation"
    && edge.to.key.key == "apply-network-bootstrap-${provisioning.resource.key}"
    && edge.kind == "data";
in
  assert builtins.length resources == 6;
  assert abilities.compositionRequests.${mappingEffects}.parameters == mapping.value;
  assert abilities.compositionRequests.${formatEffects}.parameters == format.value;
  assert mapping.realization.schema == "aos.storage.encrypted-block-mapping-realization/v1";
  assert mapping.realization.cryptsetup.entry_point == "sbin/cryptsetup";
  assert format.realization.schema == "aos.storage.format-realization/v1";
  assert format.realization.mkswap.entry_point == "sbin/mkswap";
  assert format.realization.blkid.entry_point == "sbin/blkid";
  assert abilities.compositionRequests.${poolEffects}.parameters == pool.value;
  assert abilities.compositionRequests.${datasetEffects}.parameters == dataset.value;
  assert pool.realization.zpool.entry_point == "sbin/zpool";
  assert dataset.realization.zfs.entry_point == "sbin/zfs";
  assert abilities.compositionRequests.${provisioningEffects}.parameters == provisioning.value;
  assert abilities.compositionRequests.${provisioningNetworkEffects}.parameters == {};
  assert hostNetwork.value.authority == "image";
  assert imageNetworkApply.inputs.fields.bootstrap == {
    source = "operation-result";
    reference = {
      producer = {
        kind = "merge";
        key = {
          scope = ["storage-provisioning"];
          key = "authorized-input-${provisioning.resource.key}";
        };
      };
      output = "network-bootstrap";
    };
  };
  assert builtins.length (builtins.filter bootstrapEdge imageTransition.edges) == 1;
  assert operatorNetworkApply.inputs.fields.bootstrap == {
    source = "literal";
    value = null;
  };
  assert builtins.length (builtins.filter bootstrapEdge operatorTransition.edges) == 0;
  assert provisioning.realization.systemd_repart.entry_point == "bin/systemd-repart";
  assert provisioning.realization.sfdisk.entry_point == "sbin/sfdisk";
  assert !storageTypes.stableDevice.check "/dev/sda";
  assert !storageTypes.partitionType.check "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
  assert abilities.implementations."aos-cryptsetup-provider:encrypted-block-mapping".handlerDescriptor == null;
  assert builtins.isFunction abilities.implementations."aos-cryptsetup-provider:encrypted-block-mapping".transition;
  assert abilities.implementations."aos-cryptsetup-provider:encrypted-block-mapping-effects".providerModule == null;
  assert abilities.implementations."aos-storage-format-provider:storage-format".handlerDescriptor == null;
  assert builtins.isFunction abilities.implementations."aos-storage-format-provider:storage-format".transition;
  assert abilities.implementations."aos-storage-format-provider:storage-format-effects".providerModule == null;
  assert abilities.implementations."aos-zfs-provider:storage-pool".handlerDescriptor == null;
  assert abilities.implementations."aos-zfs-provider:storage-dataset".handlerDescriptor == null;
  assert abilities.implementations."aos-zfs-provider:storage-pool-effects".providerModule == null;
  assert abilities.implementations."aos-zfs-provider:storage-dataset-effects".providerModule == null;
  assert abilities.implementations."aos-storage-provisioning-provider:storage-provisioning".handlerDescriptor == null;
  assert abilities.implementations."aos-storage-provisioning-provider:storage-provisioning-effects".providerModule == null;
  assert abilities.implementations."aos:storage-provisioning-platform-detector".handlerDescriptor.entryPoint
  == "libexec/aos-storage-provisioning-platform-detector";
  assert abilities.implementations."aos:storage-provisioning-input-authorizer".handlerDescriptor.entryPoint
  == "libexec/aos-storage-provisioning-input-authorizer";
  assert abilities.implementations."aos:storage-provisioning-plan-observer".handlerDescriptor.entryPoint
  == "libexec/aos-storage-provisioning-plan-observer";
  assert abilities.implementations."aos:storage-provisioning-configuration-evaluator".handlerDescriptor.entryPoint
  == "libexec/aos-storage-provisioning-configuration-evaluator"; true
