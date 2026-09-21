# Evaluation/source contract for the production sandbox controller boundary.
{
  pkgs,
  lib,
}: let
  moduleSource = builtins.readFile ../../modules/sandbox/controller-service.nix;
  hostModuleSource = builtins.readFile ../../modules/sandbox/host-broker.nix;
  runtimeSource = builtins.readFile ../../crates/aos-sandbox-broker-session-security/src/controller_service.rs;
  catalogReconciliationSource =
    builtins.readFile ../../crates/aos-sandbox/src/host_catalog_reconciliation.rs;
  resourceInventorySource =
    builtins.readFile ../../crates/aos-sandbox/src/resource_inventory.rs;
  packageSource = builtins.readFile ../../pkgs/tools/aos-sandboxd.nix;

  requires = fragment: source:
    if lib.hasInfix fragment source
    then true
    else throw "sandbox controller source contract is missing: ${fragment}";
  requiresAbsent = fragment: source:
    if lib.hasInfix fragment source
    then throw "sandbox controller source contract contains forbidden text: ${fragment}"
    else true;

  systemdOptions = {lib, ...}: {
    options.systemd.services = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
    options.systemd.sockets = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
    };
  };
  controllerEvaluation = lib.evalModules {
    specialArgs = {inherit pkgs;};
    modules = [
      systemdOptions
      ({lib, ...}: {
        options.aos.sandbox.controller.uid = lib.mkOption {type = lib.types.int;};
        options.aos.sandbox.controller.gid = lib.mkOption {type = lib.types.int;};
        options.aos.sandbox.hostBroker.enable = lib.mkOption {type = lib.types.bool;};
        options.aos.sandbox.storageBroker.enable = lib.mkOption {type = lib.types.bool;};
        options.aos.sandbox.mountBroker.enable = lib.mkOption {type = lib.types.bool;};
        options.aos.sandbox.networkBroker.enable = lib.mkOption {type = lib.types.bool;};

        config.aos.sandbox = {
          controller = {
            uid = 811;
            gid = 811;
          };
          controllerService = {
            enable = true;
            credentials.nodeId = "sandbox-node-id";
          };
          hostBroker.enable = true;
          storageBroker.enable = true;
          mountBroker.enable = true;
          networkBroker.enable = true;
        };
      })
      ../../modules/sandbox/controller-service.nix
    ];
  };
  controllerServiceConfig =
    controllerEvaluation.config.systemd.services.aos-sandboxd.serviceConfig;

  hostEvaluation = lib.evalModules {
    specialArgs = {inherit pkgs;};
    modules = [
      systemdOptions
      ({lib, ...}: {
        options.aos.sandbox.controller.uid = lib.mkOption {type = lib.types.int;};
        options.aos.sandbox.controller.gid = lib.mkOption {type = lib.types.int;};
        config.aos.sandbox.controller = {
          uid = 811;
          gid = 811;
        };
        config.aos.sandbox.hostBroker.enable = true;
      })
      ../../modules/sandbox/host-broker.nix
    ];
  };
  hostServiceConfig =
    hostEvaluation.config.systemd.services.aos-sandbox-hostd.serviceConfig;
in
  assert controllerServiceConfig.Type == "notify";
  assert controllerServiceConfig.CapabilityBoundingSet == "";
  assert controllerServiceConfig.User == "aos-sandboxd";
  assert controllerServiceConfig.Slice == "aos-control.slice";
  assert controllerServiceConfig.MemoryMax == "512M";
  assert controllerServiceConfig.TimeoutStartSec == "90s";
  assert ! (hostServiceConfig ? Slice);
  assert requires ''LoadCredential = nodeCredentials'' moduleSource;
  assert requires ''aos-sandbox-hostd.service'' moduleSource;
  assert requires ''aos-storaged.service'' moduleSource;
  assert requires ''aos-sandbox-mountd.service'' moduleSource;
  assert requires ''aos-netd.service'' moduleSource;
  assert requiresAbsent ''Slice ='' hostModuleSource;
  assert requires "open_protected_at_for_uid" runtimeSource;
  assert requires "bind_controller_identity" runtimeSource;
  assert requires "validate_current_node" runtimeSource;
  assert requires "production_journal_limits" runtimeSource;
  assert requires "broker_retryability_is_preserved_across_inventory_classification" runtimeSource;
  assert requires "host_publication_retryability_is_preserved_through_reconciliation" runtimeSource;
  assert requires "hostile_publication_and_transport_failures_are_terminal" runtimeSource;
  assert requires "complete_controller_catalog_cycles_reach_a_bounded_reopen_stable_fixed_point" catalogReconciliationSource;
  assert requires "maximum_valid_storage_inventory_does_not_regrow_the_journal" resourceInventorySource;
  assert requires "pending_host_catalog" runtimeSource;
  assert requires "pending_first_read_only_cycle" runtimeSource;
  assert requires "validated_unfinished_operation" runtimeSource;
  assert requires "into_async_authenticated_listener(listener, 0)" runtimeSource;
  assert requires ''/run/aos/sandboxd/diagnostics.sock'' runtimeSource;
  assert requires "root_diagnostic_response_discloses_no_catalog_or_resource_detail" runtimeSource;
  assert requires "durable_first_bind_is_idempotent_after_an_ambiguous_process_exit" runtimeSource;
  assert requires "unbound_preexisting_state_has_no_automatic_identity_migration" runtimeSource;
  assert requires "ErrorCode::Unimplemented" runtimeSource;
  assert requiresAbsent "reconcile_quantum(" runtimeSource;
  assert requiresAbsent "SemanticCapability" runtimeSource;
  assert requiresAbsent "aos.sandbox.controller.observation" runtimeSource;
  assert requires ''--frozen --offline'' packageSource;
  assert requires ''-p aos-sandbox-broker-session-security --bin aos-sandboxd'' packageSource;
  assert requires ''cargoTestFlags = "-p aos-sandbox -p aos-sandbox-broker-session-security"'' packageSource;
    pkgs.mkDerivation {
      pname = "sandbox-controller-service-source-contract";
      version = "0";
      src = null;
      buildDeps = [];
      runtimeDeps = [];
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            echo PASS > "$out/result"
          '';
        }
      ];
    }
