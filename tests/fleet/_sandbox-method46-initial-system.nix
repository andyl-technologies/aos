# Selects the real manual units and finite reservations for installed VM tests.
# Callers supply public approval pins; external credentials, existing journal
# history and TPM provisioning remain separate qualification inputs.
{
  lib,
  pkgs,
  systems,
  approvalPublicKeys,
}: let
  funded = import ./_sandbox-funded-system.nix {
    inherit lib pkgs systems;
    includeLifecycleReservations = true;
  };
  parent = funded.config.aos.sandbox.resourceBank.parentEnclosure;
  # Equal quantities become separate named subdivisions in the original M/F
  # compiler. They do not borrow the Source signer's live claim or add a bank.
  # Each manual invocation owns one original operation; its helper processes
  # still consume the copied PID and memory bounds within that same interval.
  receiving = parent.sourceSignerReceiving // {concurrent-operations = 1;};
  sender = parent.sourceSignerSender;
  additionalBacking = 2 * 5 * 1048576;
  floor = purpose: {
    required = true;
    provisionCredential = "qualification-method46-${purpose}-provision";
    indexAuthCredential = "qualification-method46-${purpose}-index-auth";
  };
in
  funded.extendModules {
    modules = [
      {
        # Keep Controller from boot-starting its broker clients before external
        # provisioning. The manual producer must still prove both writers
        # stopped; Storage retains its ordinary socket-activated definition.
        systemd.services.aos-sandboxd.wantedBy = lib.mkForce [];

        aos.sandbox = {
          controllerService.method46TpmFloor = floor "controller";
          hostBroker.credentials = {
            brokerSessionManifest = "qualification-host-broker-manifest";
            brokerSessionHelloKey = "qualification-host-broker-hello";
            brokerSessionOutcomeKey = "qualification-host-broker-outcome";
            rootNoApplyFloorPublicKey = "qualification-root-noapply-public";
          };
          # Normal Root owns the independent signer. Initializers borrow only
          # Host's public pin through their existing closed credential roster.
          policyAuthority.credentials.rootNoApplyFloorSigningKey = "qualification-root-noapply-signing";
          storageBroker = {
            method46TpmFloor = floor "storage";
            credentials = {
              brokerSessionManifest = "qualification-storage-broker-manifest";
              brokerSessionHelloKey = "qualification-storage-broker-hello";
              brokerSessionOutcomeKey = "qualification-storage-broker-outcome";
            };
          };
          method46InitialFloors = lib.genAttrs ["controller" "storage"] (purpose: {
            enable = true;
            approvalPublicKeyCredential = "qualification-method46-${purpose}-approval-public";
            approvalPublicKey = approvalPublicKeys.${purpose};
          });
          resourceBank = {
            policy.components.tmpfs-bytes = lib.mkForce (funded.config.aos.sandbox.resourceBank.policy.components.tmpfs-bytes + additionalBacking);
            parentEnclosure = {
              fixedServices.tmpfs-bytes = lib.mkForce (parent.fixedServices.tmpfs-bytes + additionalBacking);
              method46ControllerInitialReceiving = receiving;
              method46ControllerInitialSender = sender;
              method46StorageInitialReceiving = receiving;
              method46StorageInitialSender = sender;
            };
          };
        };
      }
    ];
  }
