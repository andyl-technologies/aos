//! Verifies that downstream controllers can name broker resource snapshots.

#![cfg(target_os = "linux")]

use std::os::fd::OwnedFd;

use aos_sandbox::{
    DurableNetworkResourceInventorySnapshotV1, DurableStorageResourceInventorySnapshotV1,
    NetworkResourceInventoryClient, ResourceInventoryError, ResourceInventoryServiceIdentity,
    ResourceInventorySnapshotOutcomeV1, StorageResourceInventoryClient,
};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::{ValidatedNetworkInventory, ValidatedStorageInventory};

#[test]
fn downstream_code_can_inspect_resource_inventory_snapshots() {
    let storage_client: fn(
        OwnedFd,
        ResourceInventoryServiceIdentity,
    ) -> Result<StorageResourceInventoryClient, ResourceInventoryError> =
        StorageResourceInventoryClient::from_connected;
    let network_client: fn(
        OwnedFd,
        ResourceInventoryServiceIdentity,
    ) -> Result<NetworkResourceInventoryClient, ResourceInventoryError> =
        NetworkResourceInventoryClient::from_connected;
    let storage_outcome: fn(
        &DurableStorageResourceInventorySnapshotV1,
    ) -> ResourceInventorySnapshotOutcomeV1 = DurableStorageResourceInventorySnapshotV1::outcome;
    let network_outcome: fn(
        &DurableNetworkResourceInventorySnapshotV1,
    ) -> ResourceInventorySnapshotOutcomeV1 = DurableNetworkResourceInventorySnapshotV1::outcome;
    let storage_inventory: fn(
        &DurableStorageResourceInventorySnapshotV1,
    ) -> &ValidatedStorageInventory = DurableStorageResourceInventorySnapshotV1::inventory;
    let network_inventory: fn(
        &DurableNetworkResourceInventorySnapshotV1,
    ) -> &ValidatedNetworkInventory = DurableNetworkResourceInventorySnapshotV1::inventory;
    let storage_digest: fn(&DurableStorageResourceInventorySnapshotV1) -> ObjectDigest =
        DurableStorageResourceInventorySnapshotV1::record_digest;
    let network_digest: fn(&DurableNetworkResourceInventorySnapshotV1) -> ObjectDigest =
        DurableNetworkResourceInventorySnapshotV1::record_digest;

    let _ = (
        storage_client,
        network_client,
        storage_outcome,
        network_outcome,
        storage_inventory,
        network_inventory,
        storage_digest,
        network_digest,
    );
}
