//! Commits complete actual inventory preimages as passive Delete comparison DATA.
//!
//! The caller supplies actual retained native/protected coordinates and models.
//! Root must independently verify the signed packet pair, endpoint, challenge
//! and native/currentness conjunction before comparing this same hash. Calling
//! this pure kernel or decoding a cut never constructs a native or six-owner loan.

use aos_sandbox_api::aos::sandbox::local::v1::BrokerMethod;
use sha2::{Digest as _, Sha256};
use crate::authenticated_session::all_methods::{AuthenticatedBrokerMethodOutcomeV1,
    AuthenticatedBrokerOutcomeDirectionV1, AuthenticatedBrokerRequestDirectionV1,
    AuthenticatedBrokerMethodResultV1};
use super::super::delete_batch::{DeleteBatchNativeBoundaryDataV2, DeleteBatchOwnerCutDataV2};
use super::super::lifecycle_model::LifecycleModelError;

/// Returns the sole fixed Inventory method for one canonical Delete broker role.
///
/// This compares DATA only; it cannot construct a Session or native owner.
///
/// # Errors
/// Refuses roles outside Runtime1, Mount2, Storage3 and Network4.
pub fn delete_inventory_method_for_role_data_v2(role: u8) -> Result<BrokerMethod, LifecycleModelError> {
    Ok(match role {
            1 => BrokerMethod::BROKER_METHOD_HOST_INVENTORY_RUNTIME,
            2 => BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS,
            3 => BrokerMethod::BROKER_METHOD_STORAGE_INVENTORY_RESOURCES,
            4 => BrokerMethod::BROKER_METHOD_NETWORK_INVENTORY_RESOURCES,
            _ => return Err(LifecycleModelError::InvalidModel),
        })
}

/// Borrows every canonical preimage of one complete actual broker inventory.
///
/// This public model is DATA; it cannot stand in for any live original. Native
/// and protected generations have separate fields and meanings throughout.
#[doc(hidden)]
pub struct DeleteSessionInventoryCutDataV2<'data> {
    /// Names the canonical lifecycle Runtime1/Mount2/Storage3/Network4 role.
    pub role: u8,
    /// Borrows the complete verified signed request/outcome and method model.
    pub outcome: &'data AuthenticatedBrokerMethodOutcomeV1,
    /// Gives the actual retained Session context kernel boot.
    pub kernel_boot: [u8; 16],
    /// Gives the actual held Session journal NEXT/device/inode/durable byte end.
    pub native: (u64, u64, u64, u64),
    /// Gives the actual confirmed protected CAS generation and complete head.
    pub protected: (u64, [u8; 32]),
    /// Gives the sole complete physical model's generation and commitment.
    pub inventory: (u64, [u8; 32]),
    /// Counts all rows in that same complete selected physical model.
    pub count: u32,
}

impl DeleteSessionInventoryCutDataV2<'_> {
    /// Hashes the full canonical preimage without allocating or granting custody.
    ///
    /// The exact signed packets remain borrowed throughout. Each length and
    /// numeric coordinate has one fixed big-endian encoding and domain tag.
    ///
    /// # Errors
    /// Refuses a cross-role/method/direction pair, missing boot/generation/head,
    /// invalid native NEXT/inode/end or unrepresentable packet length.
    pub fn owner_cut_data_v2(&self) -> Result<DeleteBatchOwnerCutDataV2, LifecycleModelError> {
        let expected = delete_inventory_method_for_role_data_v2(self.role)?;
        if self.outcome.method() != expected
            || self.outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
            || self.outcome.request().method() != expected
            || self.outcome.request().direction() != AuthenticatedBrokerRequestDirectionV1::ClientSend
            || !matches!(self.outcome.result(), AuthenticatedBrokerMethodResultV1::Success { .. })
            || self.kernel_boot == [0; 16] || self.native.0 == 0 || self.native.0 == u64::MAX
            || self.native.2 == 0 || self.native.3 == 0
            || self.protected.0 == 0 || self.protected.1 == [0; 32]
            || self.inventory.0 == 0 || self.inventory.1 == [0; 32] {
            return Err(LifecycleModelError::InvalidModel);
        }
        let request = self.outcome.request().canonical_packet();
        let outcome = self.outcome.canonical_packet();
        let request_len = u64::try_from(request.len()).map_err(|_| LifecycleModelError::InvalidModel)?;
        let outcome_len = u64::try_from(outcome.len()).map_err(|_| LifecycleModelError::InvalidModel)?;
        let hash = Sha256::new()
            .chain_update(b"aos.sandbox.delete.complete-session-inventory-cut.v2\0")
            .chain_update([self.role]).chain_update(self.kernel_boot)
            .chain_update(self.native.0.to_be_bytes()).chain_update(self.native.1.to_be_bytes())
            .chain_update(self.native.2.to_be_bytes()).chain_update(self.native.3.to_be_bytes())
            .chain_update(self.protected.0.to_be_bytes()).chain_update(self.protected.1)
            .chain_update(self.inventory.0.to_be_bytes()).chain_update(self.inventory.1)
            .chain_update(self.count.to_be_bytes())
            .chain_update(request_len.to_be_bytes()).chain_update(request)
            .chain_update(outcome_len.to_be_bytes()).chain_update(outcome)
            .finalize().into();
        Ok(DeleteBatchOwnerCutDataV2 {
            boundary: DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence: self.native.0 },
            count: self.count, digest: hash,
        })
    }
}

/// Hashes the full protected Cache reduction and all five actual native prefixes.
///
/// Writers have the fixed Source/Hold/State/Authority/Clock order. The owner
/// descriptor's journal boundary is the State writer's actual NEXT; all five
/// name/NEXT/end preimages remain in its digest. Rows are the sole complete
/// actionable Cache reducer's canonical resource/identity order; the separate
/// full reduction root commits every historical record, including inactive rows.
/// This function is passive DATA and provides no authority or absence proof.
///
/// # Errors
/// Refuses empty nonce/cutoff/root, malformed historical native names/NEXT,
/// invalid/duplicate/unsorted rows, changed iterator length or count overflow.
pub fn cache_inventory_cut_data_v2(
    writers: &[super::super::create_storage_history::cache_held::CacheJournalDataV1; 5],
    physical: super::super::create_storage_history::cache_held::CachePhysicalDataV1,
    nonce: [u8; 16], cutoff: u64, root: [u8; 32],
    rows: impl ExactSizeIterator<Item = (super::super::lifecycle_model::LifecycleResourceV1, [u8; 32])>,
) -> Result<DeleteBatchOwnerCutDataV2, LifecycleModelError> {
    use super::super::protected_names::ProtectedJournalNamesV1;
    if nonce == [0; 16] || cutoff == 0 || root == [0; 32] {
        return Err(LifecycleModelError::InvalidModel);
    }
    let physical = physical.canonical_comparison_bytes_v1().map_err(|_| LifecycleModelError::InvalidModel)?;
    let count = u32::try_from(rows.len()).map_err(|_| LifecycleModelError::InvalidModel)?;
    let mut hash = Sha256::new()
        .chain_update(b"aos.sandbox.delete.complete-cache-inventory-cut.v2\0")
        .chain_update(nonce).chain_update(cutoff.to_be_bytes()).chain_update(root).chain_update(physical);
    for (index, writer) in writers.iter().enumerate() {
        let names = writer.names.to_bytes();
        ProtectedJournalNamesV1::from_bytes(&names).map_err(|_| LifecycleModelError::InvalidModel)?;
        if writer.next == 0 || writer.next == u64::MAX { return Err(LifecycleModelError::InvalidModel); }
        hash = hash.chain_update([index as u8]).chain_update(names)
            .chain_update(writer.next.to_be_bytes()).chain_update(writer.end.to_be_bytes());
    }
    hash = hash.chain_update(count.to_be_bytes());
    let mut previous = None;
    let mut actual = 0_u32;
    for row in rows {
        if row.0.as_bytes() == &[0; 16] || row.1 == [0; 32]
            || previous.is_some_and(|previous| previous >= row) {
            return Err(LifecycleModelError::InvalidModel);
        }
        hash = hash.chain_update([row.0.code()]).chain_update(row.0.as_bytes()).chain_update(row.1);
        previous = Some(row);
        actual = actual.checked_add(1).ok_or(LifecycleModelError::InvalidModel)?;
    }
    if actual != count { return Err(LifecycleModelError::InvalidModel); }
    Ok(DeleteBatchOwnerCutDataV2 {
        boundary: DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence: writers[2].next },
        count, digest: hash.finalize().into(),
    })
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use super::super::super::{create_storage_history::cache_held::CacheJournalDataV1,
        lifecycle_model::LifecycleResourceV1, protected_names::ProtectedJournalNamesV1};
    use aos_sandbox_model::ResourceId;

    fn writers() -> [CacheJournalDataV1; 5] {
        std::array::from_fn(|index| CacheJournalDataV1 {
            names: ProtectedJournalNamesV1::from_historical_fields((1, 10 + index as u64),
                (1, 20 + index as u64), (1, 30 + index as u64)),
            next: 40 + index as u64, end: 50 + index as u64,
        })
    }

    fn physical() -> super::super::super::create_storage_history::cache_held::CachePhysicalDataV1 {
        super::super::super::create_storage_history::cache_held::CachePhysicalDataV1 {
            root: (1, 100), uid: 1000, mode: 0o700, lock: (1, 101), manifest: (0, 0),
            generation: 0, digest: [0; 32], limits: [8; 32],
        }
    }

    #[test]
    fn complete_cache_cut_commits_every_native_prefix_and_the_inactive_history_root() {
        let original = writers();
        let rows = [(LifecycleResourceV1::Other(ResourceId::from_bytes([1; 16])), [2; 32])];
        let expected = cache_inventory_cut_data_v2(&original, physical(), [3; 16], 4, [5; 32], rows.into_iter()).unwrap();
        assert_eq!(expected.boundary, DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence: original[2].next });
        assert_eq!(expected.count, 1);
        for index in 0..5 {
            let mut changed = original;
            changed[index].end += 1;
            assert_ne!(cache_inventory_cut_data_v2(&changed, physical(), [3; 16], 4, [5; 32], rows.into_iter()).unwrap(), expected);
        }
        assert_ne!(cache_inventory_cut_data_v2(&original, physical(), [3; 16], 4, [6; 32], rows.into_iter()).unwrap(), expected);
        assert_ne!(cache_inventory_cut_data_v2(&original, physical(), [7; 16], 4, [5; 32], rows.into_iter()).unwrap(), expected);
        let mut changed_physical = physical();
        changed_physical.limits[0] ^= 1;
        assert_ne!(cache_inventory_cut_data_v2(&original, changed_physical, [3; 16], 4, [5; 32], rows.into_iter()).unwrap(), expected);
    }

    #[test]
    fn complete_cache_cut_rejects_duplicate_rows_but_keeps_real_empty_inventory_explicit() {
        let writers = writers();
        let row = (LifecycleResourceV1::Other(ResourceId::from_bytes([1; 16])), [2; 32]);
        assert!(cache_inventory_cut_data_v2(&writers, physical(), [3; 16], 4, [5; 32], [row, row].into_iter()).is_err());
        let empty = cache_inventory_cut_data_v2(&writers, physical(), [3; 16], 4, [5; 32], [].into_iter()).unwrap();
        assert_eq!(empty.count, 0);
        assert_ne!(empty.digest, [0; 32]);
        let mut invalid = writers;
        invalid[4].next = 0;
        assert!(cache_inventory_cut_data_v2(&invalid, physical(), [3; 16], 4, [5; 32], [].into_iter()).is_err());
    }
}

/// Commits the fixed six canonical initial planning descriptors in role order.
///
/// Every descriptor must be derived separately from genuine complete query
/// originals by the producer and independently compared by the receiver. This
/// pure aggregate is neither a six-owner loan nor an acceptance/currentness token.
///
/// # Errors
/// Refuses any role/boundary/count/digest outside the sole V2 descriptor grammar.
pub fn initial_six_cut_data_v2(cuts: &[DeleteBatchOwnerCutDataV2; 6])
    -> Result<[u8; 32], LifecycleModelError>
{
    six_cut_data_v2(b"aos.sandbox.delete.initial-six-cut.v2\0", cuts)
}

/// Commits the independently observed post-ACK six under its distinct domain.
///
/// This pure comparison kernel cannot construct fresh owners or accept Delete.
///
/// # Errors
/// Refuses the same malformed typed role descriptors as the initial kernel.
pub fn fresh_six_cut_data_v2(cuts: &[DeleteBatchOwnerCutDataV2; 6])
    -> Result<[u8; 32], LifecycleModelError>
{
    six_cut_data_v2(b"aos.sandbox.delete.fresh-six-cut.v2\0", cuts)
}

fn six_cut_data_v2(domain: &[u8], cuts: &[DeleteBatchOwnerCutDataV2; 6])
    -> Result<[u8; 32], LifecycleModelError>
{
    let mut hash = Sha256::new().chain_update(domain);
    for (index, cut) in cuts.iter().enumerate() {
        hash = hash.chain_update(cut.canonical_descriptor_data_v2((index + 1) as u8)?);
    }
    Ok(hash.finalize().into())
}

#[cfg(test)]
mod six_tests {
    use super::*;

    #[test]
    fn initial_six_uses_typed_native_coordinates_and_fixed_role_order() {
        // These are explicit passive codec inputs, not six live/native owners.
        let mut cuts = std::array::from_fn(|index| DeleteBatchOwnerCutDataV2 {
            boundary: DeleteBatchNativeBoundaryDataV2::JournalPrefix { next_sequence: index as u64 + 1 },
            count: 0, digest: [index as u8 + 1; 32],
        });
        cuts[5].boundary = DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence { directory_inode: 100 };
        let expected = initial_six_cut_data_v2(&cuts).unwrap();
        cuts[5].boundary = DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence { directory_inode: 101 };
        assert_ne!(initial_six_cut_data_v2(&cuts).unwrap(), expected);
        cuts[5].boundary = DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence { directory_inode: 100 };
        cuts.swap(0, 1);
        assert_ne!(initial_six_cut_data_v2(&cuts).unwrap(), expected);
        cuts.swap(0, 5);
        assert!(initial_six_cut_data_v2(&cuts).is_err());
    }
}

/// Commits the entire original default-local Transfer planning exchange.
///
/// The native absence, active Ownership and configured Runtime trust joins
/// remain mandatory actual owner predicates around this passive kernel.
///
/// # Errors
/// Refuses malformed/mixed complete V2 originals or invalid native namespace.
pub fn transfer_planning_cut_data_v2(
    open: &super::planning::DeleteRootPlanningOpenDataV3,
    challenge: &super::planning::DeleteRootPlanningChallengeDataV3,
    observation_bytes: &[u8; 1312],
) -> Result<DeleteBatchOwnerCutDataV2, super::planning::DeleteRootPlanningDataErrorV3> {
    let observation = super::planning::DeleteRootPlanningObservationDataV2::decode(observation_bytes)?;
    observation.require_exchange_v2(*open, *challenge)?;
    let open = open.encode_v3()?;
    let challenge = challenge.encode_v3()?;
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.delete.transfer-default-local-cut.v2\0")
        .chain_update(open).chain_update(challenge).chain_update(observation_bytes)
        .finalize().into();
    Ok(DeleteBatchOwnerCutDataV2 {
        boundary: DeleteBatchNativeBoundaryDataV2::RootNamespaceAbsence {
            directory_inode: observation.native.namespace.directories[0].file.inode,
        },
        count: 0,
        digest,
    })
}


#[cfg(test)]
mod delete_mount_method_tests {
    use super::*;

    #[test]
    fn v2_delete_selects_installed_mount16_and_never_ordinary_boot6() {
        assert_eq!(delete_inventory_method_for_role_data_v2(2).unwrap(),
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_DESTINATION_SLOTS);
        assert_ne!(delete_inventory_method_for_role_data_v2(2).unwrap(),
            BrokerMethod::BROKER_METHOD_MOUNT_INVENTORY_RESOURCES);
        assert!(delete_inventory_method_for_role_data_v2(0).is_err());
        assert!(delete_inventory_method_for_role_data_v2(7).is_err());
    }
}
