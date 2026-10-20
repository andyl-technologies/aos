//! Retains creation-state opening and its protected first-local policy head.
//!
//! The actual image-enrolled Network startup lends its captured writer and
//! protected policy original. An empty creation Journal gets a distinct sealed
//! initialization head before the ordinary replay floor can succeed. No fake
//! operation, floor zero, or permission follows from parsed head DATA.

use super::*;
use crate::preparation_catalog::{CatalogHeadV1, decode_head, encode_head};
use crate::protected_policy::ProtectedNetworkPolicyOriginalV4;
use crate::journal::{NetworkCreationCapturedJournalOpenV4};
use aos_sandbox_broker::receiving::{
    FixedServiceOperationClosedV4 as Closed, FixedServiceReceivingCaptureV1 as Common,
};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::canonical_map;

const HEAD_KEY: &[u8] = b"aos.network.creation.policy-head.v1\0";
const HEAD_DOMAIN: [u8; 16] = *b"AOSNETCREATEHD1!";

#[derive(Debug, thiserror::Error)]
pub(crate) enum NetworkCreationStartupErrorV4 {
    #[error(transparent)]
    State(#[from] NetworkStateError),
    #[error(transparent)]
    Journal(#[from] crate::journal::JournalError),
    #[error(transparent)]
    Geometry(#[from] aos_sandbox_model::AccountingError),
    #[error(transparent)]
    AppendGeometry(#[from] crate::journal::JournalAppendReceivingDemandErrorV1),
    #[error(transparent)]
    EncodingGeometry(#[from] canonical_map::CanonicalMapReceivingErrorV1),
    #[error("the actual Network startup interval remains closed")]
    Closed,
}

type Result<T> = std::result::Result<T, NetworkCreationStartupErrorV4>;

pub(crate) struct NetworkCreationStateOpeningOriginalV4 {
    native: NetworkCreationCapturedJournalOpenV4,
    journal: Option<Journal>,
    report: Option<crate::journal::RecoveryReport>,
    head: Option<std::result::Result<Option<CatalogHeadV1>, NetworkStateError>>,
    encoded: Option<std::result::Result<Vec<u8>, crate::NetworkPreparationCatalogError>>,
    sealed: Option<std::result::Result<Vec<u8>, crate::NetworkAdmissionError>>,
    transaction: Option<std::result::Result<JournalTransaction, crate::journal::JournalError>>,
    commit: Option<std::result::Result<crate::journal::CommitResult, crate::journal::JournalError>>,
    model: Option<std::result::Result<BTreeMap<[u8; 16], DurableRecord>, NetworkStateError>>,
    completed: Option<NetworkStateStore>,
    result: Option<Result<()>>,
    funding: [Option<std::result::Result<(), Closed>>; 5],
    funding_refusal: bool,
    entered: bool,
    taken: bool,
}

impl NetworkCreationStateOpeningOriginalV4 {
    pub(crate) fn new() -> Self {
        Self {
            native: NetworkCreationCapturedJournalOpenV4::new(),
            journal: None,
            report: None,
            head: None,
            encoded: None,
            sealed: None,
            transaction: None,
            commit: None,
            model: None,
            completed: None,
            result: None,
            funding: std::array::from_fn(|_| None),
            funding_refusal: false,
            entered: false,
            taken: false,
        }
    }

    pub(crate) fn capture_once_v4(
        &mut self,
        common: &mut Common<Closed>,
        authority: &NetworkAuthorityV1,
        policy: &ProtectedNetworkPolicyOriginalV4,
        minimum_generation: u64,
    ) -> Result<()> {
        if self.entered {
            return Err(NetworkCreationStartupErrorV4::Closed);
        }
        self.entered = true;
        self.result = Some(self.capture_inner(common, authority, policy, minimum_generation));
        if matches!(self.result, Some(Ok(()))) {
            Ok(())
        } else {
            Err(NetworkCreationStartupErrorV4::Closed)
        }
    }

    fn capture_inner(
        &mut self,
        common: &mut Common<Closed>,
        authority: &NetworkAuthorityV1,
        policy_original: &ProtectedNetworkPolicyOriginalV4,
        minimum_generation: u64,
    ) -> Result<()> {
        if common.require_network_startup_current_v4().is_err() {
            self.funding_refusal = true;
            return Err(NetworkCreationStartupErrorV4::Closed);
        }
        self.admit(
            common,
            NetworkCreationCapturedJournalOpenV4::fixed_preparation_demand()?,
            0,
        )?;
        self.native
            .prepare_once(journal_limits());
        let extent = self
            .native
            .captured_extent()
            .ok_or(NetworkCreationStartupErrorV4::Closed)?;
        let demand = extent
            .dominant_native_receiving_demand_v1()?
            .checked_add(extent.dominant_semantic_receiving_demand_v1()?)?
            .checked_add(creation_replay_receiving_demand_v4(extent)?)?;
        self.admit(common, demand, 1)?;
        self.native.replay_once();
        let (journal, report) = self
            .native
            .take_opened()
            .ok_or(NetworkCreationStartupErrorV4::Closed)?;
        self.journal = Some(journal);
        self.report = Some(report);

        let policy = policy_original
            .catalog_v4()
            .ok_or(NetworkCreationStartupErrorV4::Closed)?;
        if policy.generation() < minimum_generation || minimum_generation == 0 {
            return Err(NetworkStateError::Rollback.into());
        }
        let journal = self
            .journal
            .as_ref()
            .ok_or(NetworkCreationStartupErrorV4::Closed)?;
        self.head = Some(read_creation_head_v4(journal, authority));
        let head = self
            .head
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(NetworkStateError::CorruptRecord)?;
        let advance = require_creation_head_v4(
            head.as_ref(),
            journal.snapshot_sequence(),
            policy.node().as_bytes(),
            policy.generation(),
            policy.digest().as_bytes(),
        )?;

        // Authenticate and validate the entire old materialized state before
        // a trusted policy advance can publish anything. The successful model
        // remains parked while the new head is encoded, sealed and appended.
        if let Some(head) = head {
            self.model = Some(replay_records_v4(journal, authority, head.generation));
            if !matches!(self.model, Some(Ok(_))) {
                return Err(NetworkCreationStartupErrorV4::Closed);
            }
        }
        if advance {
            let head = CatalogHeadV1 {
                node: *policy.node().as_bytes(),
                generation: policy.generation(),
                digest: *policy.digest().as_bytes(),
            };
            self.publish_head_v4(common, authority, &head)?;
        }
        if self.model.is_none() {
            let journal = self
                .journal
                .as_ref()
                .ok_or(NetworkCreationStartupErrorV4::Closed)?;
            self.model = Some(replay_records_v4(journal, authority, minimum_generation));
        }
        let records = match self.model.take() {
            Some(Ok(records)) => records,
            failed => {
                self.model = failed;
                return Err(NetworkCreationStartupErrorV4::Closed);
            }
        };
        let journal = self
            .journal
            .take()
            .ok_or(NetworkCreationStartupErrorV4::Closed)?;
        self.completed = Some(NetworkStateStore {
            journal,
            records,
            minimum_generation,
            commit_failed: false,
            #[cfg(test)]
            fail_after_next_journal_commit: false,
        });
        Ok(())
    }

    fn publish_head_v4(
        &mut self,
        common: &mut Common<Closed>,
        authority: &NetworkAuthorityV1,
        head: &CatalogHeadV1,
    ) -> Result<()> {
        self.admit(common, canonical_map::head_encoding_demand_v1(head, 1)?, 2)?;
        self.encoded = Some(encode_head(head));
        let payload = self
            .encoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(NetworkStateError::CorruptRecord)?;
        let sealing_bytes = aos_sandbox_broker::local_record_sealing_bytes_v1(payload.capacity())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(NetworkCreationStartupErrorV4::Closed)?;
        self.admit(
            common,
            ResourceVector::ZERO.with(D::MemoryBytes, sealing_bytes),
            3,
        )?;
        let payload = self
            .encoded
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(NetworkStateError::CorruptRecord)?;
        self.sealed = Some(authority.0.seal_local_record(
            RecordNamespace::NetworkResourceInventory,
            HEAD_KEY,
            head_domain_v4()?,
            payload,
        ));
        let sealed = self
            .sealed
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(NetworkStateError::AuthorityLink)?;
        let journal = self
            .journal
            .as_ref()
            .ok_or(NetworkCreationStartupErrorV4::Closed)?;
        let append = journal.append_receiving_demand_v1(std::iter::once(
            aos_sandbox_journal::geometry::RecordShape {
                key_bytes: HEAD_KEY.len(),
                value_bytes: Some(sealed.len()),
            },
        ))?;
        self.admit(common, append, 4)?;

        let sealed = self
            .sealed
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(NetworkStateError::AuthorityLink)?;
        let mut digest = Sha256::new();
        digest.update(b"aos.network.creation.policy-head.transaction.v1\0");
        digest.update(head.node);
        digest.update(head.generation.to_be_bytes());
        digest.update(head.digest);
        let digest = digest.finalize();
        let mut transaction_id = [0; 16];
        transaction_id.copy_from_slice(&digest[..16]);
        self.transaction = Some(
            JournalTransaction::new(
                transaction_id,
                vec![JournalRecord::put(
                    RecordNamespace::NetworkResourceInventory,
                    HEAD_KEY.to_vec(),
                    sealed.clone(),
                )],
            )
            .map_err(crate::journal::JournalError::from),
        );
        let transaction = self
            .transaction
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(NetworkCreationStartupErrorV4::Closed)?;
        self.commit = Some(
            self.journal
                .as_mut()
                .ok_or(NetworkCreationStartupErrorV4::Closed)?
                .commit(transaction),
        );
        if !matches!(self.commit, Some(Ok(_))) {
            return Err(NetworkCreationStartupErrorV4::Closed);
        }
        let journal = self
            .journal
            .as_ref()
            .ok_or(NetworkCreationStartupErrorV4::Closed)?;
        if journal.get(RecordNamespace::NetworkResourceInventory, HEAD_KEY)
            != Some(sealed.as_slice())
        {
            return Err(NetworkStateError::AuthorityLink.into());
        }
        Ok(())
    }

    fn admit(
        &mut self,
        common: &mut Common<Closed>,
        growth: ResourceVector,
        index: usize,
    ) -> Result<()> {
        self.funding[index] = Some(common.require_additional_startup_representation_v4(growth));
        if !matches!(self.funding[index], Some(Ok(()))) {
            self.funding_refusal = true;
            return Err(NetworkCreationStartupErrorV4::Closed);
        }
        Ok(())
    }

    pub(crate) fn take_completed_once_v4(&mut self) -> Option<NetworkStateStore> {
        if self.taken || !matches!(self.result, Some(Ok(()))) {
            return None;
        }
        self.taken = true;
        self.completed.take()
    }

    pub(crate) fn original_failure_selected_v4(&self) -> bool {
        self.funding_refusal
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T, E: std::error::Error + 'static>(
            slot: &Option<std::result::Result<T, E>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            slot.as_ref()?.as_ref().err().map(|cause| cause as _)
        }
        self.native
            .failure()
            .or_else(|| error(&self.head))
            .or_else(|| error(&self.encoded))
            .or_else(|| error(&self.sealed))
            .or_else(|| error(&self.transaction))
            .or_else(|| {
                self.journal
                    .as_ref()
                    .and_then(Journal::retained_native_append_failure_v1)
            })
            .or_else(|| error(&self.commit))
            .or_else(|| error(&self.model))
            .or_else(|| error(&self.result))
    }
}

fn head_domain_v4() -> std::result::Result<BrokerLocalRecordDomain, NetworkStateError> {
    BrokerLocalRecordDomain::new(HEAD_DOMAIN).map_err(|_| NetworkStateError::CorruptRecord)
}

pub(super) fn read_creation_head_v4(
    journal: &Journal,
    authority: &NetworkAuthorityV1,
) -> std::result::Result<Option<CatalogHeadV1>, NetworkStateError> {
    let mut head = None;
    for (key, value) in journal.records(RecordNamespace::NetworkResourceInventory) {
        if key != HEAD_KEY || head.is_some() {
            return Err(NetworkStateError::CorruptRecord);
        }
        let payload = authority
            .0
            .open_local_record(
                RecordNamespace::NetworkResourceInventory,
                HEAD_KEY,
                head_domain_v4()?,
                value,
            )
            .map_err(|_| NetworkStateError::CorruptRecord)?;
        head = Some(decode_head(payload).map_err(|_| NetworkStateError::CorruptRecord)?);
    }
    Ok(head)
}

/// Refuses a missing historical head and authenticates monotonic policy advance.
fn require_creation_head_v4(
    head: Option<&CatalogHeadV1>,
    sequence: u64,
    node: &[u8; 16],
    generation: u64,
    digest: &[u8; 32],
) -> std::result::Result<bool, NetworkStateError> {
    match head {
        None if sequence == 0 => Ok(true),
        None => Err(NetworkStateError::Rollback),
        Some(head)
            if head.node != *node
                || head.generation > generation
                || (head.generation == generation && head.digest != *digest) =>
        {
            Err(NetworkStateError::Rollback)
        }
        Some(head) => Ok(head.generation < generation),
    }
}

/// Prices the actual creation parser and its three independent uniqueness maps.
fn creation_replay_receiving_demand_v4(
    extent: &crate::journal::ProtectedJournalPreopenReplayExtentV1,
) -> Result<ResourceVector> {
    let overflow = || NetworkCreationStartupErrorV4::Closed;
    let source_rows = extent
        .source_transactions
        .checked_mul(extent.limits.maximum_records_per_transaction)
        .and_then(|rows| rows.checked_add(extent.source_checkpoint_rows))
        .ok_or_else(overflow)?;
    let rows = source_rows.min(extent.limits.maximum_materialized_records);
    // Use the same pinned standard-library BTree node supplier for the
    // actual record, pending, handle and physical-identity map types.
    use aos_sandbox_journal::geometry::conservative_btree_node_bytes_v1 as nodes;
    let nodes = nodes::<[u8; 16], DurableRecord>(rows)
        .and_then(|bytes| bytes.checked_add(nodes::<[u8; 16], [u8; 16]>(rows)?))
        .and_then(|bytes| bytes.checked_add(nodes::<[u8; 32], NetworkHandleLineage>(rows)?))
        .and_then(|bytes| bytes.checked_add(nodes::<([u8; 16], u64, u64), [u8; 16]>(rows)?))
        .ok_or_else(overflow)?;
    // The canonical binary decoder copies disjoint blobs and endpoint lists;
    // the handle index clones one catalog. Sixteen physical prefix copies
    // cover those co-live capacities. One malformed record may preallocate
    // 256 endpoints before discovering EOF, independently of prefix length.
    let dynamic = extent
        .native_bytes
        .checked_mul(16)
        .and_then(|bytes| bytes.checked_add((256 * size_of::<ResolvedEndpointV1>() * 4) as u64))
        .and_then(|bytes| bytes.checked_add((MAXIMUM_RECORD_BYTES * 8) as u64))
        .and_then(|bytes| bytes.checked_add(u64::try_from(nodes).ok()?))
        .ok_or_else(overflow)?;
    Ok(ResourceVector::ZERO.with(D::MemoryBytes, dynamic).with(
        D::MetadataEntries,
        u64::try_from(rows.checked_mul(4).ok_or_else(overflow)?).map_err(|_| overflow())?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_new_empty_prefix_can_initialize_its_policy_head() {
        assert_eq!(
            require_creation_head_v4(None, 0, &[1; 16], 7, &[2; 32]).unwrap(),
            true
        );
        assert!(require_creation_head_v4(None, 1, &[1; 16], 7, &[2; 32]).is_err());
        let head = CatalogHeadV1 {
            node: [1; 16],
            generation: 7,
            digest: [2; 32],
        };
        assert_eq!(
            require_creation_head_v4(Some(&head), 4, &[1; 16], 7, &[2; 32]).unwrap(),
            false
        );
        assert_eq!(
            require_creation_head_v4(Some(&head), 4, &[1; 16], 8, &[3; 32]).unwrap(),
            true
        );
        assert!(require_creation_head_v4(Some(&head), 4, &[1; 16], 7, &[3; 32]).is_err());
        assert!(require_creation_head_v4(Some(&head), 4, &[1; 16], 6, &[2; 32]).is_err());
        assert!(require_creation_head_v4(Some(&head), 4, &[4; 16], 8, &[3; 32]).is_err());
    }

    #[test]
    fn replay_names_follow_reached_rows_instead_of_control_fields() {
        let empty = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
            journal_limits(),
            0,
        )
        .unwrap();
        let reached = crate::journal::protected_journal_preopen_replay_extent_for_prefix_v1(
            journal_limits(),
            4096,
        )
        .unwrap();
        let empty_demand = creation_replay_receiving_demand_v4(&empty).unwrap();
        let reached_demand = creation_replay_receiving_demand_v4(&reached).unwrap();
        assert_eq!(empty_demand.get(D::MetadataEntries), 0);
        assert!(reached_demand.get(D::MetadataEntries) > 0);
        assert!(reached_demand.get(D::MemoryBytes) > empty_demand.get(D::MemoryBytes));
    }
}

impl NetworkCreationStateOpeningOriginalV4 {
    pub(crate) fn inventory_currentness_demand_v2(&self)
        -> std::result::Result<ResourceVector, crate::journal::JournalError>
    {
        self.native.inventory_currentness_receiving_demand_v2()
    }

    pub(crate) fn inventory_currentness_before_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), crate::journal::JournalError> {
        self.native.observe_inventory_currentness_before_v2(journal, original)
    }

    pub(crate) fn inventory_currentness_after_owed_v2(&self, journal: &Journal,
        original: &mut crate::journal::FixedServiceInventoryJournalCurrentnessOriginalV2,
    ) -> std::result::Result<(), crate::journal::JournalError> {
        self.native.observe_inventory_currentness_after_owed_v2(journal, original)
    }
}

impl NetworkStateStore {
    pub(crate) fn inventory_no_resource_history_v2(
        &self, authority: &NetworkAuthorityV1, policy: &crate::NetworkPolicyCatalogV1,
    ) -> std::result::Result<bool, NetworkStateError> {
        self.ensure_authority_readable()?;
        self.journal.ensure_healthy()?;
        if !self.records.is_empty() || self.journal.all_records().any(|(namespace, key, _)| {
            namespace != RecordNamespace::NetworkResourceInventory || key != HEAD_KEY
        }) {
            return Ok(false);
        }
        let head = read_creation_head_v4(&self.journal, authority)?
            .ok_or(NetworkStateError::CorruptRecord)?;
        if head.node != *policy.node().as_bytes() || head.generation != policy.generation()
            || head.digest != *policy.digest().as_bytes() {
            return Err(NetworkStateError::Rollback);
        }
        Ok(true)
    }
}

pub(super) fn inventory_creation_head_memory_v2(journal: &Journal) -> Option<usize> {
    journal.get(RecordNamespace::NetworkResourceInventory, HEAD_KEY)
        .map_or(Some(0), crate::service_original::journal::inventory_head_decode_memory_v2::<CatalogHeadV1>)
}

/// Checks only this creation journal's closed key families before native replay.
pub(crate) fn creation_journal_key_data_v1(namespace: RecordNamespace, key: &[u8]) -> bool {
    match namespace {
        RecordNamespace::Operation | RecordNamespace::Effect
        | RecordNamespace::AuthorityPublication | RecordNamespace::DesiredState => key.len() == 16,
        RecordNamespace::NetworkResourceInventory => key == HEAD_KEY,
        _ => false,
    }
}
