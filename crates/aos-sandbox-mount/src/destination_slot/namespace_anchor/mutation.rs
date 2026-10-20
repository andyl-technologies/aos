//! Performs the finite no-slot materialization through the actual Mount loan.
//!
//! An inert header is retained by the installed service. Its lazy models and
//! every directory/append prefix are admitted before allocation or native work.

use super::*;
use aos_sandbox_broker::VerifiedBrokerAdmission;
use aos_sandbox_broker::receiving::MountAttachmentAnchorReceivingLoanV4;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::geometry::{RecordShape, conservative_btree_node_bytes_v1};
use aos_sandbox_protocol::mount_attachment_anchor::{
    ValidatedAttachmentAnchorRequestV1, encode_attachment_anchor_resource_v1,
    MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1,
};

mod reap;

/// Carries passive complete physical/model geometry for the held Mount writer.
///
/// Private fields prevent changing the selected recipe after it was measured;
/// the value grants no request authority, writer, role or native destination.
pub struct MountAttachmentAnchorPhysicalShapeDataV1 {
    complete: ResourceVector,
}

impl MountAttachmentAnchorPhysicalShapeDataV1 {
    /// Prices the exact held namespace and finite materialization recipe.
    ///
    /// # Errors
    /// Preserves unhealthy journal/native append or checked geometry refusal.
    pub fn for_current_v4(
        journal: &Journal,
        store: &DestinationSlotStoreV1,
        admission: &VerifiedBrokerAdmission,
    ) -> Result<Self> {
        let overflow = || invalid("namespace anchor representation overflow");
        // The response carries one canonical resource row and its protobuf
        // envelope. This is the finite schema bound, never a configured tail.
        let receipt = MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1.checked_add(16)
            .ok_or_else(overflow)?;
        let records = aos_sandbox_broker::mount_attachment_anchor_record_shape_v4(
            &admission.fence, &admission.effect, receipt,
        ).ok_or_else(overflow)?;
        let resource = RecordShape { key_bytes: 40,
            value_bytes: Some(MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1) };
        let authority = [
            RecordShape { key_bytes: 16, value_bytes: Some(records.fence_bytes_v4()) },
            RecordShape { key_bytes: 16, value_bytes: Some(32 + 16) },
            RecordShape { key_bytes: 16, value_bytes: Some(records.pending_bytes_v4()) },
        ];
        let complete_effect = RecordShape { key_bytes: 16,
            value_bytes: Some(records.complete_bytes_v4()) };
        let transactions = [Ok(authority.into_iter()),
            Ok([resource, EMPTY_SHAPE, EMPTY_SHAPE].into_iter()),
            Ok([resource, EMPTY_SHAPE, EMPTY_SHAPE].into_iter()),
            Ok([complete_effect, EMPTY_SHAPE, EMPTY_SHAPE].into_iter())];
        // All actual transactions retain their own framing. No synthetic
        // records are passed: the short arrays have their actual cardinality.
        let append = journal.append_sequence_receiving_demand_v1(
            transactions.into_iter().enumerate().map(|(index, rows)| {
                rows.map(|rows| rows.take(if index == 0 { 3 } else { 1 }))
            }),
        ).map_err(MountError::AnchorGeometry)?;
        let mut memory = std::mem::size_of::<MountAttachmentAnchorOriginalV4>()
            .checked_mul(2).and_then(|value| value.checked_add(
                std::mem::size_of::<NamespaceMutationModelsV4>().checked_mul(2)?))
            .and_then(|value| value.checked_add(records.sealing_bytes_v4()))
            .ok_or_else(overflow)?;
        let mut files = store.pins.len().checked_add(store.namespace_anchors.pins.len())
            .ok_or_else(overflow)?;
        let mut names = 0usize;
        if admission.effect.verb() == aos_sandbox_core::BrokerVerb::MountReapAttachmentAnchor {
            let native = reap::receiving_obligations_v4().ok_or_else(overflow)?;
            memory = memory.checked_add(native.0).ok_or_else(overflow)?;
            files = files.checked_add(native.1).ok_or_else(overflow)?;
            names = names.checked_add(native.2).ok_or_else(overflow)?;
            let physical = ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| overflow())?)
                .with(D::OpenFiles, u64::try_from(files).map_err(|_| overflow())?)
                .with(D::MetadataEntries, u64::try_from(names).map_err(|_| overflow())?);
            return Ok(Self { complete: append.checked_add(physical).map_err(|_| overflow())? });
        }
        for bytes in [5, 32, 32, 16] {
            let native = DirectoryParentOriginalV1::receiving_obligations_v1(bytes)
                .ok_or_else(overflow)?;
            let sync = DirectorySyncOriginalV1::receiving_obligations_v1()
                .ok_or_else(overflow)?;
            memory = memory.checked_add(native.0).and_then(|value| value.checked_add(sync.0))
                .and_then(|value| value.checked_add(bytes.checked_mul(2)?)).ok_or_else(overflow)?;
            files = files.checked_add(native.1).and_then(|value| value.checked_add(sync.1))
                .ok_or_else(overflow)?;
            names = names.checked_add(native.2).ok_or_else(overflow)?;
        }
        // Ready replay uses the same retained full-path resolver as inventory.
        // Its prefixes remain owned even though the ordinary creation branch
        // has already paid its four separate parent-resolution destinations.
        let replay = aos_sandbox_linux::path::BeneathRootResolveOriginalV2::receiving_obligations_v2(88)
            .ok_or_else(overflow)?;
        memory = memory.checked_add(replay.0).ok_or_else(overflow)?;
        files = files.checked_add(replay.1).ok_or_else(overflow)?;
        names = names.checked_add(replay.2).ok_or_else(overflow)?;
        // The new protected resource and its retained native pin occupy two
        // additional real logical namespace indices beside filesystem names.
        names = names.checked_add(2).ok_or_else(overflow)?;
        let rows = store.namespace_anchors.len_v1().checked_add(1).ok_or_else(overflow)?;
        memory = memory.checked_add(conservative_btree_node_bytes_v1::<[u8; 40],
            ValidatedAttachmentAnchorResourceV1>(rows).ok_or_else(overflow)?)
            .and_then(|value| value.checked_add(conservative_btree_node_bytes_v1::<[u8; 40],
                Arc<BeneathRoot>>(rows)?))
            .and_then(|value| value.checked_add(MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1.checked_mul(8)?))
            .and_then(|value| value.checked_add(std::mem::size_of::<BeneathRoot>()
                .checked_add(2 * std::mem::size_of::<usize>())?.checked_mul(2)?))
            .ok_or_else(overflow)?;
        let physical = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| overflow())?)
            .with(D::OpenFiles, u64::try_from(files).map_err(|_| overflow())?)
            .with(D::MetadataEntries, u64::try_from(names).map_err(|_| overflow())?);
        let complete = append.checked_add(physical).map_err(|_| overflow())?;
        Ok(Self { complete })
    }

    /// Returns this immutable recipe's cost DATA without admitting it.
    ///
    /// # Errors
    /// The already checked recipe has no additional failure path.
    pub fn receiving_demand_v4(&self) -> Result<ResourceVector> { Ok(self.complete) }
}

const EMPTY_SHAPE: RecordShape = RecordShape { key_bytes: 0, value_bytes: None };

/// Retains an actual once-only namespace materialization and all failed prefixes.
///
/// Empty construction performs no IO and grants no physical permission.
#[derive(Default)]
pub struct MountAttachmentAnchorOriginalV4 {
    entered: bool,
    first: Option<First>,
    shape: Option<Result<MountAttachmentAnchorPhysicalShapeDataV1>>,
    entry: Option<std::result::Result<(), aos_sandbox_broker::receiving::FixedServiceOperationClosedV4>>,
    admission: Option<std::result::Result<(), aos_sandbox_broker::receiving::FixedServiceOperationClosedV4>>,
    models: Option<Box<NamespaceMutationModelsV4>>,
    closed: Option<MountError>,
}

#[derive(Clone, Copy)]
enum First { Entry, Shape, Admission, Body, Order }

#[derive(Default)]
struct NamespaceMutationModelsV4 {
    reap: reap::NamespaceReapOriginalV4,
    intent: Option<std::result::Result<ValidatedAttachmentAnchorResourceV1,
        aos_sandbox_protocol::ProtocolValidationError>>,
    ready: Option<std::result::Result<ValidatedAttachmentAnchorResourceV1,
        aos_sandbox_protocol::ProtocolValidationError>>,
    replay_read: inventory::AnchorReadOriginalV4,
    parents: [DirectoryParentOriginalV1; 4],
    syncs: [DirectorySyncOriginalV1; 4],
    guards: [Option<Result<()>>; 10],
    mount: Option<std::result::Result<MountId, aos_sandbox_linux::Error>>,
    pin: Option<Arc<BeneathRoot>>,
    intent_transaction: Option<std::result::Result<JournalTransaction,
        aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>,
    intent_commit: Option<std::result::Result<aos_sandbox_mount_native::CommitResult, aos_sandbox_mount_native::MountJournalErrorV1>>,
    ready_transaction: Option<std::result::Result<JournalTransaction,
        aos_sandbox_protocol::domain_ledger::JournalTransactionDataError>>,
    ready_commit: Option<std::result::Result<aos_sandbox_mount_native::CommitResult, aos_sandbox_mount_native::MountJournalErrorV1>>,
    result: Option<Result<()>>,
}

impl MountAttachmentAnchorOriginalV4 {
    pub(crate) fn retire_completed_positive_native_once_v5(&mut self) -> Result<()> {
        if !self.entered || self.first.is_some()
            || !matches!(self.entry, Some(Ok(()))) || !matches!(self.admission, Some(Ok(())))
            || !self.models.as_ref().is_some_and(|models| matches!(models.result, Some(Ok(())))) {
            return Err(conflict("namespace native retirement requires the same whole positive original"));
        }
        // The actual service calls only after successful send and all same
        // Session/Source posts. The Store keeps its namespace pin, while the
        // complete physical DATA result and every F charge remain retained.
        drop(self.models.take());
        Ok(())
    }

    /// Borrows the first original refusal without releasing failed native custody.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Entry => self.entry.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Shape => self.shape.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Admission => self.admission.as_ref()?.as_ref().err().map(|cause| cause as _),
            First::Body => self.models.as_ref()?.failure_v4(),
            First::Order => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

impl NamespaceMutationModelsV4 {
    fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.reap.failure_v4()
            .or_else(|| self.intent.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.intent_transaction.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.intent_commit.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.guards.iter().find_map(|result| result.as_ref()?.as_ref().err().map(|cause| cause as _)))
            .or_else(|| self.replay_read.failure_v4())
            .or_else(|| self.parents.iter().find_map(|original| original.failure_v1()))
            .or_else(|| self.syncs.iter().find_map(|original| original.failure_v1()))
            .or_else(|| self.mount.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.ready.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.ready_transaction.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.ready_commit.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.result.as_ref()?.as_ref().err().map(|cause| cause as _))
    }
}

impl DestinationSlotStoreV1 {
    pub(crate) fn materialize_namespace_anchor_once_v4(
        &mut self,
        journal: &mut Journal,
        request: &ValidatedAttachmentAnchorRequestV1,
        exact_body: &[u8],
        admission: &VerifiedBrokerAdmission,
        loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
        original: &mut MountAttachmentAnchorOriginalV4,
        before_effect: &mut dyn FnMut(&mut MountAttachmentAnchorReceivingLoanV4<'_>) -> Result<()>,
    ) -> Result<ValidatedAttachmentAnchorResourceV1> {
        if original.entered {
            original.first.get_or_insert(First::Order);
            original.closed.get_or_insert_with(|| conflict("namespace original already entered"));
            return Err(conflict("namespace original remains closed"));
        }
        original.entered = true;
        original.entry = Some(loan.require_current_v4());
        if !matches!(original.entry, Some(Ok(()))) {
            original.first = Some(First::Entry);
            return Err(conflict("namespace Mount62 original entry refused"));
        }
        original.shape = Some(MountAttachmentAnchorPhysicalShapeDataV1::for_current_v4(
            journal, self, admission,
        ));
        let shape = match original.shape.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(shape) => shape,
            None => {
                original.first = Some(First::Shape);
                return Err(conflict("namespace shape original refused"));
            }
        };
        let demand = shape.receiving_demand_v4()?;
        original.admission = Some(loan.require_representation_v4(demand));
        if !matches!(original.admission, Some(Ok(()))) {
            original.first = Some(First::Admission);
            return Err(conflict("namespace receiving original refused"));
        }
        original.models = Some(Box::new(NamespaceMutationModelsV4::default()));
        let models = original.models.as_mut().ok_or_else(|| corrupt("namespace models absent"))?;
        models.result = Some((|| {
            loan.require_current_v4().map_err(|_| conflict("namespace Mount62 original is not current"))?;
            if request.action() == aos_proto::aos::sandbox::local::v1::AttachmentAnchorActionV1::ATTACHMENT_ANCHOR_ACTION_V1_REAP {
                return reap::apply_v4(self, journal, request, exact_body, admission,
                    loan, models, before_effect);
            }
            models.intent = Some(ValidatedAttachmentAnchorResourceV1::materializing_v1(
                request, exact_body, self.kernel_boot_id,
            ));
            let intent = models.intent.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| conflict("namespace intent is not canonical"))?;
            let key = intent.key_v1();
            if self.records.keys().any(|slot| slot.sandbox_id == *request.fence().sandbox_id()
                && slot.incarnation_id == *request.fence().incarnation_id()
                && slot.namespace_generation == request.namespace_generation())
            {
                return Err(conflict("namespace is already owned by destination slots"));
            }
            match self.namespace_anchors.records.get(&key) {
                Some(existing) if existing.lifecycle() == Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY => {
                    existing.require_request_v1(request, exact_body)?;
                    let pin = self.namespace_anchors.pins.get(&key)
                        .ok_or_else(|| corrupt("Ready namespace original is not pinned"))?;
                    if existing.physical_identity_v1() != Some((pin.identity().device,
                        pin.identity().inode, self.anchor_mount_id.get()))
                    { return Err(corrupt("Ready namespace pin changed")); }
                    models.replay_read.resolve_v4(self, &namespace_path_v1(existing),
                        existing.physical_identity_v1())?;
                    models.ready = Some(Ok(existing.clone()));
                    return Ok(());
                }
                Some(existing) if existing == intent => {}
                Some(_) => return Err(conflict("namespace original or phase changed")),
                None => {
                    self.require_capacity()?;
                    self.require_unused_operation(OperationId::from_bytes(*request.header().request_id()))?;
                    models.guards[0] = Some(before_effect(loan));
                    require_guard_v4(&models.guards[0])?;
                    models.intent_transaction = Some(namespace_transaction_v4(intent));
                    let transaction = models.intent_transaction.as_ref().and_then(|result| result.as_ref().ok())
                        .ok_or_else(|| corrupt("namespace intent transaction invalid"))?;
                    models.intent_commit = Some(journal.commit(transaction));
                    if !matches!(models.intent_commit, Some(Ok(_))) {
                        return Err(conflict("namespace intent commit retained a refusal"));
                    }
                    self.namespace_anchors.records.insert(key, intent.clone());
                }
            }
            let components = [SLOT_ROOT_COMPONENT.to_owned(), encode_hex(request.fence().sandbox_id()),
                encode_hex(request.fence().incarnation_id()), format!("{:016x}", request.namespace_generation())];
            for (index, name) in components.iter().enumerate() {
                loan.require_current_v4().map_err(|_| conflict("namespace original changed before mkdir"))?;
                models.guards[1 + 2 * index] = Some(before_effect(loan));
                require_guard_v4(&models.guards[1 + 2 * index])?;
                let (earlier, current) = models.parents.split_at_mut(index);
                let parent = if index == 0 { &self.root }
                    else { earlier[index - 1].root_v1().ok_or_else(|| corrupt("namespace parent prefix absent"))? };
                let mode = if index + 1 == components.len() { ANCHOR_DIRECTORY_MODE }
                    else { PARENT_DIRECTORY_MODE };
                current[0].enter_once_v1(parent, name, mode, self.root_owner)?;
                models.guards[2 + 2 * index] = Some(before_effect(loan));
                require_guard_v4(&models.guards[2 + 2 * index])?;
                models.syncs[index].enter_once_v1(parent)?;
            }
            let pin = models.parents[3].root_v1().ok_or_else(|| corrupt("namespace anchor absent"))?;
            models.mount = Some(MountId::from_fd(pin.as_fd()));
            let mount = models.mount.as_ref().and_then(|result| result.as_ref().ok())
                .copied().ok_or_else(|| conflict("namespace mount identity retained a refusal"))?;
            if mount != self.anchor_mount_id {
                return Err(corrupt("namespace directory is outside original Mount anchor"));
            }
            let identity = pin.identity();
            models.ready = Some(intent.ready_v1((identity.device, identity.inode, mount.get())));
            let ready = models.ready.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| corrupt("namespace Ready row invalid"))?;
            models.guards[9] = Some(before_effect(loan));
            require_guard_v4(&models.guards[9])?;
            models.ready_transaction = Some(namespace_transaction_v4(ready));
            let transaction = models.ready_transaction.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(|| corrupt("namespace Ready transaction invalid"))?;
            models.ready_commit = Some(journal.commit(transaction));
            if !matches!(models.ready_commit, Some(Ok(_))) {
                return Err(conflict("namespace Ready commit retained a refusal"));
            }
            let root = models.parents[3].take_root_once_v1()
                .ok_or_else(|| corrupt("namespace Ready original lost its physical root"))?;
            models.pin = Some(Arc::new(root));
            let pin = models.pin.as_ref().ok_or_else(|| corrupt("namespace Ready pin absent"))?;
            self.namespace_anchors.pins.insert(key, Arc::clone(pin));
            self.namespace_anchors.records.insert(key, ready.clone());
            Ok(())
        })());
        if !matches!(models.result, Some(Ok(()))) {
            original.first = Some(First::Body);
            return Err(conflict("namespace original retained a refusal"));
        }
        models.ready.as_ref().and_then(|result| result.as_ref().ok()).cloned()
            .ok_or_else(|| corrupt("completed namespace original lost its Ready record"))
    }
}

fn require_guard_v4(result: &Option<Result<()>>) -> Result<()> {
    if matches!(result, Some(Ok(()))) { Ok(()) }
    else { Err(conflict("namespace authority deadline guard refused")) }
}

fn namespace_transaction_v4(record: &ValidatedAttachmentAnchorResourceV1)
    -> std::result::Result<JournalTransaction, aos_sandbox_protocol::domain_ledger::JournalTransactionDataError> {
    let digest = Sha256::new().chain_update(b"aos.sandbox.mount.namespace-anchor.transaction.v1\0")
        .chain_update([record.lifecycle() as u8]).chain_update(record.resource_digest()).finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] { id[15] = 1; }
    JournalTransaction::new(id, vec![JournalRecord::put(RecordNamespace::MountDestinationSlot,
        record.key_v1().to_vec(), encode_attachment_anchor_resource_v1(record))])
}
