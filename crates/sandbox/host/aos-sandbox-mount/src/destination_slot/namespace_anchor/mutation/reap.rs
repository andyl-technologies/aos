//! Reaps one exact no-slot namespace under the genuine signed Mount62 loan.
//!
//! Root's private Delete compiler lends the completed Host disposal by issuing
//! this distinct signed verb for the old Ready digest. Mount keeps its own
//! native pin, records Reaping before unlink, and publishes Released only after
//! exact non-recursive removal, durability, independently owed posts and local
//! descriptor retirement. No Host scope DATA reconstructs a native owner.

use super::*;
use aos_sandbox_model::BrokerVerb;
use aos_sandbox_linux::path::BeneathRootResolveOriginalV2;

#[derive(Clone, Copy)]
enum First {
    Before,
    HeldBefore,
    Parent,
    Remove,
    Sync,
    HeldAfter,
    After,
}

#[derive(Default)]
pub(super) struct NamespaceReapOriginalV4 {
    before: inventory::AnchorReadOriginalV4,
    parent: inventory::AnchorReadOriginalV4,
    after: inventory::AnchorReadOriginalV4,
    held_before: HeldPinOriginalV4,
    held_after: HeldPinOriginalV4,
    before_result: Option<Result<bool>>,
    parent_result: Option<Result<()>>,
    removed: Option<std::result::Result<(), rustix::io::Errno>>,
    sync: DirectorySyncOriginalV1,
    sync_result: Option<Result<()>>,
    after_result: Option<Result<()>>,
    first: Option<First>,
}

#[derive(Default)]
struct HeldPinOriginalV4 {
    metadata: Option<std::result::Result<rustix::fs::Stat, rustix::io::Errno>>,
    mount: Option<std::result::Result<MountId, aos_linux_descriptors::Error>>,
    compared: Option<Result<()>>,
}

impl HeldPinOriginalV4 {
    fn observe_v4(
        &mut self,
        pin: &BeneathRoot,
        store: &DestinationSlotStoreV1,
        physical: (u64, u64, u64),
        linked: bool,
    ) -> Result<()> {
        self.metadata = Some(rustix::fs::fstat(pin.as_fd()));
        self.mount = Some(MountId::from_fd(pin.as_fd()));
        self.compared = Some((|| {
            let stat = self
                .metadata
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or_else(|| conflict("namespace held metadata retained a refusal"))?;
            let mount = self
                .mount
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or_else(|| conflict("namespace held mount retained a refusal"))?;
            if stat.st_dev as u64 != physical.0
                || stat.st_ino as u64 != physical.1
                || mount.get() != physical.2
                || *mount != store.anchor_mount_id
                || stat.st_uid != store.root_owner
                || stat.st_mode & 0o7777 != ANCHOR_DIRECTORY_MODE
                || (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
                || (linked && stat.st_nlink < 2)
                || (!linked && stat.st_nlink != 0)
            {
                return Err(corrupt("namespace held original changed"));
            }
            Ok(())
        })());
        if matches!(self.compared, Some(Ok(()))) {
            Ok(())
        } else {
            Err(conflict("namespace held comparison retained a refusal"))
        }
    }

    fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.metadata
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| self.mount.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.compared
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }
}

impl NamespaceReapOriginalV4 {
    pub(super) fn failure_v4(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            First::Before => self.before.failure_v4().or_else(|| {
                self.before_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::HeldBefore => self.held_before.failure_v4(),
            First::Parent => self.parent.failure_v4().or_else(|| {
                self.parent_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::Remove => self
                .removed
                .as_ref()?
                .as_ref()
                .err()
                .map(|cause| cause as _),
            First::Sync => self.sync.failure_v1().or_else(|| {
                self.sync_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
            First::HeldAfter => self.held_after.failure_v4(),
            First::After => self.after.failure_v4().or_else(|| {
                self.after_result
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            }),
        }
    }

    fn before_v4(
        &mut self,
        store: &DestinationSlotStoreV1,
        record: &ValidatedAttachmentAnchorResourceV1,
    ) -> Result<bool> {
        let path = namespace_path_v1(record);
        self.before_result = Some(
            self.before
                .resolve_optional_v4(
                    store,
                    &path,
                    ANCHOR_DIRECTORY_MODE,
                    record.physical_identity_v1(),
                )
                .map(|value| value.is_some()),
        );
        let present = match self.before_result.as_ref() {
            Some(Ok(present)) => *present,
            _ => {
                self.first = Some(First::Before);
                return Err(conflict("namespace before retained a refusal"));
            }
        };
        let physical = record
            .physical_identity_v1()
            .ok_or_else(|| corrupt("namespace physical original absent"))?;
        let pin = store.namespace_anchors.pins.get(&record.key_v1());
        if let Some(pin) = pin {
            // The service holds the one actual namespace pin. Another local
            // owning export is residual custody, never permission to unlink.
            if Arc::strong_count(pin) != 1 {
                return Err(conflict("namespace original still has an owning export"));
            }
            if self
                .held_before
                .observe_v4(pin, store, physical, present)
                .is_err()
            {
                self.first = Some(First::HeldBefore);
                return Err(conflict("namespace held before retained a refusal"));
            }
        } else if present {
            return Err(corrupt("present namespace has no original Mount pin"));
        }
        if !present && record.lifecycle() == Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY {
            return Err(corrupt("Ready namespace disappeared before Reaping"));
        }
        self.parent_result = Some((|| {
            let parent = path
                .parent()
                .ok_or_else(|| corrupt("namespace parent absent"))?;
            self.parent
                .resolve_optional_v4(store, parent, PARENT_DIRECTORY_MODE, None)?
                .ok_or_else(|| corrupt("namespace parent disappeared"))?;
            Ok(())
        })());
        if !matches!(self.parent_result, Some(Ok(()))) {
            self.first = Some(First::Parent);
            return Err(conflict("namespace parent retained a refusal"));
        }
        Ok(present)
    }

    // All three posts are prepaid before the causative unlink. They run
    // independently even when unlink fails, without another healthy/D gate.
    fn remove_and_posts_v4(
        &mut self,
        store: &DestinationSlotStoreV1,
        record: &ValidatedAttachmentAnchorResourceV1,
        present: bool,
    ) -> Result<()> {
        let parent = self
            .parent
            .borrowed_pin_v4()
            .ok_or_else(|| corrupt("namespace parent original absent"))?;
        if present {
            let name = format!("{:016x}", record.namespace_generation());
            self.removed = Some(super::super::physical::unlink_empty_directory_v1(
                parent.as_fd(),
                &name,
            ));
            // NOENT is ambiguous after a positive named before; only the
            // separate durable Reaping+already-absent resume omits unlink.
            if !matches!(self.removed, Some(Ok(()))) {
                self.first = Some(First::Remove);
            }
        }
        self.sync_result = Some(self.sync.enter_descriptor_once_v1(parent.as_fd()));
        if !matches!(self.sync_result, Some(Ok(()))) {
            self.first.get_or_insert(First::Sync);
        }
        if let Some(pin) = store.namespace_anchors.pins.get(&record.key_v1()) {
            let physical = record
                .physical_identity_v1()
                .ok_or_else(|| corrupt("namespace physical original absent"))?;
            if self
                .held_after
                .observe_v4(pin, store, physical, false)
                .is_err()
            {
                self.first.get_or_insert(First::HeldAfter);
            }
        }
        self.after_result = Some((|| {
            if self
                .after
                .resolve_path_optional_v4(store, &namespace_path_v1(record))?
            {
                return Err(corrupt("namespace remains named after removal"));
            }
            Ok(())
        })());
        if !matches!(self.after_result, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        if self.first.is_some() {
            Err(conflict(
                "namespace removal or owed post retained a refusal",
            ))
        } else {
            Ok(())
        }
    }

    fn released_absent_v4(
        &mut self,
        store: &DestinationSlotStoreV1,
        record: &ValidatedAttachmentAnchorResourceV1,
    ) -> Result<()> {
        if store.namespace_anchors.pins.contains_key(&record.key_v1()) {
            return Err(corrupt("Released namespace retains a Mount pin"));
        }
        self.after_result = Some((|| {
            if self
                .after
                .resolve_path_optional_v4(store, &namespace_path_v1(record))?
            {
                return Err(corrupt("Released namespace remains named"));
            }
            Ok(())
        })());
        if matches!(self.after_result, Some(Ok(()))) {
            Ok(())
        } else {
            self.first = Some(First::After);
            Err(conflict("Released namespace after retained a refusal"))
        }
    }

    fn retire_positive_native_v4(&mut self) {
        // Only the entire successful native interval retires its exclusive
        // descriptors. Results and every charged debit remain resident.
        self.before = Default::default();
        self.parent = Default::default();
        self.after = Default::default();
        self.sync = Default::default();
    }
}

pub(super) fn receiving_obligations_v4() -> Option<(usize, usize, usize)> {
    let resolver = BeneathRootResolveOriginalV2::receiving_obligations_v2(88)?;
    let sync = DirectorySyncOriginalV1::receiving_obligations_v1()?;
    let memory = std::mem::size_of::<NamespaceReapOriginalV4>()
        .checked_mul(2)?
        .checked_add(resolver.0.checked_mul(3)?)?
        .checked_add(sync.0)?
        .checked_add(MAXIMUM_ATTACHMENT_ANCHOR_RECORD_BYTES_V1.checked_mul(8)?)?
        .checked_add(88usize.checked_mul(4)?)?;
    Some((
        memory,
        resolver.1.checked_mul(3)?.checked_add(sync.1)?,
        resolver.2.checked_mul(3)?,
    ))
}

impl DestinationSlotStoreV1 {
    pub(crate) fn require_released_namespace_replay_v5(
        &self,
        request: &ValidatedAttachmentAnchorRequestV1,
        body: &[u8],
    ) -> Result<()> {
        let current = self.namespace_anchors.records.get(&request_key_v4(request))
            .ok_or_else(|| corrupt("Complete Reap lost its Released original"))?;
        if current.lifecycle() != Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED
            || current.resource_kernel_boot_id() != &self.kernel_boot_id {
            return Err(corrupt("Complete Reap is not a same-boot Released original"));
        }
        current.require_request_v1(request, body)?;
        Ok(())
    }
}

fn request_key_v4(request: &ValidatedAttachmentAnchorRequestV1) -> [u8; 40] {
    let mut key = [0; 40];
    key[..16].copy_from_slice(request.binding_fence().sandbox_id());
    key[16..32].copy_from_slice(request.binding_fence().incarnation_id());
    key[32..].copy_from_slice(&request.namespace_generation().to_be_bytes());
    key
}

// Same private writer, signed admission, original Source loan and deadline as
// materialization. The old resource fence is deliberately not the new cleanup
// fence; the canonical signed semantics already bind both independently.
pub(super) fn apply_v4(
    store: &mut DestinationSlotStoreV1,
    journal: &mut Journal,
    request: &ValidatedAttachmentAnchorRequestV1,
    body: &[u8],
    admission: &VerifiedBrokerAdmission,
    loan: &mut MountAttachmentAnchorReceivingLoanV4<'_>,
    models: &mut NamespaceMutationModelsV4,
    before_effect: &mut dyn FnMut(&mut MountAttachmentAnchorReceivingLoanV4<'_>) -> Result<()>,
) -> Result<()> {
    let semantics =
        aos_sandbox_protocol::mount_attachment_anchor::canonical_attachment_anchor_semantics_v1(
            request,
        )
        .map_err(|_| conflict("namespace Reap semantics invalid"))?;
    if admission.effect.verb() != BrokerVerb::MountReapAttachmentAnchor
        || admission.effect.verb() != semantics.verb()
        || admission.effect.target() != semantics.target()
        || admission.effect.request_id() != request.header().request_id()
        || admission.effect.transport_request_digest().as_bytes()
            != &<[u8; 32]>::from(Sha256::digest(body))
    {
        return Err(conflict("namespace Reap has no exact signed admission"));
    }
    // The selected no-slot profile has no native/FUSE/source resources. An
    // unknown or foreign row remains quarantined rather than recursively
    // inventing a cleanup owner from its DATA. Ordinary attachment profiles
    // retain their distinct existing resource/custody reconciliation engine.
    if journal.records(RecordNamespace::Operation).next().is_some()
        || journal
            .records(RecordNamespace::MountSourcePin)
            .next()
            .is_some()
        || store.records.keys().any(|slot| {
            slot.sandbox_id == *request.binding_fence().sandbox_id()
                && slot.incarnation_id == *request.binding_fence().incarnation_id()
                && slot.namespace_generation == request.namespace_generation()
        })
    {
        return Err(conflict(
            "namespace Reap has residual Mount resource custody",
        ));
    }
    let key = request_key_v4(request);
    let current = store
        .namespace_anchors
        .records
        .get(&key)
        .cloned()
        .ok_or_else(|| conflict("namespace Reap original is absent"))?;
    if current.fence() != request.binding_fence()
        || current.namespace_generation() != request.namespace_generation()
        || current.sandbox_spec() != request.sandbox_spec()
        || current.resource_kernel_boot_id() != &store.kernel_boot_id
    {
        return Err(conflict(
            "namespace Reap original fence, Spec or boot changed",
        ));
    }
    let correlation = (
        *request.header().request_id(),
        <[u8; 32]>::from(Sha256::digest(body)),
        *request
            .expected_resource_digest()
            .ok_or_else(|| conflict("namespace Ready digest absent"))?,
    );
    match current.lifecycle() {
        Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY => {
            if !store.namespace_anchors.pins.contains_key(&key) {
                return Err(corrupt("Ready namespace lost its actual Mount pin"));
            }
            store.require_unused_operation(OperationId::from_bytes(
                *request.header().request_id(),
            ))?;
            models.intent = Some(current.reaping_v1(request, body));
        }
        Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_REAPING
        | Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED
            if current.reap_v1() == Some(&correlation) =>
        {
            models.intent = Some(Ok(current.clone()));
        }
        _ => return Err(conflict("namespace Reap phase or operation changed")),
    }
    if current.lifecycle() == Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_RELEASED {
        current.require_request_v1(request, body)?;
        models.reap.released_absent_v4(store, &current)?;
        models.ready = Some(Ok(current));
        return Ok(());
    }
    let intent = models
        .intent
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or_else(|| conflict("namespace Reaping transition invalid"))?;
    let present = models.reap.before_v4(store, &current)?;
    if current.lifecycle() == Phase::ATTACHMENT_ANCHOR_LIFECYCLE_V1_READY {
        models.guards[0] = Some(before_effect(loan));
        require_guard_v4(&models.guards[0])?;
        models.intent_transaction = Some(namespace_transaction_v4(intent));
        let transaction = models
            .intent_transaction
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or_else(|| corrupt("namespace Reaping transaction invalid"))?;
        models.intent_commit = Some(journal.commit(transaction));
        if !matches!(models.intent_commit, Some(Ok(_))) {
            return Err(conflict("namespace Reaping commit retained a refusal"));
        }
        store.namespace_anchors.records.insert(key, intent.clone());
    }
    models.guards[1] = Some(before_effect(loan));
    require_guard_v4(&models.guards[1])?;
    models.reap.remove_and_posts_v4(store, intent, present)?;
    models.ready = Some(intent.released_v1());
    let released = models
        .ready
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or_else(|| corrupt("namespace Released transition invalid"))?;
    models.guards[2] = Some(before_effect(loan));
    require_guard_v4(&models.guards[2])?;
    models.ready_transaction = Some(namespace_transaction_v4(released));
    let transaction = models
        .ready_transaction
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .ok_or_else(|| corrupt("namespace Released transaction invalid"))?;
    models.ready_commit = Some(journal.commit(transaction));
    if !matches!(models.ready_commit, Some(Ok(_))) {
        return Err(conflict("namespace Released commit retained a refusal"));
    }
    models.reap.retire_positive_native_v4();
    store.namespace_anchors.pins.remove(&key);
    store
        .namespace_anchors
        .records
        .insert(key, released.clone());
    Ok(())
}

#[cfg(test)]
mod tests;
