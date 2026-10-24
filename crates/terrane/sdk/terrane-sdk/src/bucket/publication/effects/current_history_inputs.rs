//! Closes current-history physical inputs through the native read-only lane.
//!
//! Ordinary DATA retains its original descriptors and exact consumed bytes.
//! Selected controls and Original records retain their independent protected
//! policies. The resulting receipt supplies no ACL decision, candidate history,
//! publication authority, or durability acknowledgment.

use super::{
    BucketBinding, FencePolicy, Frame, LocalFs, MetadataStamp, SelectedObservation, StoreFailure,
    corrupt, duplicate, io_failure, unsupported,
};
use crate::bucket::publication::receipts::RecordRead;
use crate::guard::{PendingCurrentReadCheck, RetainedControls};
use crate::store::{NativeOrdinaryRead, OrdinaryReadOutcome};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use terrane_format::bucket::BucketKey;
use terrane_format::gc::publication::BackendBinding;

/// Retains the exact inputs acknowledged by one physical current-history close.
///
/// Only this native factory constructs the receipt. The owning Guard separately
/// checks purpose, reader, holder, token invocation and complete consumed pins
/// before promoting its pending history.
pub(crate) struct CurrentHistoryPhysicalInputs<'scope, 'held> {
    observed: &'scope SelectedObservation<'held>,
    // Keep captured descriptors and exclusions alive through owning promotion.
    _controls: Vec<RetainedControls>,
    _original_reads: Vec<RecordRead>,
    _payload_reads: Vec<RecordRead>,
}

impl<'scope, 'held> CurrentHistoryPhysicalInputs<'scope, 'held> {
    /// Borrows the same actual selected observation used by the closing worker.
    pub(crate) fn observed(&self) -> &'scope SelectedObservation<'held> {
        self.observed
    }

    /// Borrows the exact administrative receipts retained through native closing.
    #[cfg(test)]
    pub(crate) fn controls(&self) -> &[RetainedControls] {
        &self._controls
    }

    /// Borrows the original whole-ref and selected snapshot recipes.
    #[cfg(test)]
    pub(crate) fn original_reads(&self) -> &[RecordRead] {
        &self._original_reads
    }

    /// Borrows every original recipe consumed by the sealed current reader.
    #[cfg(test)]
    pub(crate) fn payload_reads(&self) -> &[RecordRead] {
        &self._payload_reads
    }
}

/// Preserves a token refusal carried through the native I/O interface.
fn current_read_failure(error: std::io::Error) -> StoreFailure {
    let kind = error.kind();
    match error.into_inner() {
        Some(source) => match source.downcast::<StoreFailure>() {
            Ok(failure) => *failure,
            Err(source) => io_failure(std::io::Error::new(kind, source)),
        },
        None => io_failure(std::io::Error::from(kind)),
    }
}

/// Imports original reads without converting ordinary DATA into effect inputs.
fn retain_reads(
    frame: &mut Frame,
    reads: &[RecordRead],
    root: &Path,
    control: &Path,
    ordinary: &mut Vec<Arc<super::RetainedPayloadRanges>>,
    owner: u32,
) -> Result<(), StoreFailure> {
    for read in reads {
        let policy = if read.path().starts_with(control) {
            FencePolicy::ProtectedRecord { owner }
        } else if read.path().starts_with(root) {
            FencePolicy::Payload { owner }
        } else {
            return Err(corrupt());
        };
        if let Some(retained) = read.ordinary_retained() {
            // Protected selected records can never be satisfied by an ordinary
            // descriptor, even when its current mode happens to be private.
            if read.path().starts_with(control) {
                return Err(unsupported());
            }
            ordinary.push(Arc::clone(retained));
        } else {
            frame.retained_record_read(read.retained_payload().ok_or_else(unsupported)?, policy)?;
        }
    }
    Ok(())
}

/// Freshly closes the actual current selection and every original read recipe.
///
/// The worker owns duplicates of the actual namespace and administrative holds
/// through its final synchronous token check, including cancellation of its
/// waiter. No writable adapter, mutation frame or actor grant is constructed.
///
/// # Errors
/// Refuses foreign namespace bindings, missing original recipes, changed bodies,
/// ancestors, protection or selected inputs, expired tokens and unavailable
/// native execution. Native token refusals preserve their store error taxonomy.
pub(crate) async fn close_current_history_inputs<'scope, 'held, F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &'scope SelectedObservation<'held>,
    controls: &[RetainedControls],
    original_reads: &[RecordRead],
    payload_reads: Vec<RecordRead>,
    current: &PendingCurrentReadCheck,
) -> Result<CurrentHistoryPhysicalInputs<'scope, 'held>, StoreFailure> {
    close_inputs(
        fs,
        observed,
        controls,
        original_reads,
        payload_reads,
        current,
        None,
    )
    .await
}

impl<'scope, 'held> CurrentHistoryPhysicalInputs<'scope, 'held> {
    /// Closes the actual paired transition beside one complete held history.
    ///
    /// # Errors
    /// Preserves original destination/source recipes, issuer/current/signer and
    /// unchanged operation-deadline refusals before owning promotion.
    pub(crate) async fn close_held<F: LocalFs + BucketBinding>(
        fs: &F,
        observed: &'scope SelectedObservation<'held>,
        controls: &[RetainedControls],
        original_reads: &[RecordRead],
        payload_reads: Vec<RecordRead>,
        current: &PendingCurrentReadCheck,
        transition: Option<&crate::selected_bridge::native_guard::disclosure::GuardTransition<'_>>,
    ) -> Result<Self, StoreFailure> {
        close_inputs(
            fs,
            observed,
            controls,
            original_reads,
            payload_reads,
            current,
            transition,
        )
        .await
    }
}

async fn close_inputs<'scope, 'held, F: LocalFs + BucketBinding>(
    fs: &F,
    observed: &'scope SelectedObservation<'held>,
    controls: &[RetainedControls],
    original_reads: &[RecordRead],
    payload_reads: Vec<RecordRead>,
    current: &PendingCurrentReadCheck,
    transition: Option<&crate::selected_bridge::native_guard::disclosure::GuardTransition<'_>>,
) -> Result<CurrentHistoryPhysicalInputs<'scope, 'held>, StoreFailure> {
    current.check_paired_transition(transition)?;
    if let Some(transition) = transition {
        transition.check_selected(fs, observed).await?;
    }
    let mut controls = controls.to_vec();
    let mut original_reads = original_reads.to_vec();
    if let Some(transition) = transition {
        controls.push(transition.source_controls().clone());
        original_reads.push(transition.old_guard().clone());
    }
    let owner = observed.configured_operator_uid();
    let BackendBinding::Local {
        root,
        root_device,
        root_inode,
        coordination_device,
        coordination_inode,
    } = &observed.state().binding
    else {
        return Err(unsupported());
    };
    if root.as_slice() != observed.identity().root().as_os_str().as_encoded_bytes()
        || (
            (*root_device, *root_inode),
            (*coordination_device, *coordination_inode),
        ) != observed.identity().physical_identity()
        || controls.first().ok_or_else(unsupported)?.owner() != owner
    {
        return Err(corrupt());
    }
    let root = observed.identity().root();
    let registration = observed
        .physical_reads()
        .first()
        .filter(|read| {
            read.path()
                .file_name()
                .is_some_and(|name| name == "backend-registration.cbor")
        })
        .ok_or_else(corrupt)?;
    let control = registration.path().parent().ok_or_else(corrupt)?;
    let mut exclusions = vec![duplicate(observed.identity().retained_namespace()?)?];
    let source_descriptor = if let Some(transition) = transition {
        let descriptor = exclusions.len();
        exclusions.push(duplicate(
            transition
                .source_selected()
                .identity()
                .retained_namespace()?,
        )?);
        Some(descriptor)
    } else {
        None
    };
    let mut descriptors = Vec::with_capacity(controls.len());
    for retained in &controls {
        let start = exclusions.len();
        for exclusion in retained.exclusions().iter() {
            exclusions.push(duplicate(exclusion)?);
        }
        if start == exclusions.len() {
            return Err(unsupported());
        }
        descriptors.push(start..exclusions.len());
    }
    let mut frame = Frame {
        exclusions: exclusions.into(),
        pairs: Vec::new(),
        names: Vec::new(),
        reads: Vec::new(),
        parents: BTreeMap::new(),
        final_check: None,
        owner,
        writes: None,
    };
    frame
        .name(
            fs,
            root.to_owned(),
            (*root_device, *root_inode),
            FencePolicy::NamespaceDirectory { owner },
            None,
        )
        .await?;
    let key = BucketKey::parse("CAPABILITIES").map_err(|_| corrupt())?;
    frame
        .name(
            fs,
            root.join(key.lock_name()),
            (*coordination_device, *coordination_inode),
            FencePolicy::NamespaceCoordination { owner },
            Some(0),
        )
        .await?;
    frame
        .name(
            fs,
            control.to_owned(),
            observed.control_identity(),
            FencePolicy::PrivateControlDirectory { owner },
            None,
        )
        .await?;

    for (retained, descriptors) in controls.iter().zip(descriptors) {
        let control_owner = retained.owner();
        for ancestor in retained.ancestors() {
            let metadata = fs
                .symlink_metadata(ancestor.path())
                .await
                .map_err(io_failure)?;
            let stamp = MetadataStamp::checked(&metadata).map_err(io_failure)?;
            FencePolicy::ProtectedAncestor {
                owner: control_owner,
            }
            .validate(stamp)
            .map_err(io_failure)?;
            if stamp.identity != ancestor.identity()
                || (stamp.owner, stamp.mode & 0o7777) != ancestor.protection()
                || frame
                    .parents
                    .get(ancestor.path())
                    .is_some_and(|(previous, _)| !stamp.same_incarnation(*previous))
            {
                return Err(corrupt());
            }
            frame
                .parents
                .insert(ancestor.path().to_owned(), (stamp, control_owner));
        }
        let (directory, lock) = retained.identities();
        frame
            .name(
                fs,
                retained.directory().to_owned(),
                directory,
                FencePolicy::PrivateControlDirectory {
                    owner: control_owner,
                },
                None,
            )
            .await?;
        for descriptor in descriptors {
            frame
                .name(
                    fs,
                    retained.directory().join("retention.lock"),
                    lock,
                    FencePolicy::ProtectedRecord {
                        owner: control_owner,
                    },
                    Some(descriptor),
                )
                .await?;
        }
        for record in retained.records() {
            let metadata = fs
                .symlink_metadata(record.path())
                .await
                .map_err(io_failure)?;
            if MetadataStamp::checked(&metadata)
                .map_err(io_failure)?
                .identity
                != record.identity()
            {
                return Err(corrupt());
            }
            frame
                .observed_read(
                    fs,
                    record.path(),
                    Some(record.bytes()),
                    Some(&metadata),
                    FencePolicy::ProtectedRecord {
                        owner: control_owner,
                    },
                )
                .await?;
        }
    }
    let mut ordinary = Vec::new();
    retain_reads(
        &mut frame,
        observed.physical_reads(),
        root,
        control,
        &mut ordinary,
        owner,
    )?;
    retain_reads(
        &mut frame,
        &original_reads,
        root,
        control,
        &mut ordinary,
        owner,
    )?;
    retain_reads(
        &mut frame,
        &payload_reads,
        root,
        control,
        &mut ordinary,
        owner,
    )?;
    if let (Some(transition), Some(descriptor)) = (transition, source_descriptor) {
        append_source(&mut frame, fs, transition, descriptor, &mut ordinary).await?;
    }

    current.recheck()?;
    let request = NativeOrdinaryRead::for_projection(
        frame.current_read_projection(ordinary, current.clone())?,
    );
    let record = fs
        .read_ordinary_record(request)
        .await
        .map_err(current_read_failure)?
        .ok_or_else(unsupported)?;
    current.recheck()?;
    if !matches!(
        record.into_outcome(),
        OrdinaryReadOutcome::ProjectionChecked
    ) {
        return Err(corrupt());
    }
    Ok(CurrentHistoryPhysicalInputs {
        observed,
        _controls: controls,
        _original_reads: original_reads,
        _payload_reads: payload_reads,
    })
}

/// Appends only the original source recipes under their independent owner policy.
async fn append_source<F: LocalFs + BucketBinding>(
    frame: &mut Frame,
    fs: &F,
    transition: &crate::selected_bridge::native_guard::disclosure::GuardTransition<'_>,
    descriptor: usize,
    ordinary: &mut Vec<Arc<super::RetainedPayloadRanges>>,
) -> Result<(), StoreFailure> {
    let source = transition.source_selected();
    let owner = source.configured_operator_uid();
    let BackendBinding::Local {
        root,
        root_device,
        root_inode,
        coordination_device,
        coordination_inode,
    } = &source.state().binding
    else {
        return Err(unsupported());
    };
    if root.as_slice() != source.identity().root().as_os_str().as_encoded_bytes()
        || (
            (*root_device, *root_inode),
            (*coordination_device, *coordination_inode),
        ) != source.identity().physical_identity()
    {
        return Err(corrupt());
    }
    let root = source.identity().root();
    let registration = source
        .physical_reads()
        .first()
        .filter(|read| {
            read.path()
                .file_name()
                .is_some_and(|name| name == "backend-registration.cbor")
        })
        .ok_or_else(corrupt)?;
    let control = registration.path().parent().ok_or_else(corrupt)?;
    frame
        .name(
            fs,
            root.to_owned(),
            (*root_device, *root_inode),
            FencePolicy::NamespaceDirectory { owner },
            None,
        )
        .await?;
    let key = BucketKey::parse("CAPABILITIES").map_err(|_| corrupt())?;
    frame
        .name(
            fs,
            root.join(key.lock_name()),
            (*coordination_device, *coordination_inode),
            FencePolicy::NamespaceCoordination { owner },
            Some(descriptor),
        )
        .await?;
    frame
        .name(
            fs,
            control.to_owned(),
            source.control_identity(),
            FencePolicy::PrivateControlDirectory { owner },
            None,
        )
        .await?;
    retain_reads(
        frame,
        source.physical_reads(),
        root,
        control,
        ordinary,
        owner,
    )?;
    retain_reads(
        frame,
        transition.source_reads(),
        root,
        control,
        ordinary,
        owner,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "current_history_inputs/tests.rs"]
mod tests;
