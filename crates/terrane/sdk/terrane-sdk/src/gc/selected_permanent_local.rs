//! Resolves permanent local ownership from the actual selected protected chain.
//!
//! The opaque owner borrows one selected holder and live collector Session.
//! It grants neither first ownership nor complete serving-placement permission;
//! native requests additionally require the matching current DATA qualifier.

#[path = "selected_permanent_local/physical.rs"]
mod physical;
#[path = "selected_permanent_local/request.rs"]
mod request;
#[path = "selected_permanent_local/selection.rs"]
mod selection;

#[path = "selected_permanent_local/history.rs"]
pub(crate) mod history;

pub(crate) use request::{CheckedPermanentReclaim, qualify_reclaim};

use super::{GcCheckpointEffectContext, GcControlOwner, OwnedFinalCheck};
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::SelectedObservation;
use crate::bucket::publication::receipts::RecordRead;
use crate::bucket::{BucketBinding, FileBucket};
use crate::gc::runner::{CollectionError, session::Session};
use crate::guard::{ConsumedResolver, Guard, OriginalAuthority, RetainedControls};
use crate::store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure};
use std::path::{Path, PathBuf};
use terrane_format::gc::GcLease;
use terrane_format::gc::publication::evidence::RequiredControlPin;
use terrane_format::gc::retirement::{OwnershipSlot, PermanentDeleteAuthorization, RecordPointer};

#[cfg(not(feature = "send"))]
use std::rc::Rc as Shared;
#[cfg(feature = "send")]
use std::sync::Arc as Shared;

/// Borrows independently resolved permanent ownership beneath a live holder.
pub(crate) struct CheckedPermanentLocalOwner<'operation, 'held> {
    observed: &'operation SelectedObservation<'held>,
    session: &'operation Session,
    authorization: PermanentDeleteAuthorization,
    genesis: OwnershipSlot,
    owner: OwnershipSlot,
    key: String,
    selected_owner: RecordPointer,
    guard: RecordRead,
    controls: RetainedControls,
    control_pins: Vec<RequiredControlPin>,
    backend_control: PathBuf,
    effects: GcCheckpointEffectContext,
}

impl<'operation, 'held> CheckedPermanentLocalOwner<'operation, 'held> {
    /// Borrows the exact selected namespace observation checked by this producer.
    pub(crate) fn observed(&self) -> &'operation SelectedObservation<'held> {
        self.observed
    }

    /// Borrows the same live collector Session, without renewal permission.
    pub(crate) fn session(&self) -> &'operation Session {
        self.session
    }

    /// Returns the permanently owned physical pack family.
    pub(crate) fn pack(&self) -> [u8; 16] {
        self.authorization.exclusion().pack
    }

    /// Borrows the canonical immutable authorization resolved from actual selection.
    pub(crate) fn authorization(&self) -> &PermanentDeleteAuthorization {
        &self.authorization
    }

    /// Borrows the independently checked registered destination genesis slot.
    pub(crate) fn genesis(&self) -> &OwnershipSlot {
        &self.genesis
    }

    /// Borrows the independently selected immutable owner key and authorization digest.
    pub(crate) fn selected_owner(&self) -> &RecordPointer {
        &self.selected_owner
    }

    /// Borrows the actual first winning permanent ownership slot.
    pub(crate) fn owner(&self) -> &OwnershipSlot {
        &self.owner
    }

    /// Borrows the selected mutable operation key with its immutable authorization.
    pub(crate) fn key(&self) -> &str {
        &self.key
    }

    /// Borrows the genuine configured control exclusion for same-holder refresh.
    pub(crate) fn controls(&self) -> &RetainedControls {
        &self.controls
    }

    /// Borrows the backend control directory resolved from actual registration.
    ///
    /// This namespace is distinct from consumed Original control exclusions.
    pub(crate) fn backend_control(&self) -> &Path {
        &self.backend_control
    }

    /// Borrows exact consumed Original predicates, separately from exclusion holds.
    pub(crate) fn control_pins(&self) -> &[RequiredControlPin] {
        &self.control_pins
    }

    /// Borrows the actual selected Guard preimage retained during qualification.
    pub(crate) fn guard(&self) -> &RecordRead {
        &self.guard
    }

    /// Borrows actual current lease, consumed Original predicates and retained controls.
    ///
    /// This context grants neither complete serving DATA nor fresh admission.
    pub(crate) fn effects(&self) -> &GcCheckpointEffectContext {
        &self.effects
    }

    /// Rechecks whole selection and live Session without manufacturing DATA authority.
    ///
    /// # Errors
    /// Refuses changed selected owner/control preimages, expired lease,
    /// cancellation or clock discontinuity. Native requests also retain actual
    /// configured control receipts and complete current DATA checks.
    pub(crate) async fn revalidate(&self) -> Result<(), StoreFailure> {
        self.session.recheck()?;
        self.observed.revalidate().await?;
        self.session.recheck()?;
        Ok(())
    }
}

fn denied() -> StoreFailure {
    StoreFailure::new(StoreErrorKind::Denied {
        verb: "gc-permanent-local",
        pattern: "current selected permanent local owner".into(),
    })
}

/// Resolves selected ownership and configured current controls under actual exclusion.
///
/// # Errors
/// Refuses copied visibility without ownership, unrelated keys/backends,
/// malformed or unselected immutable owner records, stale whole leases,
/// changed Guard and unavailable configured native control retention.
pub(crate) async fn qualify<'operation, 'held, F, B, V, C>(
    guard: &Guard<FileBucket<F, B, V>, C>,
    authority: &OriginalAuthority,
    session: &'operation Session,
    held: &'operation HeldBucket<'held, F, B, V, true>,
    observed: &'operation SelectedObservation<'held>,
    key: &str,
    retained: Option<&RetainedControls>,
) -> Result<CheckedPermanentLocalOwner<'operation, 'held>, CollectionError>
where
    F: LocalFs + BucketBinding,
    B: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    C: Clock,
{
    let now = session.recheck()?;
    let lease = observed
        .logical()
        .get("gc/lease")
        .and_then(Option::as_deref)
        .map(GcLease::decode)
        .transpose()?;
    session.lease().check(lease.as_ref(), now)?;
    if held.root() != observed.identity().root()
        || held.physical_identity() != observed.identity().physical_identity()
        || guard.store().publication_operator_uid() != Some(observed.configured_operator_uid())
        || !observed.identity().writable()
    {
        return Err(denied().into());
    }
    held.retained_namespace()?;
    observed.revalidate().await?;
    let resolved = selection::resolve(observed, key)?;

    let consumed = ConsumedResolver::new(guard, authority)?;
    consumed.registration(authority)?;
    let snapshot = consumed.snapshot_bytes()?;
    let guard_read = held
        .selected_guard_snapshot_record(observed)
        .await?
        .ok_or_else(denied)?;
    if guard_read.bytes() != Some(snapshot.as_slice())
        || observed.state().guard != Some(*blake3::hash(&snapshot).as_bytes())
    {
        return Err(denied().into());
    }
    let used = consumed.finish()?;
    if used.controls.is_empty() {
        return Err(denied().into());
    }
    let controls = match retained {
        Some(retained) => {
            if retained.directory() != authority.control()
                || retained.owner() != observed.configured_operator_uid()
            {
                return Err(denied().into());
            }
            super::native_collection::revalidate_controls(held.fs(), retained, &used.controls)
                .await?;
            retained.clone()
        }
        None => {
            let mut acquired = guard
                .hold_original_registration(authority, observed.identity())
                .await?;
            let retained = acquired.retain_used(&used.controls).await?;
            acquired.revalidate().await?;
            retained
        }
    };
    observed.revalidate().await?;
    super::native_collection::revalidate_controls(held.fs(), &controls, &used.controls).await?;
    session.recheck()?;
    let effects = GcCheckpointEffectContext {
        lease: session.lease().clone(),
        final_check: OwnedFinalCheck {
            check: Shared::new(session.owned_check()),
        },
        control_owners: vec![GcControlOwner {
            registration: crate::guard::consumed_registration(authority),
            configured_operator_uid: controls.owner(),
            pins: used.controls.clone(),
        }],
        controls: vec![controls.clone()],
    };
    Ok(CheckedPermanentLocalOwner {
        observed,
        session,
        authorization: resolved.authorization,
        genesis: resolved.genesis,
        owner: resolved.owner,
        selected_owner: resolved.selected_owner,
        key: key.to_owned(),
        guard: guard_read,
        controls,
        control_pins: used.controls,
        backend_control: resolved.backend_control,
        effects,
    })
}
