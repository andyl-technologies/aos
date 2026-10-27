//! Keeps full Hold fields and exact groups owned throughout later read errors.

use super::*;
use crate::protocol_snapshot::owned11::typed::Native17Build;

/// Owns the concrete Hold construction and its final typed DATA.
#[derive(Default)]
pub(crate) struct CurrentControlHold17ReadAttempt {
    started: bool,
    completed: Option<CurrentControlHold17Data>,
    groups: Option<CurrentControlHold17GroupIds>,
    schema: Option<HoldSchema17>,
    creator: Option<u32>,
    thread: Option<ThreadRole17>,
    control_identity_role: Option<ControlIdentity17Data>,
    phase: Option<HoldPhase17Data>,
    cursor: Option<Position>,
    inventory_hash: Option<HashRef>,
    inventory_hash_attempt: <HashRef as Native17Build>::Attempt,
    group: Option<usize>,
}

impl CurrentControlHold17ReadAttempt {
    /// Borrows the completed Hold while keeping it in the caller's once owner.
    pub(crate) fn completed_data(&self) -> Option<&CurrentControlHold17Data> {
        self.completed.as_ref()
    }

    /// Transfers a complete Hold only after its enclosing read succeeds.
    pub(crate) fn take_completed_data(&mut self) -> Option<CurrentControlHold17Data> {
        self.completed.take()
    }

    /// Borrows a retained inventory hash even if trailing fields or aliases fail.
    pub(crate) fn partial_inventory_hash_data(&self) -> Option<&HashRef> {
        self.inventory_hash.as_ref()
    }

    /// Observes completed and still-pending hash backing without fake Rc rows.
    ///
    /// # Errors
    /// Refuses observer exhaustion or checked retained-backing overflow.
    pub(crate) fn observe_attempt_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        if let Some(completed) = &self.completed {
            observer.observe(&completed.inventory_hash)?;
        }
        if let Some(hash) = &self.inventory_hash {
            observer.observe(hash)?;
        }
        HashRef::observe_attempt_data(&self.inventory_hash_attempt, observer)
    }

    pub(crate) fn read_into(
        &mut self,
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<CurrentControlHold17GroupIds, ProviderError> {
        if self.started {
            return Err(ProviderError::Conflict(
                "native17 Hold read already attempted",
            ));
        }
        self.started = true;

        let start = ledger.rows.encoded_position();
        let layout = size_of::<PacketCompleteRestorePhysicalHold>();
        if ledger.row_aligned(
            MetadataRecordKind::Shared,
            1,
            align_of::<PacketCompleteRestorePhysicalHold>(),
        )? != layout
        {
            return Err(invalid());
        }
        let group = ledger.shared_begin(MetadataSharedKind::NativeRestoredPhysicalHold)?;
        self.group = Some(group);
        let mut fields = Fields::object(input)?;
        self.schema = ledger.read::<HoldSchema17>(fields.named("schema")?, build)?;
        self.creator = ledger.read::<u32>(fields.named("creator")?, build)?;
        self.thread = ledger.read::<ThreadRole17>(fields.named("thread")?, build)?;
        let identity = ledger
            .read::<ControlIdentity17Data>(fields.named("control_identity_role")?, true)?
            .ok_or_else(invalid)?;
        let capture_identity = identity.group;
        self.control_identity_role = build.then_some(identity);
        self.phase = ledger.read::<HoldPhase17Data>(fields.named("phase")?, build)?;
        self.cursor = ledger.read::<Position>(fields.named("cursor")?, build)?;
        read_owned_field::<HashRef>(
            fields.named("inventory_hash")?,
            ledger,
            build,
            &mut self.inventory_hash_attempt,
            &mut self.inventory_hash,
        )?;
        fields.finish()?;
        let rows = ledger.rows.encoded_between(start)?;
        ledger.shared_finish(group, layout, input, rows)?;
        let groups = CurrentControlHold17GroupIds {
            hold: group,
            capture_identity,
        };
        self.groups = Some(groups);
        if !build {
            return Ok(groups);
        }
        self.finish_data()?;
        Ok(groups)
    }

    fn finish_data(&mut self) -> Result<(), ProviderError> {
        if self.completed.is_some()
            || self.schema.is_none()
            || self.creator.is_none()
            || self.thread.is_none()
            || self.control_identity_role.is_none()
            || self.phase.is_none()
            || self.cursor.is_none()
            || self.inventory_hash.is_none()
            || self.group.is_none()
        {
            return Err(invalid());
        }
        self.completed = Some(CurrentControlHold17Data {
            schema: self.schema.take().ok_or_else(invalid)?,
            creator: self.creator.take().ok_or_else(invalid)?,
            thread: self.thread.take().ok_or_else(invalid)?,
            control_identity_role: self.control_identity_role.take().ok_or_else(invalid)?,
            phase: self.phase.take().ok_or_else(invalid)?,
            cursor: self.cursor.take().ok_or_else(invalid)?,
            inventory_hash: self.inventory_hash.take().ok_or_else(invalid)?,
            group: self.group.take().ok_or_else(invalid)?,
        });
        Ok(())
    }
}

/// Reads a full Hold into a concrete attempt retained before entry.
///
/// # Errors
/// Refuses reused attempts, malformed fields or mismatched source rows/aliases;
/// all previously completed fields remain in the supplied owner on error.
pub(crate) fn read_current_control_hold_root17_into_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    attempt: &mut CurrentControlHold17ReadAttempt,
) -> Result<CurrentControlHold17GroupIds, ProviderError> {
    attempt.read_into(input, ledger, true)
}

impl Native17Build for CurrentControlHold17Data {
    type Attempt = CurrentControlHold17ReadAttempt;

    fn read_into_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        attempt: &mut Self::Attempt,
    ) -> Result<(), ProviderError> {
        attempt.read_into(input, ledger, true).map(|_| ())
    }

    fn preflight_data(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        let mut attempt = CurrentControlHold17ReadAttempt::default();
        attempt.read_into(input, ledger, false).map(|_| ())
    }

    fn observe_attempt_data(
        attempt: &Self::Attempt,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        attempt.observe_attempt_data(observer)
    }

    fn observe_output_data(
        value: &Self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        observer.observe(&value.inventory_hash)
    }

    fn output_data(attempt: &Self::Attempt) -> Option<&Self> {
        attempt.completed_data()
    }

    fn take_output_data(attempt: &mut Self::Attempt) -> Option<Self> {
        attempt.take_completed_data()
    }
}
