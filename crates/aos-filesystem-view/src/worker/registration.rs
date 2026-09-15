//! Journal-shaped pure lifecycle for connection-local passthrough registrations.
//!
//! The model coalesces opens for one verified backing, separates registration
//! credit from open-reference credit, and never permits the final worker
//! RELEASE until `BACKING_CLOSE` is confirmed. State transitions become durable
//! only when the broker canonically persists [`PassthroughRegistrations::snapshot`]
//! before the corresponding external effect or reply. OS descriptors, journal
//! fsync, and ioctl effects remain owned by that adapter.
//!
//! ```text
//! record-count:u32be || repeated(
//!   callback-reducer-commitment[32] || operation:u64be || phase:u8 ||
//!   backing-id-or-zero:u64be ||
//!   descriptor-commitment-or-zero[32] || references:u64be ||
//!   canonical-backing-identity
//! )
//! ```

use super::durable::{Cursor, DurableStateError, Writer};
use super::{BackingIdentity, ConnectionLease, DataError, PreparedFuseConnection};

/// Bounds retained registrations and associated consumer opens.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationLimits {
    /// Maximum distinct backing registrations on the connection.
    pub maximum_registrations: usize,
    /// Maximum pending and active opens across registrations.
    pub maximum_open_references: u64,
}

/// Identifies one durable registration operation without exposing a backing ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationOperation(u64);

impl RegistrationOperation {
    /// Returns the durable operation sequence for journal encoding.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Describes the durable phase of one registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationPhase {
    /// A slot is persisted before `BACKING_OPEN` begins.
    Pending,
    /// The returned selector is durably recorded and may be published.
    Active,
    /// The final release is waiting for `BACKING_CLOSE` confirmation.
    Closing,
    /// Effect completion cannot be determined; the connection must be replaced.
    Ambiguous,
}

/// Requests one external effect in strict durable order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationAction {
    /// Registers the verified backing for the pending operation.
    OpenBacking { operation: RegistrationOperation },
    /// Reuses the already active selector without another ioctl.
    PublishCoalesced { operation: RegistrationOperation },
    /// Closes the selector before releasing the final worker open.
    CloseBeforeRelease { operation: RegistrationOperation },
    /// Aborts the still-pending worker open after definite registration failure.
    AbortWorkerOpen { operation: RegistrationOperation },
    /// Releases worker state after close confirmation or a nonfinal reference.
    ReleaseWorkerOpen { operation: RegistrationOperation },
    /// Tears down and replaces the connection after ambiguous external state.
    ReplaceConnection,
}

#[derive(Clone, Copy)]
struct Registration {
    operation: RegistrationOperation,
    backing: BackingIdentity,
    phase: RegistrationPhase,
    backing_id: Option<u64>,
    descriptor_commitment: Option<[u8; 32]>,
    references: u64,
}

/// Opaque canonically decoded durable registration record.
#[derive(Clone, Copy)]
pub struct DurableRegistrationRecord {
    authority_binding: [u8; 32],
    callback_reducer_commitment: [u8; 32],
    operation: RegistrationOperation,
    backing: BackingIdentity,
    phase: RegistrationPhase,
    backing_id: Option<u64>,
    descriptor_commitment: Option<[u8; 32]>,
    references: u64,
}

impl DurableRegistrationRecord {
    /// Creates a record after the broker journal verifies canonical bytes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_canonical_journal(
        authority_binding: [u8; 32],
        callback_reducer_commitment: [u8; 32],
        operation: u64,
        backing: BackingIdentity,
        phase: RegistrationPhase,
        backing_id: Option<u64>,
        descriptor_commitment: Option<[u8; 32]>,
        references: u64,
    ) -> Result<Self, DataError> {
        if authority_binding == [0; 32]
            || callback_reducer_commitment == [0; 32]
            || operation == 0
            || references == 0
            || (phase == RegistrationPhase::Pending
                && (backing_id.is_some() || descriptor_commitment.is_some() || references != 1))
            || (matches!(
                phase,
                RegistrationPhase::Active | RegistrationPhase::Closing
            ) && (!matches!(backing_id, Some(value) if value != 0)
                || !matches!(descriptor_commitment, Some(value) if value != [0; 32])))
            || matches!(backing_id, Some(0))
            || backing_id.is_some() != descriptor_commitment.is_some()
            || matches!(descriptor_commitment, Some(value) if value == [0; 32])
            || (phase == RegistrationPhase::Closing && references != 1)
        {
            return Err(DataError::IntegrityFailure);
        }
        Ok(Self {
            authority_binding,
            callback_reducer_commitment,
            operation: RegistrationOperation(operation),
            backing,
            phase,
            backing_id,
            descriptor_commitment,
            references,
        })
    }

    /// Returns the non-authorizing connection commitment covering this record.
    #[must_use]
    pub const fn authority_binding(&self) -> [u8; 32] {
        self.authority_binding
    }

    /// Returns the worker-minted callback-reducer commitment for this record.
    #[must_use]
    pub const fn callback_reducer_commitment(&self) -> [u8; 32] {
        self.callback_reducer_commitment
    }

    /// Returns the durable operation identity.
    #[must_use]
    pub const fn operation(&self) -> RegistrationOperation {
        self.operation
    }

    /// Returns the verified backing bound to the record.
    #[must_use]
    pub const fn backing(&self) -> BackingIdentity {
        self.backing
    }

    /// Returns the durable registration phase.
    #[must_use]
    pub const fn phase(&self) -> RegistrationPhase {
        self.phase
    }

    /// Returns the recorded connection-local selector, when known.
    #[must_use]
    pub const fn backing_id(&self) -> Option<u64> {
        self.backing_id
    }

    /// Returns the exact descriptor identity commitment, when known.
    #[must_use]
    pub const fn descriptor_commitment(&self) -> Option<[u8; 32]> {
        self.descriptor_commitment
    }

    /// Returns the exact number of associated worker opens.
    #[must_use]
    pub const fn references(&self) -> u64 {
        self.references
    }
}

/// Owns bounded durable registration state for one authority-bound connection.
pub struct PassthroughRegistrations {
    authority_binding: [u8; 32],
    callback_reducer_commitment: [u8; 32],
    lease: ConnectionLease,
    limits: RegistrationLimits,
    entries: Vec<Registration>,
    references: u64,
    next_operation: u64,
}

impl PassthroughRegistrations {
    /// Allocates the exact admitted registration table once.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::InvalidLimit`] for zero bounds or connection
    /// authority and [`DataError::AllocationRefused`] if exact preallocation
    /// fails.
    pub(crate) fn new(
        connection: &PreparedFuseConnection<'_, '_, '_, '_, '_>,
        limits: RegistrationLimits,
    ) -> Result<Self, DataError> {
        let authority_binding = connection.binding();
        if authority_binding == [0; 32]
            || limits.maximum_registrations == 0
            || limits.maximum_open_references == 0
        {
            return Err(DataError::InvalidLimit);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limits.maximum_registrations)
            .map_err(|_| DataError::AllocationRefused)?;
        if entries.capacity() > limits.maximum_registrations {
            return Err(DataError::ResourceExhausted);
        }
        Ok(Self {
            authority_binding,
            callback_reducer_commitment: [0; 32],
            lease: connection.lease(),
            limits,
            entries,
            references: 0,
            next_operation: 1,
        })
    }

    /// Restores exact canonical durable records without replaying OS effects.
    pub(crate) fn restore(
        connection: &PreparedFuseConnection<'_, '_, '_, '_, '_>,
        limits: RegistrationLimits,
        records: &[DurableRegistrationRecord],
    ) -> Result<Self, DataError> {
        let authority_binding = connection.binding();
        let mut state = Self::new(connection, limits)?;
        if records.len() > limits.maximum_registrations {
            return Err(DataError::ResourceExhausted);
        }
        let mut previous = 0_u64;
        let restored_reducer_commitment = records
            .first()
            .map_or([0; 32], |record| record.callback_reducer_commitment);
        for record in records {
            if record.authority_binding != authority_binding
                || record.callback_reducer_commitment != restored_reducer_commitment
                || record.operation.0 <= previous
                || record.backing.authority_binding() != authority_binding
            {
                return Err(DataError::IntegrityFailure);
            }
            state.references = state
                .references
                .checked_add(record.references)
                .ok_or(DataError::ResourceExhausted)?;
            if state.references > limits.maximum_open_references {
                return Err(DataError::ResourceExhausted);
            }
            state.entries.push(Registration {
                operation: record.operation,
                backing: record.backing,
                phase: record.phase,
                backing_id: record.backing_id,
                descriptor_commitment: record.descriptor_commitment,
                references: record.references,
            });
            previous = record.operation.0;
        }
        state.next_operation = previous
            .checked_add(1)
            .ok_or(DataError::ResourceExhausted)?;
        state.callback_reducer_commitment = restored_reducer_commitment;
        Ok(state)
    }

    /// Returns the non-authorizing connection commitment for join validation.
    #[must_use]
    pub const fn authority_binding(&self) -> [u8; 32] {
        self.authority_binding
    }

    pub(super) const fn callback_reducer_commitment(&self) -> [u8; 32] {
        self.callback_reducer_commitment
    }

    pub(super) fn bind_callback_reducer(&mut self, commitment: [u8; 32]) -> Result<(), DataError> {
        if commitment == [0; 32]
            || (self.callback_reducer_commitment != [0; 32]
                && commitment == self.callback_reducer_commitment)
        {
            return Err(DataError::IntegrityFailure);
        }
        self.callback_reducer_commitment = commitment;
        Ok(())
    }

    /// Returns the admitted table and aggregate-reference ceilings.
    #[must_use]
    pub const fn limits(&self) -> RegistrationLimits {
        self.limits
    }

    /// Returns the exact aggregate number of pending and active worker opens.
    #[must_use]
    pub const fn open_references(&self) -> u64 {
        self.references
    }

    /// Copies canonical live state for durable persistence before effects.
    ///
    /// The returned records are already ordered by operation. Persisting the
    /// bytes and proving durability remains the broker journal's responsibility.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::AllocationRefused`] if bounded snapshot allocation
    /// fails or [`DataError::IntegrityFailure`] for inconsistent live state.
    pub fn snapshot(&self) -> Result<Vec<DurableRegistrationRecord>, DataError> {
        let mut records = Vec::new();
        records
            .try_reserve_exact(self.entries.len())
            .map_err(|_| DataError::AllocationRefused)?;
        if records.capacity() > self.entries.len() {
            return Err(DataError::ResourceExhausted);
        }
        for entry in &self.entries {
            records.push(DurableRegistrationRecord::from_canonical_journal(
                self.authority_binding,
                self.callback_reducer_commitment,
                entry.operation.get(),
                entry.backing,
                entry.phase,
                entry.backing_id,
                entry.descriptor_commitment,
                entry.references,
            )?);
        }
        Ok(records)
    }

    /// Returns the durable phase for one exact operation.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] for an unknown operation.
    pub fn phase(&self, operation: RegistrationOperation) -> Result<RegistrationPhase, DataError> {
        Ok(self.entry(operation)?.phase)
    }

    /// Returns the exact verified backing for an operation.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] for an unknown operation.
    pub fn backing(&self, operation: RegistrationOperation) -> Result<BackingIdentity, DataError> {
        Ok(self.entry(operation)?.backing)
    }

    /// Returns the recorded selector for an active or closing operation.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] when the operation is unknown,
    /// pending, ambiguous, or lacks a nonzero selector.
    pub fn backing_id(&self, operation: RegistrationOperation) -> Result<u64, DataError> {
        let entry = self.entry(operation)?;
        if !matches!(
            entry.phase,
            RegistrationPhase::Active | RegistrationPhase::Closing
        ) {
            return Err(DataError::IntegrityFailure);
        }
        entry
            .backing_id
            .filter(|value| *value != 0)
            .ok_or(DataError::IntegrityFailure)
    }

    /// Returns the descriptor commitment for an active or closing operation.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] when the operation is unknown,
    /// pending, ambiguous, or lacks an exact nonzero descriptor commitment.
    pub fn descriptor_commitment(
        &self,
        operation: RegistrationOperation,
    ) -> Result<[u8; 32], DataError> {
        let entry = self.entry(operation)?;
        if !matches!(
            entry.phase,
            RegistrationPhase::Active | RegistrationPhase::Closing
        ) {
            return Err(DataError::IntegrityFailure);
        }
        entry
            .descriptor_commitment
            .filter(|commitment| *commitment != [0; 32])
            .ok_or(DataError::IntegrityFailure)
    }

    /// Enters pending state or coalesces with one active backing.
    ///
    /// The caller must persist [`Self::snapshot`] before executing
    /// [`RegistrationAction::OpenBacking`] or publishing a coalesced selector.
    ///
    /// # Errors
    ///
    /// Returns a deadline, resource, or integrity error without changing state
    /// when the lease, a ceiling, authority binding, or backing lifecycle
    /// invariant fails.
    pub fn begin_open(
        &mut self,
        backing: BackingIdentity,
        monotonic_now_ns: u64,
    ) -> Result<RegistrationAction, DataError> {
        if !self.lease.contains(monotonic_now_ns) {
            return Err(DataError::DeadlineExpired);
        }
        if self.callback_reducer_commitment == [0; 32]
            || backing.authority_binding() != self.authority_binding
            || backing.evidence_commitment() == [0; 32]
        {
            return Err(DataError::IntegrityFailure);
        }
        let next_references = self
            .references
            .checked_add(1)
            .ok_or(DataError::ResourceExhausted)?;
        if next_references > self.limits.maximum_open_references {
            return Err(DataError::ResourceExhausted);
        }
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.backing == backing && entry.phase == RegistrationPhase::Active)
        {
            entry.references = entry
                .references
                .checked_add(1)
                .ok_or(DataError::ResourceExhausted)?;
            self.references = next_references;
            return Ok(RegistrationAction::PublishCoalesced {
                operation: entry.operation,
            });
        }
        if self.entries.len() == self.limits.maximum_registrations {
            return Err(DataError::ResourceExhausted);
        }
        let operation = RegistrationOperation(self.next_operation);
        self.next_operation = self
            .next_operation
            .checked_add(1)
            .ok_or(DataError::ResourceExhausted)?;
        self.entries.push(Registration {
            operation,
            backing,
            phase: RegistrationPhase::Pending,
            backing_id: None,
            descriptor_commitment: None,
            references: 1,
        });
        self.references = next_references;
        Ok(RegistrationAction::OpenBacking { operation })
    }

    /// Records the exact selector and descriptor identity returned by backing open.
    ///
    /// The caller must persist [`Self::snapshot`] before publishing the selector.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] for an unknown operation,
    /// non-pending phase, zero selector, or zero descriptor commitment.
    pub fn record_opened(
        &mut self,
        operation: RegistrationOperation,
        backing_id: u64,
        descriptor_commitment: [u8; 32],
    ) -> Result<(), DataError> {
        let entry = self.entry_mut(operation)?;
        if entry.phase != RegistrationPhase::Pending
            || backing_id == 0
            || descriptor_commitment == [0; 32]
        {
            return Err(DataError::IntegrityFailure);
        }
        entry.backing_id = Some(backing_id);
        entry.descriptor_commitment = Some(descriptor_commitment);
        entry.phase = RegistrationPhase::Active;
        Ok(())
    }

    /// Records a definite backing-open failure and permits worker-open release.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] unless the operation is the
    /// single-reference pending registration created by [`Self::begin_open`].
    pub fn record_open_failed(
        &mut self,
        operation: RegistrationOperation,
    ) -> Result<RegistrationAction, DataError> {
        let position = self.position(operation)?;
        let entry = &self.entries[position];
        if entry.phase != RegistrationPhase::Pending
            || entry.backing_id.is_some()
            || entry.descriptor_commitment.is_some()
            || entry.references != 1
        {
            return Err(DataError::IntegrityFailure);
        }
        let remaining_references = self
            .references
            .checked_sub(1)
            .ok_or(DataError::IntegrityFailure)?;

        self.entries.remove(position);
        self.references = remaining_references;
        Ok(RegistrationAction::AbortWorkerOpen { operation })
    }

    /// Begins release; the final reference always closes before worker release.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] unless the operation is active
    /// with at least one reference.
    pub fn begin_release(
        &mut self,
        operation: RegistrationOperation,
    ) -> Result<RegistrationAction, DataError> {
        let position = self.position(operation)?;
        let entry = &self.entries[position];
        if entry.phase != RegistrationPhase::Active || entry.references == 0 {
            return Err(DataError::IntegrityFailure);
        }
        if entry.references > 1 {
            let remaining_entry_references = entry
                .references
                .checked_sub(1)
                .ok_or(DataError::IntegrityFailure)?;
            let remaining_total_references = self
                .references
                .checked_sub(1)
                .ok_or(DataError::IntegrityFailure)?;

            self.entries[position].references = remaining_entry_references;
            self.references = remaining_total_references;
            return Ok(RegistrationAction::ReleaseWorkerOpen { operation });
        }
        self.entries[position].phase = RegistrationPhase::Closing;
        Ok(RegistrationAction::CloseBeforeRelease { operation })
    }

    /// Reissues a close after a definite retryable failure.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] unless the operation is closing.
    pub fn retry_close(
        &self,
        operation: RegistrationOperation,
    ) -> Result<RegistrationAction, DataError> {
        let entry = self.entry(operation)?;
        (entry.phase == RegistrationPhase::Closing)
            .then_some(RegistrationAction::CloseBeforeRelease { operation })
            .ok_or(DataError::IntegrityFailure)
    }

    /// Returns the recorded selector only while a close effect is authorized.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] for an unknown, non-closing, or
    /// selector-less operation.
    pub fn closing_backing_id(&self, operation: RegistrationOperation) -> Result<u64, DataError> {
        let entry = self.entry(operation)?;
        if entry.phase != RegistrationPhase::Closing {
            return Err(DataError::IntegrityFailure);
        }
        entry.backing_id.ok_or(DataError::IntegrityFailure)
    }

    /// Records close confirmation and permits the final worker release.
    ///
    /// The caller must persist [`Self::snapshot`] before releasing worker state.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] unless the final reference and
    /// selector remain in the closing phase.
    pub fn record_closed(
        &mut self,
        operation: RegistrationOperation,
    ) -> Result<RegistrationAction, DataError> {
        let position = self.position(operation)?;
        if self.entries[position].phase != RegistrationPhase::Closing
            || self.entries[position].backing_id.is_none()
            || self.entries[position].descriptor_commitment.is_none()
            || self.entries[position].references != 1
        {
            return Err(DataError::IntegrityFailure);
        }
        let remaining_references = self
            .references
            .checked_sub(1)
            .ok_or(DataError::IntegrityFailure)?;

        self.entries.remove(position);
        self.references = remaining_references;
        Ok(RegistrationAction::ReleaseWorkerOpen { operation })
    }

    /// Confirms close for a rejected OPEN and permits pending-worker abort.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] unless the exact final selector
    /// remains in the closing phase.
    pub fn record_rejected_open_closed(
        &mut self,
        operation: RegistrationOperation,
    ) -> Result<RegistrationAction, DataError> {
        let action = self.record_closed(operation)?;
        if action != (RegistrationAction::ReleaseWorkerOpen { operation }) {
            return Err(DataError::IntegrityFailure);
        }
        Ok(RegistrationAction::AbortWorkerOpen { operation })
    }

    /// Records an indeterminate open/close result and requires replacement.
    ///
    /// # Errors
    ///
    /// Returns [`DataError::IntegrityFailure`] for an unknown operation.
    pub fn record_ambiguous(
        &mut self,
        operation: RegistrationOperation,
    ) -> Result<RegistrationAction, DataError> {
        self.entry_mut(operation)?.phase = RegistrationPhase::Ambiguous;
        Ok(RegistrationAction::ReplaceConnection)
    }

    fn position(&self, operation: RegistrationOperation) -> Result<usize, DataError> {
        self.entries
            .iter()
            .position(|entry| entry.operation == operation)
            .ok_or(DataError::IntegrityFailure)
    }

    fn entry(&self, operation: RegistrationOperation) -> Result<&Registration, DataError> {
        self.position(operation)
            .map(|position| &self.entries[position])
    }

    fn entry_mut(
        &mut self,
        operation: RegistrationOperation,
    ) -> Result<&mut Registration, DataError> {
        let position = self.position(operation)?;
        Ok(&mut self.entries[position])
    }
}

pub(super) fn encode_canonical_records(
    writer: &mut Writer,
    records: &[DurableRegistrationRecord],
    authority_binding: [u8; 32],
) -> Result<(), DurableStateError> {
    writer.u32(u32::try_from(records.len()).map_err(|_| DurableStateError::ResourceExhausted)?)?;
    let mut previous = 0_u64;
    let reducer_commitment = records
        .first()
        .map_or([0; 32], |record| record.callback_reducer_commitment);
    for record in records {
        if record.authority_binding != authority_binding
            || record.callback_reducer_commitment == [0; 32]
            || record.callback_reducer_commitment != reducer_commitment
            || record.operation.get() <= previous
        {
            return Err(DurableStateError::Integrity);
        }
        writer.bytes(&record.callback_reducer_commitment)?;
        writer.u64(record.operation.get())?;
        writer.u8(registration_phase_code(record.phase))?;
        writer.u64(record.backing_id.unwrap_or(0))?;
        writer.bytes(&record.descriptor_commitment.unwrap_or([0; 32]))?;
        writer.u64(record.references)?;
        record.backing.encode_canonical(writer)?;
        previous = record.operation.get();
    }
    Ok(())
}

pub(super) fn decode_canonical_records(
    cursor: &mut Cursor<'_>,
    authority_binding: [u8; 32],
    maximum_records: usize,
) -> Result<Vec<DurableRegistrationRecord>, DurableStateError> {
    let count = usize::try_from(cursor.u32()?).map_err(|_| DurableStateError::ResourceExhausted)?;
    if count > maximum_records {
        return Err(DurableStateError::ResourceExhausted);
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| DurableStateError::AllocationRefused)?;
    if records.capacity() > count {
        return Err(DurableStateError::ResourceExhausted);
    }
    let mut previous = 0_u64;
    for _ in 0..count {
        let callback_reducer_commitment = cursor.array()?;
        let operation = cursor.u64()?;
        if operation <= previous {
            return Err(DurableStateError::Integrity);
        }
        let phase = decode_registration_phase(cursor.u8()?)?;
        let backing_id = match cursor.u64()? {
            0 => None,
            value => Some(value),
        };
        let descriptor_commitment = match cursor.array()? {
            value if value == [0; 32] => None,
            value => Some(value),
        };
        let references = cursor.u64()?;
        let backing = BackingIdentity::decode_canonical(cursor, authority_binding)?;
        records.push(DurableRegistrationRecord::from_canonical_journal(
            authority_binding,
            callback_reducer_commitment,
            operation,
            backing,
            phase,
            backing_id,
            descriptor_commitment,
            references,
        )?);
        previous = operation;
    }
    Ok(records)
}

const fn registration_phase_code(phase: RegistrationPhase) -> u8 {
    match phase {
        RegistrationPhase::Pending => 0,
        RegistrationPhase::Active => 1,
        RegistrationPhase::Closing => 2,
        RegistrationPhase::Ambiguous => 3,
    }
}

fn decode_registration_phase(value: u8) -> Result<RegistrationPhase, DurableStateError> {
    match value {
        0 => Ok(RegistrationPhase::Pending),
        1 => Ok(RegistrationPhase::Active),
        2 => Ok(RegistrationPhase::Closing),
        3 => Ok(RegistrationPhase::Ambiguous),
        _ => Err(DurableStateError::Integrity),
    }
}
