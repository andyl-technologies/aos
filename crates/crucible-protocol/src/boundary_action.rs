//! Encodes a retained boundary action and its separate physical-return journal.
//!
//! ```text
//! action[896] = header[128] | four parent rows[192]
//! return[184] = binding header[120] | signed first/post | physical mask/state |
//!               typed progress witness | canonical zero padding
//! ```
//!
//! These pointer-free observations corroborate existing owners. Decoding never
//! issues an operation, Root child, descriptor, progress unit, or physical loan.
//! Park publications use CRUCPRK1 and a distinct ParentParkReturn codec. Their correlation
//! replaces the control-token/sample union; it never advances a control ACK.
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Number of primary producers supported by the actual boundary callers.
pub const ACTION_PRIMARY_CAPACITY: usize = 2;
/// Two producers and their retained Preparation dependencies.
pub const ACTION_PARENT_CAPACITY: usize = 4;
/// Fixed action publication tail extent.
pub const ACTION_BYTES: usize = 896;
/// Fixed canonical parent row extent.
pub const ACTION_PARENT_BYTES: usize = 192;
/// Physical return payload extent, excluding its atomic sequence word.
pub const ACTION_RETURN_BYTES: usize = 184;

/// Corroborates the exact Source and immutable request frontier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionBinding {
    /// Containing Source cap identity.
    pub cap: [u8; 32],
    /// Actual Source reservation identity.
    pub reservation: [u8; 32],
    /// Admitted account incarnation.
    pub account_generation: u64,
    /// Actual Source execution incarnation.
    pub process_generation: u64,
    /// Genuine containing publisher sequence captured at action birth.
    pub loan_sequence: u64,
    /// Existing even control token; wraparound zero remains valid.
    pub token: u32,
    /// Optional odd sample request generation, with absence distinct from zero.
    pub capture: Option<u32>,
    /// Actual Park request correlation, absent for a control-boundary action.
    ///
    /// A Park request has no control token or capture selector. Its separately
    /// retained physical lifetime ends only at the matching Park return.
    pub park_request: Option<u64>,
    /// Immutable command producer ordinal.
    pub frontier: u64,
}

/// Observes a real producing operation without changing its class or clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActionParent {
    /// Actual lender cap identity, which may differ from the Source cap.
    pub cap: [u8; 32],
    /// Actual budget-owner identity within that lender cap; zero denotes root.
    pub budget_owner: u64,
    /// Nonzero existing operation identity within that budget owner.
    pub operation: u64,
    /// Producing time class in the canonical fourteen-class roster.
    pub class: u32,
    /// Sticky Running0, Completed1, Expired2 or Canceled3.
    pub state: u32,
    /// Immutable revision at the actual operation entry.
    pub started_revision: u64,
    /// Actual lender policy revision.
    pub policy_revision: u64,
    /// Actual lender outer revision.
    pub outer_revision: u64,
    /// Immutable monotonic origin.
    pub origin_ns: u64,
    /// Original operation entry coordinate.
    pub started_ns: u64,
    /// Actual last meaningful progress coordinate.
    pub progress_ns: u64,
    /// Absolute total end, or zero for deliberate absence.
    pub total_end_ns: u64,
    /// Absolute progress end, or zero for deliberate absence.
    pub progress_end_ns: u64,
    /// Absolute outer end, or zero for deliberate absence.
    pub outer_end_ns: u64,
    /// Immutable private interval end, or zero when not applicable.
    pub private_end_ns: u64,
    /// Current bounded polling allowance in nanoseconds.
    pub poll_ns: u64,
    /// Genuine completed required units, never inferred from page traffic.
    pub completed: u64,
    /// Actual nonzero required-work inventory.
    pub required: u64,
    /// Preparation row index plus one; zero denotes no dependency.
    pub preparation: u32,
    /// Primary0 or Preparation1, independent of producing time class.
    pub role: u32,
}

/// One coherent action snapshot under its actual retained lenders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionObservation {
    /// Exact request and Source binding.
    pub binding: ActionBinding,
    /// Number of primary rows, preceding all dependency rows.
    pub primary_count: u32,
    /// Number of planned rows; unborn rows remain zero.
    pub row_count: u32,
    /// Rows genuinely retained before any fallible projection.
    pub borrowed_mask: u32,
    /// Born rows whose factual identity/clock projection succeeded.
    pub projected_mask: u32,
    /// A full locked cohort, distinct from a dirty or partly born action.
    pub cohort_current: bool,
    /// Actual producer and dependency observations.
    pub parents: [ActionParent; ACTION_PARENT_CAPACITY],
}

/// Independent native disposition of the actual action borrowers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionReturn {
    /// Same actual Source and request binding.
    pub binding: ActionBinding,
    /// First semantic result, independently retained even after physical close.
    pub first: i32,
    /// Independent semantic post result, never synthesized from ACKs.
    pub post: i32,
    /// Pending0, Returned1, or Uncertain2.
    pub physical_state: u32,
    /// Returned genuinely borrowed rows; unused rows never imply consumption.
    pub returned_mask: u32,
    /// Rows genuinely borrowed, distinct from absent planned rows.
    pub borrowed_mask: u32,
    /// Number of planned rows in this action.
    pub row_count: u32,
    /// Witness kind: None0, SourceRead1, Protection2, Wake3, MaterialClose4.
    pub progress_kind: u32,
    /// Witness lender row index plus one; zero only when no witness exists.
    pub progress_row: u32,
    /// Genuine effect completion coordinate under the producing clock.
    pub progress_ns: u64,
    /// Actual one-use issuer witness; syntax alone never authorizes progress.
    pub progress_witness: u64,
}

/// Refuses malformed action observations before any owner effects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid boundary action observation")]
pub struct ActionDecodeError;

impl ActionBinding {
    fn validate(self) -> Result<(), ActionDecodeError> {
        if self.cap == [0; 32]
            || self.reservation == [0; 32]
            || self.account_generation == 0
            || self.process_generation == 0
            || self.loan_sequence == 0
            || self.loan_sequence & 1 != 0
            || self.loan_sequence == u64::MAX
            || self.token & 1 != 0
            || self.capture.is_some_and(|value| value & 1 == 0)
            || self.park_request.is_some_and(|value| {
                value == 0 || value == u64::MAX || self.token != 0 || self.capture.is_some()
            })
        {
            return Err(ActionDecodeError);
        }
        Ok(())
    }
}

impl ActionObservation {
    /// Validates and encodes one canonical fixed action tail.
    ///
    /// # Errors
    /// Refuses unsupported counts, changed dependency geometry, invalid clocks,
    /// unknown classes/dispositions or nonzero unused rows.
    pub fn encode(&self) -> Result<[u8; ACTION_BYTES], ActionDecodeError> {
        self.binding.validate()?;
        if !(1..=2).contains(&self.primary_count)
            || self.row_count < self.primary_count
            || self.row_count > 4
            || self.borrowed_mask == 0
            || self.borrowed_mask & !((1 << self.row_count) - 1) != 0
            || self.projected_mask & !self.borrowed_mask != 0
            || (self.cohort_current
                && (self.borrowed_mask != (1 << self.row_count) - 1
                    || self.projected_mask != self.borrowed_mask))
        {
            return Err(ActionDecodeError);
        }
        if self.binding.park_request.is_some() {
            if self.primary_count != 2
                || (0..2).any(|index| {
                    self.projected_mask & (1 << index) != 0 && self.parents[index].class != 6
                })
            {
                return Err(ActionDecodeError);
            }
            if self.projected_mask & 3 == 3
                && self.parents[0].cap == self.parents[1].cap
                && self.parents[0].budget_owner == self.parents[1].budget_owner
                && self.parents[0].operation == self.parents[1].operation
            {
                return Err(ActionDecodeError);
            }
        }
        let mut bytes = [0; ACTION_BYTES];
        let magic = if self.binding.park_request.is_some() {
            *b"CRUCPRK1"
        } else {
            *b"CRUCACT2"
        };
        header(&mut bytes, magic, self.binding);
        put32(
            &mut bytes,
            120,
            self.primary_count
                | (self.borrowed_mask << 8)
                | (self.projected_mask << 16)
                | (u32::from(!self.cohort_current) << 31),
        );
        put32(&mut bytes, 124, self.row_count);
        for (index, row) in self.parents.iter().enumerate() {
            if self.projected_mask & (1 << index) == 0 {
                if *row != ActionParent::default() {
                    return Err(ActionDecodeError);
                }
                continue;
            }
            if row.cap == [0; 32]
                || row.operation == 0
                || row.class >= 14
                || row.state > 3
                || row.started_ns < row.origin_ns
                || row.progress_ns < row.started_ns
                || row.poll_ns == 0
                || row.poll_ns > i64::MAX as u64
                || row.required == 0
                || row.completed > row.required
                || row.role != u32::from(index >= self.primary_count as usize)
                || (row.role == 1 && (row.class != 12 || row.preparation != 0))
                || (row.class != 1
                    && [
                        row.total_end_ns,
                        row.progress_end_ns,
                        row.outer_end_ns,
                        row.private_end_ns,
                    ]
                    .iter()
                    .all(|end| *end == 0))
            {
                return Err(ActionDecodeError);
            }
            if row.preparation != 0 {
                let dependency = row.preparation as usize - 1;
                if dependency < self.primary_count as usize
                    || dependency >= self.row_count as usize
                    || (self.cohort_current && self.parents[dependency].role != 1)
                {
                    return Err(ActionDecodeError);
                }
            }
            let offset = 128 + index * ACTION_PARENT_BYTES;
            bytes[offset..offset + 32].copy_from_slice(&row.cap);
            put64(&mut bytes, offset + 32, row.budget_owner);
            put64(&mut bytes, offset + 40, row.operation);
            put32(&mut bytes, offset + 48, row.class);
            put32(&mut bytes, offset + 52, row.state);
            for (position, value) in [
                row.policy_revision,
                row.outer_revision,
                row.origin_ns,
                row.started_ns,
                row.progress_ns,
                row.total_end_ns,
                row.progress_end_ns,
                row.outer_end_ns,
                row.private_end_ns,
                row.poll_ns,
                row.completed,
                row.required,
            ]
            .into_iter()
            .enumerate()
            {
                put64(&mut bytes, offset + 56 + position * 8, value);
            }
            put32(&mut bytes, offset + 152, row.preparation);
            put32(&mut bytes, offset + 156, row.role);
            put64(&mut bytes, offset + 160, row.started_revision);
        }
        Ok(bytes)
    }

    /// Decodes the fixed tail and verifies exact canonical re-encoding.
    ///
    /// # Errors
    /// Refuses predecessor geometry, malformed ownership coordinates or padding.
    pub fn decode(bytes: &[u8]) -> Result<Self, ActionDecodeError> {
        let magic = if bytes.get(..8) == Some(b"CRUCPRK1".as_slice()) {
            *b"CRUCPRK1"
        } else {
            *b"CRUCACT2"
        };
        let binding = read_header(bytes, magic, ACTION_BYTES)?;
        let mut parents = [ActionParent::default(); ACTION_PARENT_CAPACITY];
        for (index, row) in parents.iter_mut().enumerate() {
            let offset = 128 + index * ACTION_PARENT_BYTES;
            row.cap.copy_from_slice(&bytes[offset..offset + 32]);
            row.budget_owner = get64(bytes, offset + 32);
            row.operation = get64(bytes, offset + 40);
            row.class = get32(bytes, offset + 48);
            row.state = get32(bytes, offset + 52);
            row.policy_revision = get64(bytes, offset + 56);
            row.outer_revision = get64(bytes, offset + 64);
            row.origin_ns = get64(bytes, offset + 72);
            row.started_ns = get64(bytes, offset + 80);
            row.progress_ns = get64(bytes, offset + 88);
            row.total_end_ns = get64(bytes, offset + 96);
            row.progress_end_ns = get64(bytes, offset + 104);
            row.outer_end_ns = get64(bytes, offset + 112);
            row.private_end_ns = get64(bytes, offset + 120);
            row.poll_ns = get64(bytes, offset + 128);
            row.completed = get64(bytes, offset + 136);
            row.required = get64(bytes, offset + 144);
            row.preparation = get32(bytes, offset + 152);
            row.role = get32(bytes, offset + 156);
            row.started_revision = get64(bytes, offset + 160);
        }
        let value = Self {
            binding,
            primary_count: get32(bytes, 120) & 3,
            row_count: get32(bytes, 124),
            borrowed_mask: (get32(bytes, 120) >> 8) & 15,
            projected_mask: (get32(bytes, 120) >> 16) & 15,
            cohort_current: get32(bytes, 120) >> 31 == 0,
            parents,
        };
        if value.encode()?.as_slice() != bytes {
            return Err(ActionDecodeError);
        }
        Ok(value)
    }
}

impl ActionReturn {
    /// Encodes the physical journal independently of control/sample ACKs.
    ///
    /// # Errors
    /// Refuses positive semantic statuses, unknown dispositions or witnesses,
    /// unused-row masks and an incomplete Returned disposition.
    pub fn encode(self) -> Result<[u8; ACTION_RETURN_BYTES], ActionDecodeError> {
        self.binding.validate()?;
        if self.binding.park_request.is_some()
            || self.first > 0
            || self.post > 0
            || self.physical_state > 2
            || !(1..=4).contains(&self.row_count)
            || self.borrowed_mask == 0
            || self.borrowed_mask & !((1 << self.row_count) - 1) != 0
            || self.returned_mask & !self.borrowed_mask != 0
            || (self.physical_state == 1 && self.returned_mask != self.borrowed_mask)
            || self.progress_kind > 4
            || (self.progress_kind == 0
                && (self.progress_row != 0 || self.progress_ns != 0 || self.progress_witness != 0))
            || (self.progress_kind != 0
                && (self.progress_row == 0
                    || self.progress_row > self.row_count
                    || self.borrowed_mask & (1 << (self.progress_row - 1)) == 0
                    || self.progress_ns == 0
                    || self.progress_witness == 0))
        {
            return Err(ActionDecodeError);
        }
        let mut bytes = [0; ACTION_RETURN_BYTES];
        header(&mut bytes, *b"CRUCRET1", self.binding);
        put32(&mut bytes, 120, self.first as u32);
        put32(&mut bytes, 124, self.post as u32);
        put32(&mut bytes, 128, self.physical_state);
        put32(&mut bytes, 132, self.returned_mask);
        put32(&mut bytes, 136, self.row_count);
        put32(&mut bytes, 140, self.progress_kind);
        put32(&mut bytes, 144, self.progress_row);
        put64(&mut bytes, 152, self.progress_ns);
        put64(&mut bytes, 160, self.progress_witness);
        put32(&mut bytes, 168, self.borrowed_mask);
        Ok(bytes)
    }

    /// Decodes one canonical physical journal without issuing return authority.
    ///
    /// # Errors
    /// Refuses unknown geometry, noncanonical fields and reserved-byte changes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ActionDecodeError> {
        let binding = read_header(bytes, *b"CRUCRET1", ACTION_RETURN_BYTES)?;
        let value = Self {
            binding,
            first: get32(bytes, 120) as i32,
            post: get32(bytes, 124) as i32,
            physical_state: get32(bytes, 128),
            returned_mask: get32(bytes, 132),
            row_count: get32(bytes, 136),
            progress_kind: get32(bytes, 140),
            progress_row: get32(bytes, 144),
            progress_ns: get64(bytes, 152),
            progress_witness: get64(bytes, 160),
            borrowed_mask: get32(bytes, 168),
        };
        if value.encode()?.as_slice() != bytes {
            return Err(ActionDecodeError);
        }
        Ok(value)
    }
}

fn header(bytes: &mut [u8], magic: [u8; 8], binding: ActionBinding) {
    bytes[..8].copy_from_slice(&magic);
    put32(bytes, 8, if magic == *b"CRUCACT2" { 2 } else { 1 });
    let extent = bytes.len() as u32;
    put32(bytes, 12, extent);
    bytes[16..48].copy_from_slice(&binding.cap);
    bytes[48..80].copy_from_slice(&binding.reservation);
    put64(bytes, 80, binding.account_generation);
    put64(bytes, 88, binding.process_generation);
    if let Some(correlation) = binding.park_request {
        put64(bytes, 96, correlation);
    } else {
        put32(bytes, 96, binding.token);
        put32(bytes, 100, binding.capture.unwrap_or(0));
    }
    put64(bytes, 104, binding.frontier);
    put64(bytes, 112, binding.loan_sequence);
}

fn read_header(
    bytes: &[u8],
    magic: [u8; 8],
    size: usize,
) -> Result<ActionBinding, ActionDecodeError> {
    if bytes.len() != size
        || bytes[..8] != magic
        || get32(bytes, 8) != if magic == *b"CRUCACT2" { 2 } else { 1 }
        || get32(bytes, 12) != size as u32
    {
        return Err(ActionDecodeError);
    }
    let mut cap = [0; 32];
    cap.copy_from_slice(&bytes[16..48]);
    let mut reservation = [0; 32];
    reservation.copy_from_slice(&bytes[48..80]);
    let park = magic == *b"CRUCPRK1";
    let capture = get32(bytes, 100);
    let binding = ActionBinding {
        cap,
        reservation,
        account_generation: get64(bytes, 80),
        process_generation: get64(bytes, 88),
        token: if park { 0 } else { get32(bytes, 96) },
        capture: (!park && capture != 0).then_some(capture),
        park_request: park.then(|| get64(bytes, 96)),
        frontier: get64(bytes, 104),
        loan_sequence: get64(bytes, 112),
    };
    binding.validate()?;
    Ok(binding)
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn get64(bytes: &[u8], offset: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(word)
}

#[cfg(test)]
mod tests;
