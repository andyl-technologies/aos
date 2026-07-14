//! Candidate-C scalar-store and compressed-word error types and the
//! exposed-address pointer helpers (split from compressed.rs, §2 cap).
use super::*;

pub(crate) fn pointer_from_exposed_address(
    address: usize,
    kind: &'static str,
) -> Result<std::ptr::NonNull<crate::value::HeapObject>, CandidateCScalarError> {
    std::ptr::NonNull::new(std::ptr::with_exposed_provenance_mut(address))
        .ok_or(CandidateCScalarError::PointerCellNotFound { kind, address })
}

pub(crate) fn candidate_c_pointer_error(
    error: CandidateCScalarError,
    kind: &'static str,
    index: u32,
) -> CandidateCScalarError {
    match error {
        CandidateCScalarError::PointerCellNotFound { .. } => {
            CandidateCScalarError::ScalarCellNotFound { kind, index }
        }
        error => error,
    }
}

/// A Candidate-C boxed scalar could not be stored or decoded.
#[derive(Debug, Error)]
pub enum CandidateCScalarError {
    /// The codec rejected a requested scalar encoding.
    #[error(transparent)]
    Codec(#[from] CompressedValueError),
    /// The flat store could not allocate or resolve the scalar cell.
    #[error(transparent)]
    Flat(#[from] FlatObjectError),
    /// The shared flat store could not publish a scalar cell.
    #[error(transparent)]
    SharedFlat(#[from] SharedFlatObjectError),
    /// Candidate C was requested without a reservation backend.
    #[error("Candidate-C scalar storage requires a reservation-backed arena")]
    ReservationUnavailable,
    /// A fresh scalar allocation did not belong to the expected reservation.
    #[error("scalar allocation 0x{address:x} is outside the Candidate-C reservation")]
    AddressOutsideReservation {
        /// The rejected native address.
        address: usize,
    },
    /// A scalar word named an index outside the reservation's live lanes.
    #[error("scalar index {index} is outside the Candidate-C reservation's live lanes")]
    IndexOutsideReservation {
        /// The rejected compressed offset.
        index: u32,
    },
    /// A scalar decoder received the wrong representation kind.
    #[error("expected a compressed {expected}, found {actual:?}")]
    KindMismatch {
        /// The requested semantic scalar type.
        expected: &'static str,
        /// The observed representation kind.
        actual: CompressedValueKind,
    },
    /// A scalar word belonged to another live reservation.
    #[error("compressed scalar arena domain {actual} does not match expected domain {expected}")]
    ArenaDomainMismatch {
        /// The receiving scalar store's domain.
        expected: u32,
        /// The word's encoded domain.
        actual: u32,
    },
    /// A shared hash-cons table was poisoned by a panicking publisher.
    #[error("shared boxed-{kind} hash-cons lock is poisoned")]
    HashConsLockPoisoned {
        /// The scalar population whose lock was poisoned.
        kind: &'static str,
    },
    /// A live shared reservation index did not name the expected scalar store.
    #[error("Candidate-C shared {kind} cell at index {index} is not published")]
    ScalarCellNotFound {
        /// The expected scalar population.
        kind: &'static str,
        /// The rejected reservation offset.
        index: u32,
    },
    /// A native address did not name the expected typed scalar population.
    #[error("boxed {kind} cell at address 0x{address:x} is not published")]
    PointerCellNotFound {
        /// The expected scalar population.
        kind: &'static str,
        /// The rejected native address.
        address: usize,
    },
}

/// A Candidate-C value could not be encoded or decoded.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CompressedValueError {
    /// A raw kind value has no assigned representation.
    #[error("unknown compressed value kind 0x{kind:08x}")]
    UnknownKind {
        /// The rejected kind bits, without the forced flag.
        kind: u32,
    },
    /// A 64-bit integer needs a boxed arena cell.
    #[error("integer {value} does not fit the Candidate-C 32-bit immediate range")]
    IntegerRequiresBox {
        /// The integer that requires boxing.
        value: i64,
    },
    /// A scalar tag was passed to the typed heap-index constructor.
    #[error("runtime tag {tag:?} is not a heap-index kind")]
    NonHeapTag {
        /// The rejected runtime tag.
        tag: ValueTag,
    },
    /// An indexed word omitted its nonzero reservation domain.
    #[error("compressed indexed kind {kind:?} has no arena domain")]
    MissingArenaDomain {
        /// The indexed representation kind.
        kind: CompressedValueKind,
    },
    /// An inline word carried reservation-domain metadata.
    #[error("compressed inline kind {kind:?} carries arena domain {domain}")]
    ArenaDomainOnInline {
        /// The inline representation kind.
        kind: CompressedValueKind,
        /// The rejected metadata.
        domain: u32,
    },
    /// The forced shortcut appeared on a value other than a thunk.
    #[error("compressed forced bit is invalid on {kind:?}")]
    ForcedBitOnNonThunk {
        /// The decoded non-thunk kind.
        kind: CompressedValueKind,
    },
    /// A boolean payload was not zero or one.
    #[error("compressed boolean payload is {payload}, expected zero or one")]
    InvalidBoolPayload {
        /// The rejected payload.
        payload: u32,
    },
    /// A null payload was not zero.
    #[error("compressed null payload is {payload}, expected zero")]
    InvalidNullPayload {
        /// The rejected payload.
        payload: u32,
    },
}
