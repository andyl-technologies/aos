//! Supplies the defining private native identity geometry to the Hello quote.
//!
//! The actual owner fields, phase enum and fixed counter come from the original
//! Native18 identity. No identity constructor, authentication/issuer callback,
//! native dispatcher, input custody or phase permission is selected here.

use super::*;
use crate::reference_packet::NativeImport18PolicyData;
use crate::transport::original_frames::OriginalFrameReservation;
use crucible_node_format::SchemaRef;
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, mem::size_of};

/// Retains one native-side transport identity without issuing import authority.
pub(crate) struct NativeImport18ConnectionIdentity {
    actor: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    authority: Option<ConnectionAuthority>,
    policy: Rc<NativeImport18PolicyData>,
    frames: Rc<RefCell<OriginalFrameReservation>>,
    phase: NativeImport18ConnectionPhase,
    request_id: Option<Id>,
    sequence: crucible_node_format::U64,
    literal_slot: usize,
    literal_length: usize,
    literal_digest: blake3::Hash,
    ready: bool,
}

/// Selects all five native phases without casting an old two-phase identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeImport18ConnectionPhase {
    Prepare,
    Commit,
    Arm,
    World,
    FirstObserve,
}

impl NativeImport18ConnectionIdentity {
    /// Names the original fixed clone, literal-loan and phase-key controls.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<std::cell::Ref<'static, OriginalFrameReservation>>()
            + size_of::<crate::transport::original_frames::OriginalFrame<'static>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<[usize; 3], ProviderError>>()
            + size_of::<[Option<&str>; 3]>()
            + size_of::<std::array::IntoIter<Option<&'static str>, 3>>()
            + size_of::<std::iter::Flatten<std::array::IntoIter<Option<&'static str>, 3>>>()
            + size_of::<std::slice::Iter<'static, Option<&'static str>>>()
            + size_of::<Option<&SchemaRef>>()
            + size_of::<std::slice::Iter<'static, SchemaRef>>()
            + size_of::<Option<&Id>>()
            + crate::protocol_snapshot::owned11::correspondence::envelope_comparison_scratch_data()
            + ConnectionAuthority::independent_clone_counter_scratch_data()
            + crate::transport::original_frames::original_frames_iterator_counter_scratch_data()
            + size_of::<Option<usize>>()
            + size_of::<Option<crate::transport::original_frames::OriginalFrame<'static>>>()
    }
}
