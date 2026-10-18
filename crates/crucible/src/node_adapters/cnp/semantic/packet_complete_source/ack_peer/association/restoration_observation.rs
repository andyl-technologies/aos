//! Signs one independently admitted observation of the genuine restored world.
//!
//! The opaque Core claim is spent before assignment. A Source-owned attempt
//! keeps normalized originals, the actual native model and scheduling output
//! through failure. Neither World completion nor a portable observation DTO
//! supplies observation credit, a current owner or a new execution permission.

use super::*;
use crate::node_admission::{
    OriginalInstalledRestorationObservationClaim,
    OriginalInstalledRestorationObservationSigningConstructionInputs,
    OriginalInstalledRestorationObservationSigningInputs,
};
use crate::node_contract::{NodeRuntime, RuntimeError};
use crate::node_scheduling::NativeSchedulingObservation;
use crucible_node_contract::{Bytes, ContentRef, Id};
use crucible_node_provider::{
    bodies::ResponseBody,
    reference_packet::{
        control::PacketNative5UnderlyingRecord,
        service::complete_restore::{
            PacketNativeRestoredRecord,
            activation::{
                restoration_activation_retained_native_evidence_counter_scratch_data,
                restoration_activation_retained_native_evidence_data,
            },
            restoration_observe::*,
        },
    },
};
use std::mem::size_of;

#[path = "restoration_observation/checkpoint_cache17.rs"]
mod checkpoint_cache17;
#[path = "restoration_observation/construction.rs"]
mod construction;
#[path = "restoration_observation/construction_data.rs"]
mod construction_data;
#[path = "restoration_observation/effect.rs"]
mod effect;
#[path = "restoration_observation/evidence.rs"]
mod evidence;
#[path = "restoration_observation/owner.rs"]
mod owner;
#[path = "restoration_observation/projection.rs"]
mod projection;
#[path = "restoration_observation/scheduling.rs"]
mod scheduling;
#[path = "restoration_transfer/construction/typed_backing.rs"]
mod typed_backing;

pub use construction_data::OriginalSourceRestorationObservationConstructionData;
pub use evidence::OriginalSourceRestorationObservationVerifiedPhase;
pub(super) use owner::OriginalSourceRestorationObservationAttempt;

fn sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, RuntimeError> {
    crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::sum_with_error::<
        RuntimeError,
        N,
    >(terms, maximum)
}

#[path = "restoration_observation/current.rs"]
mod current;
pub(super) use current::CurrentObservationHistory;
pub(crate) use current::OriginalSourceRestoredObservationCompletion;

#[path = "restoration_observation/checkpoint17.rs"]
mod checkpoint17;
