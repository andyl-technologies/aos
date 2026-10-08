//! Explicitly selected future placement, transport and ordered-watch adapters.
//!
//! This module is absent without `multi-node`. Its adapters consume the local
//! protected owner's validated views; they do not replace lease or complete
//! inventory ownership. Transport custody remains in the verifier's private
//! child. No listener, worker, service registration or advertisement is added.

#[cfg(target_os = "linux")]
mod lease_protobuf;
pub mod placement;
pub mod watch_service;

pub use super::carrier_authority::{
    DormantAuthenticatedCoordinatorNodeTransportV1, DormantCoordinatorNodeEncodingV1,
    DormantOutboundExchangeV1, DormantOutboundResponseV1, DormantTransportHandshakeV1,
};
pub use placement::{
    AffinityPlacementV1, CandidateRejectionReasonV1, CandidateRejectionV1, InvalidPlacementInput,
    MAX_AFFINITY_PLACEMENTS, MAX_PLACEMENT_CANDIDATES, MAX_PLACEMENT_REQUIRED_FEATURES,
    PlacementBlockReasonV1, PlacementCandidateV1, PlacementDecisionV1, PlacementSelectionV1,
    place_deterministically,
};
pub use watch_service::{
    DormantOrderedWatchClientV1, DormantOrderedWatchServiceV1, DormantWatchClientOutcomeV1,
    DormantWatchReadOutcomeV1, MAX_DORMANT_WATCH_HISTORY,
};
