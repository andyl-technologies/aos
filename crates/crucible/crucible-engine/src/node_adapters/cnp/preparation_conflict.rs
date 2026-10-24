//! Sends predeclared changed bodies without replacing original guarded journals.
//!
//! Archives are reserved before Child and installed only into the exact original
//! live connection. Source policy authenticates complete bodies and actual
//! provider-only custody before every send; response data grants no authority.

use std::io::{self, Write};

use crucible_node_format::{Id, canonical};
use crucible_node_transport::{
    bodies::{ResponseBody, decode_request},
    client::{OriginalConflictObservationHandle, OriginalConflictReservation},
    envelope::Method,
};
use serde_json::{Map, Value};

use super::{CnpLaunchGuard, CnpReferenceQualification};
use crate::node_contract::{EffectKnowledge, OperationFailure};

const MAXIMUM_REQUESTS: usize = 16;
const MAXIMUM_REQUEST_BYTES: usize = 256 * 1024;
const MAXIMUM_RESPONSE_BYTES: usize = 1024 * 1024;

/// Selects exact changed material under an already retained original request ID.
pub struct CnpPreRealizationConflictRequest {
    /// Names the unchanged original controller request.
    pub request: Id,
    /// Names the original method; changing methods is not supported.
    pub method: Method,
    /// Contains the source-predeclared changed typed body.
    pub body: Map<String, Value>,
}

impl CnpLaunchGuard {
    /// Transfers pre-Child archive custody to its exact original controller.
    ///
    /// # Errors
    /// Refuses missing/realized custody, invalid provider/source authentication,
    /// foreign reservation or late/repeated installation. Refusal retains the
    /// same reservation and performs no transport operation.
    pub fn install_pre_realization_conflict_archive(
        &mut self,
        qualification: &dyn CnpReferenceQualification,
        reservation: &mut Option<OriginalConflictReservation>,
    ) -> Result<OriginalConflictObservationHandle, OperationFailure> {
        let profile = self.original_conflict_profile()?;
        qualification.authenticate_provider(self, &profile)?;
        self.custody
            .as_mut()
            .and_then(|slot| slot.controller.as_mut())
            .ok_or_else(|| failure("original conflict controller absent", false))?
            .install_original_conflict_reservation(reservation)
            .map_err(|error| failure(&error.to_string(), false))
    }

    /// Transmits bounded source-planned conflicts beside unchanged originals.
    ///
    /// The SDK bypasses its ordinary exchange cache and compares actual wire
    /// responses. Every error after possible dispatch retains original custody
    /// and reports Unknown; callers cannot renew the original attempt.
    ///
    /// # Errors
    /// Refuses absent source authorization, changed original bodies/IDs, missing
    /// archive or finite reservations. Transport ambiguity preserves the guard.
    pub fn probe_pre_realization_conflicts(
        &mut self,
        qualification: &dyn CnpReferenceQualification,
        requests: &[CnpPreRealizationConflictRequest],
    ) -> Result<Vec<ResponseBody>, OperationFailure> {
        if requests.is_empty() || requests.len() > MAXIMUM_REQUESTS {
            return Err(failure("original conflict population ceiling", false));
        }
        self.original_conflict_profile()?;
        qualification.authenticate_pre_realization_conflicts(self, requests)?;

        // Count borrowed JSON before typed decoding or Value copies. The
        // authoritative canonical writer separately enforces the exact byte
        // credit; this count bounds intermediate ownership, not JCS expansion.
        let mut material = Vec::new();
        material
            .try_reserve_exact(MAXIMUM_REQUEST_BYTES)
            .map_err(|_| failure("original conflict request reservation", false))?;
        for (index, request) in requests.iter().enumerate() {
            if requests[..index]
                .iter()
                .any(|prior| prior.request == request.request)
            {
                return Err(failure("original conflict request repeated", false));
            }
            count_borrowed(&request.body, MAXIMUM_REQUEST_BYTES)
                .map_err(|error| failure(&error.to_string(), false))?;
            decode_request(request.method, &request.body)
                .map_err(|error| failure(&error.to_string(), false))?;
            canonical::canonical_json_to_writer(
                &Value::Object(request.body.clone()),
                &mut Bounded {
                    bytes: &mut material,
                    maximum: MAXIMUM_REQUEST_BYTES,
                },
            )
            .map_err(|error| failure(&error.to_string(), false))?;
        }
        let mut replies = Vec::new();
        replies
            .try_reserve_exact(requests.len())
            .map_err(|_| failure("original conflict reply slot reservation", false))?;
        let credit = requests
            .len()
            .checked_mul(MAXIMUM_RESPONSE_BYTES)
            .ok_or_else(|| failure("original conflict reply credit overflow", false))?;
        let mut arena = Vec::new();
        arena
            .try_reserve_exact(credit)
            .map_err(|_| failure("original conflict reply byte reservation", false))?;
        let mut dispatched = false;
        for request in requests {
            qualification
                .authenticate_pre_realization_conflicts(self, requests)
                .map_err(|mut error| {
                    if dispatched {
                        error.effects = EffectKnowledge::Unknown;
                    }
                    error
                })?;
            let controller = self
                .custody
                .as_mut()
                .and_then(|slot| slot.controller.as_mut())
                .ok_or_else(|| failure("original conflict controller lost", dispatched))?;
            dispatched = true;
            let response = controller
                .probe_original_body_conflict(&request.request, &request.body)
                .map_err(|error| failure(&error.to_string(), true))?;
            count_borrowed(&response.shape, MAXIMUM_RESPONSE_BYTES)
                .map_err(|error| failure(&error.to_string(), true))?;
            let value = serde_json::to_value(&response.shape)
                .map_err(|error| failure(&error.to_string(), true))?;
            let maximum = arena
                .len()
                .checked_add(MAXIMUM_RESPONSE_BYTES)
                .filter(|maximum| *maximum <= credit)
                .ok_or_else(|| failure("original conflict reply ceiling", true))?;
            canonical::canonical_json_to_writer(
                &value,
                &mut Bounded {
                    bytes: &mut arena,
                    maximum,
                },
            )
            .map_err(|error| failure(&error.to_string(), true))?;
            replies.push(response);
        }
        Ok(replies)
    }

    fn original_conflict_profile(
        &self,
    ) -> Result<crucible_node_transport::reference_service::ReferenceProfile, OperationFailure>
    {
        let custody = self
            .custody
            .as_ref()
            .ok_or_else(|| failure("original conflict custody absent", false))?;
        if custody.handshake.is_none() || custody.companion.is_some() || custody.runtime.is_some() {
            return Err(failure(
                "original conflict pre-realization scope differs",
                false,
            ));
        }
        custody
            .controller
            .as_ref()
            .map(|controller| controller.profile.clone())
            .ok_or_else(|| failure("original conflict controller absent", false))
    }
}

fn failure(reason: &str, dispatched: bool) -> OperationFailure {
    OperationFailure {
        effects: if dispatched {
            EffectKnowledge::Unknown
        } else {
            EffectKnowledge::None
        },
        reason: reason.into(),
    }
}

// These writers own no storage. Counts stop before copies, and canonical output
// can only append to the caller's already reserved finite bank.
struct Count {
    used: usize,
    maximum: usize,
}

impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.used = self
            .used
            .checked_add(bytes.len())
            .filter(|used| *used <= self.maximum)
            .ok_or_else(|| io::Error::other("original conflict borrowed byte ceiling"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn count_borrowed(value: &impl serde::Serialize, maximum: usize) -> Result<(), serde_json::Error> {
    serde_json::to_writer(&mut Count { used: 0, maximum }, value)
}

struct Bounded<'a> {
    bytes: &'a mut Vec<u8>,
    maximum: usize,
}

impl Write for Bounded<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.maximum && *end <= self.bytes.capacity())
            .ok_or_else(|| io::Error::other("original conflict canonical byte ceiling"))?;
        self.bytes.extend_from_slice(bytes);
        debug_assert_eq!(self.bytes.len(), end);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
