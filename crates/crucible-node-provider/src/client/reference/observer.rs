//! Opt-in inert observation custody independent of native control ownership.
//!
//! The archive reserves its complete byte arena and metadata slots before the
//! controller registers native work. A copied handle can outlive the runtime
//! that owns the controller, but exposes no socket, acknowledgement, or effect
//! authority. Recording failure is sticky and never changes a native result.

use std::sync::{Arc, Mutex};

use crucible_node_contract::{Bytes, ContentRef};
use serde::Serialize;

use crate::ProviderError;
use crate::bodies::{OperationState, ResponseBody};
use crate::envelope::{Nullable, RequestOrigin};

use super::{
    ByteBudget, ObservationLimits, ObservationScope, ObservedContent, ObservedRequest,
    ObservedRequestKey, ReferenceController, ReferenceObservationSnapshot, envelope_content,
    reject_private_envelope,
};

/// Contains selected observations together with sticky archive completeness facts.
///
/// These flags describe host observation custody. They do not establish native
/// containment, absence of effects, complete modeled state, or qualification.
#[derive(Clone, Debug, Serialize)]
pub struct RecordedReferenceObservation {
    /// States whether all attempted observations fit the reserved archive.
    pub recording_complete: bool,
    /// Records an unresolved control outcome without replacing its original.
    pub observed_unknown: bool,
    /// Retains the first bounded recording diagnostic, or explicit null.
    pub recording_failure: Nullable<&'static str>,
    /// Contains explicitly selected original envelope and content observations.
    pub evidence: ReferenceObservationSnapshot,
}

impl RecordedReferenceObservation {
    /// Encodes completeness facts and original selected data under one byte ceiling.
    ///
    /// # Errors
    /// Refuses zero or larger-than64MiB bounds and oversized or noncanonical
    /// encoding. Encoding does not persist or qualify the observation.
    pub fn encode(&self, maximum_bytes: usize) -> Result<Vec<u8>, ProviderError> {
        super::encode_observation(self, maximum_bytes)
    }
}

impl ReferenceController {
    /// Installs opt-in finite inert recording before the first original control.
    ///
    /// The recorder has a separately reserved byte arena and metadata slots.
    /// Native results and supervision remain unchanged. Any recording failure
    /// or unresolved control outcome remains visible as sticky incompleteness.
    /// The default controller has no recorder and performs no recording work.
    ///
    /// # Errors
    /// Refuses repeated or late installation, invalid original scope, private
    /// content, or unavailable complete archive count/byte reservations.
    pub fn observe(
        &mut self,
        limits: ObservationLimits,
    ) -> Result<ObservationHandle, ProviderError> {
        if self.observer.is_some() || self.custody.originals().next().is_some() {
            return Err(ProviderError::Correlation(
                "observation must be reserved before original controls",
            ));
        }
        let (recorder, handle) = ObservationRecorder::reserve(self.observation_scope()?, limits)?;
        {
            let mut archive = recorder
                .archive
                .lock()
                .map_err(|_| ProviderError::Correlation("observation archive poisoned"))?;
            archive.record_controller(self)?;
        }
        self.observer = Some(recorder);
        Ok(handle)
    }
}

/// Provides read-only bounded data access to a privately updated observation archive.
///
/// The handle is safe to transfer between host threads. Native controller,
/// process, handshake, operation and input custody remain with their original
/// owners; this handle cannot drive, acknowledge, resume, or release them.
#[derive(Clone)]
pub struct ObservationHandle {
    archive: Arc<Mutex<Archive>>,
}

impl ObservationHandle {
    /// Copies explicitly selected retained observations under independent bounds.
    ///
    /// An incomplete archive still preserves its successfully retained originals.
    /// The source-owned witness must refuse qualification from incomplete or
    /// unexpected unresolved evidence instead of treating absence as success.
    ///
    /// # Errors
    /// Refuses poisoned observation custody, duplicate or unavailable selectors,
    /// invalid limits, or exhausted selected-output byte/count credit.
    pub fn snapshot(
        &self,
        requests: &[ObservedRequestKey],
        references: &[ContentRef],
        limits: ObservationLimits,
    ) -> Result<RecordedReferenceObservation, ProviderError> {
        limits.validate()?;
        if requests.len() > limits.maximum_requests || references.len() > limits.maximum_objects {
            return Err(ProviderError::ResourceExhausted(
                "selected observation cardinality",
            ));
        }
        let archive = self
            .archive
            .lock()
            .map_err(|_| ProviderError::Correlation("observation archive poisoned"))?;
        let mut keys = std::collections::BTreeSet::new();
        let mut budget = ByteBudget(limits.maximum_bytes);
        let mut observed = Vec::with_capacity(requests.len());
        for key in requests {
            if !keys.insert(key) {
                return Err(ProviderError::Conflict("duplicate observed original"));
            }
            let original = archive
                .requests
                .iter()
                .find(|original| original.key == *key)
                .ok_or(ProviderError::Correlation("observed original unavailable"))?;
            let request = archive.copy_content(&original.request, &mut budget)?;
            let response = original
                .response
                .as_ref()
                .map(|response| archive.copy_content(response, &mut budget))
                .transpose()?;
            observed.push(ObservedRequest {
                key: original.key.clone(),
                identity: original.identity.clone(),
                request,
                response: Nullable(response),
            });
        }
        observed.sort_by(|left, right| left.key.cmp(&right.key));

        let mut selected = std::collections::BTreeSet::new();
        let mut objects = Vec::with_capacity(references.len());
        for reference in references {
            if !selected.insert(reference) {
                return Err(ProviderError::Conflict("duplicate observed content"));
            }
            let object = archive
                .objects
                .iter()
                .find(|object| object.reference == *reference)
                .ok_or(ProviderError::Correlation("observed content unavailable"))?;
            objects.push(archive.copy_content(object, &mut budget)?);
        }
        objects.sort_by(|left, right| left.reference.cmp(&right.reference));
        Ok(RecordedReferenceObservation {
            recording_complete: archive.failure.is_none() && !archive.observed_unknown,
            observed_unknown: archive.observed_unknown,
            recording_failure: Nullable(archive.failure),
            evidence: ReferenceObservationSnapshot {
                schema_version: 1,
                encoding: "retained-canonical-envelope-v1",
                scope: archive.scope.clone(),
                requests: observed,
                objects,
            },
        })
    }

    /// Enumerates retained endpoint/ID selectors without exposing control authority.
    ///
    /// # Errors
    /// Refuses poisoned archive custody. Enumeration remains bounded by the
    /// positive request allowance reserved before recording was installed.
    pub fn request_keys(&self) -> Result<Vec<ObservedRequestKey>, ProviderError> {
        let archive = self
            .archive
            .lock()
            .map_err(|_| ProviderError::Correlation("observation archive poisoned"))?;
        let mut keys = archive
            .requests
            .iter()
            .map(|request| request.key.clone())
            .collect::<Vec<_>>();
        keys.sort();
        Ok(keys)
    }

    /// Enumerates retained content selectors without declaring a native closure.
    ///
    /// # Errors
    /// Refuses poisoned archive custody. The source-owned witness independently
    /// selects and authenticates the required receipt dependency closure.
    pub fn content_references(&self) -> Result<Vec<ContentRef>, ProviderError> {
        let archive = self
            .archive
            .lock()
            .map_err(|_| ProviderError::Correlation("observation archive poisoned"))?;
        let mut references = archive
            .objects
            .iter()
            .map(|object| object.reference.clone())
            .collect::<Vec<_>>();
        references.sort();
        Ok(references)
    }
}

pub(crate) struct ObservationRecorder {
    archive: Arc<Mutex<Archive>>,
}

impl ObservationRecorder {
    pub(crate) fn reserve(
        scope: ObservationScope,
        limits: ObservationLimits,
    ) -> Result<(Self, ObservationHandle), ProviderError> {
        limits.validate()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(limits.maximum_bytes)
            .map_err(|_| ProviderError::ResourceExhausted("observation byte reservation"))?;
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(limits.maximum_requests)
            .map_err(|_| ProviderError::ResourceExhausted("observation request reservation"))?;
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(limits.maximum_objects)
            .map_err(|_| ProviderError::ResourceExhausted("observation object reservation"))?;
        let archive = Arc::new(Mutex::new(Archive {
            scope,
            limits,
            bytes,
            requests,
            objects,
            failure: None,
            observed_unknown: false,
        }));
        Ok((
            Self {
                archive: Arc::clone(&archive),
            },
            ObservationHandle { archive },
        ))
    }

    pub(crate) fn record(
        &self,
        controller: &ReferenceController,
        result: &Result<ResponseBody, ProviderError>,
    ) {
        let Ok(mut archive) = self.archive.lock() else {
            // No native return value or resource obligation is replaced by an
            // observational failure. A poisoned archive can never qualify.
            return;
        };
        archive.observed_unknown |= result.is_err()
            || result
                .as_ref()
                .is_ok_and(|response| response.shape.operation_state() == OperationState::Unknown);
        if archive.failure.is_some() {
            return;
        }
        if archive.record_controller(controller).is_err() {
            archive.failure = Some("original observation custody incomplete");
        }
    }

    pub(crate) fn attempt(&self) -> ObservationAttempt {
        ObservationAttempt {
            archive: Arc::clone(&self.archive),
            finished: false,
        }
    }
}

pub(crate) struct ObservationAttempt {
    archive: Arc<Mutex<Archive>>,
    finished: bool,
}

impl ObservationAttempt {
    pub(crate) fn finish(mut self) {
        self.finished = true;
    }
}

impl Drop for ObservationAttempt {
    fn drop(&mut self) {
        if !self.finished
            && let Ok(mut archive) = self.archive.lock()
        {
            archive
                .failure
                .get_or_insert("original control observation unwound");
            archive.observed_unknown = true;
        }
    }
}

struct ArchivedRequest {
    key: ObservedRequestKey,
    identity: crucible_node_contract::HashRef,
    request: ArchivedContent,
    response: Option<ArchivedContent>,
}

#[derive(Clone)]
struct ArchivedContent {
    reference: ContentRef,
    start: usize,
    end: usize,
}

struct Archive {
    scope: ObservationScope,
    limits: ObservationLimits,
    bytes: Vec<u8>,
    requests: Vec<ArchivedRequest>,
    objects: Vec<ArchivedContent>,
    failure: Option<&'static str>,
    observed_unknown: bool,
}

impl Archive {
    fn record_controller(&mut self, controller: &ReferenceController) -> Result<(), ProviderError> {
        let authority = controller.session.authority();
        if u64::from(controller.peer_pid()) != self.scope.provider_pid.get()
            || controller.peer_executable() != &self.scope.provider_executable
            || authority.session_id() != &self.scope.session_id
            || authority.incarnation_id() != &self.scope.incarnation_id
            || authority.connection_id() != &self.scope.connection_id
            || authority.epoch() != self.scope.connection_epoch.get()
            || authority.selected_features() != &self.scope.selected_features
            || controller.binding()?.0.identity()? != self.scope.binding_hash
        {
            return Err(ProviderError::Correlation(
                "original observation scope changed",
            ));
        }
        for origin in [RequestOrigin::Controller, RequestOrigin::Provider] {
            for original in controller.custody.originals_by_origin(origin) {
                let request_id = original
                    .request
                    .request_id
                    .0
                    .as_ref()
                    .ok_or(ProviderError::Correlation("observed request has no ID"))?;
                let key = ObservedRequestKey {
                    origin,
                    request_id: request_id.clone(),
                };
                reject_private_envelope(
                    &original.request,
                    controller.bootstrap.admission_token.as_slice(),
                )?;
                if original.request.request_hash(origin)? != original.identity {
                    return Err(ProviderError::Conflict("observed request identity changed"));
                }
                let previous = self.requests.iter().position(|request| request.key == key);
                if previous.is_none() && self.requests.len() >= self.limits.maximum_requests {
                    return Err(ProviderError::ResourceExhausted(
                        "observation request slots",
                    ));
                }
                let mut budget = ByteBudget(self.limits.maximum_bytes);
                let request = envelope_content(&original.request, &mut budget)?;
                let request = if let Some(index) = previous {
                    let retained = &self.requests[index];
                    if retained.identity != original.identity
                        || retained.request.reference != request.reference
                        || self.bytes[retained.request.start..retained.request.end]
                            != *request.bytes.as_slice()
                    {
                        return Err(ProviderError::Conflict("original observation changed"));
                    }
                    retained.request.clone()
                } else {
                    self.append(&request.reference, request.bytes.as_slice())?
                };
                // Retain the original row before a fallible response copy.
                // Partial recording then preserves an unanswered original.
                let index = if let Some(index) = previous {
                    index
                } else {
                    self.requests.push(ArchivedRequest {
                        key,
                        identity: original.identity.clone(),
                        request,
                        response: None,
                    });
                    self.requests.len() - 1
                };
                let response = if let Some(response) = &original.response {
                    original.request.matches_response(response)?;
                    reject_private_envelope(
                        response,
                        controller.bootstrap.admission_token.as_slice(),
                    )?;
                    let response = envelope_content(response, &mut budget)?;
                    let retained = self.requests[index].response.as_ref().filter(|retained| {
                        retained.reference == response.reference
                            && self.bytes[retained.start..retained.end]
                                == *response.bytes.as_slice()
                    });
                    Some(match retained {
                        Some(retained) => retained.clone(),
                        None => self.append(&response.reference, response.bytes.as_slice())?,
                    })
                } else {
                    if self.requests[index].response.is_some() {
                        return Err(ProviderError::Conflict("observed response disappeared"));
                    }
                    None
                };
                self.requests[index].response = response;
            }
        }
        for reference in controller.custody.content().references() {
            let bytes = controller.content(reference)?;
            super::reject_private_content(bytes, controller.bootstrap.admission_token.as_slice())?;
            if let Some(original) = self
                .objects
                .iter()
                .find(|object| object.reference.hash == reference.hash)
            {
                if original.reference != *reference
                    || self.bytes[original.start..original.end] != *bytes
                {
                    return Err(ProviderError::Conflict("observed content changed"));
                }
                continue;
            }
            if self.objects.len() >= self.limits.maximum_objects {
                return Err(ProviderError::ResourceExhausted(
                    "observation content slots",
                ));
            }
            let object = self.append(reference, bytes)?;
            self.objects.push(object);
        }
        Ok(())
    }

    fn append(
        &mut self,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<ArchivedContent, ProviderError> {
        reference.verify(bytes)?;
        let end = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.limits.maximum_bytes)
            .ok_or(ProviderError::ResourceExhausted("observation byte arena"))?;
        let start = self.bytes.len();
        self.bytes.extend_from_slice(bytes);
        Ok(ArchivedContent {
            reference: reference.clone(),
            start,
            end,
        })
    }

    fn copy_content(
        &self,
        object: &ArchivedContent,
        budget: &mut ByteBudget,
    ) -> Result<ObservedContent, ProviderError> {
        let bytes = self
            .bytes
            .get(object.start..object.end)
            .ok_or(ProviderError::Correlation(
                "observation arena bounds changed",
            ))?;
        budget.reserve(bytes.len())?;
        object.reference.verify(bytes)?;
        Ok(ObservedContent {
            reference: object.reference.clone(),
            bytes: Bytes::new(bytes.to_vec()),
        })
    }
}

#[cfg(test)]
#[path = "observer_tests.rs"]
mod tests;
