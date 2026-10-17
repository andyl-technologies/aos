//! Bounded authenticated planner-record reuse within one complete validation.
//!
//! Only fully checked immutable tuples are retained. This context never replaces
//! fresh closure byte authentication, child traversal, or owner-transition checks.

use super::*;

const MAX_PLANNER_VALIDATION_ENTRIES: usize = 16;
const MAX_PLANNER_VALIDATION_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Retains a fully authenticated request and its resolved invocation.
#[derive(Clone)]
pub(super) struct ValidatedPlannerRequest {
    /// Original canonical request, including its by-value input bundle.
    pub(super) request: PlannerRequest,
    /// Invocation authenticated against the stored request and input links.
    pub(super) invocation: PlannerInvocation,
}

/// Retains a checked step with the exact request used for its validation.
#[derive(Clone)]
pub(super) struct ValidatedPlannerStep {
    /// Step whose request, parent state, and accounting checks succeeded.
    pub(super) step: PlannerStep,
    /// Fully checked request and resolved invocation for this step.
    pub(super) retained: ValidatedPlannerRequest,
}

enum ValidatedRecord {
    Request {
        id: ContentId,
        value: Box<ValidatedPlannerRequest>,
    },
    Step {
        id: ContentId,
        request_id: ContentId,
        value: Box<ValidatedPlannerStep>,
    },
}

impl ValidatedRecord {
    fn request_id(&self) -> ContentId {
        match self {
            Self::Request { id, .. } => *id,
            Self::Step { request_id, .. } => *request_id,
        }
    }

    fn request(&self) -> &ValidatedPlannerRequest {
        match self {
            Self::Request { value, .. } => value,
            Self::Step { value, .. } => &value.retained,
        }
    }

    // Charge canonical tuple bodies; envelope headers and child tables are
    // reconstructed during fresh closure reads and are never retained here.
    fn payload_bytes(&self) -> Option<usize> {
        let request = self.request();
        let bytes = crate::codec::encode(&request.request)
            .len()
            .checked_add(crate::codec::encode(&request.invocation).len())?;
        match self {
            Self::Request { .. } => Some(bytes),
            Self::Step { value, .. } => bytes.checked_add(crate::codec::encode(&value.step).len()),
        }
    }
}

struct Entry {
    record: ValidatedRecord,
    payload_bytes: usize,
}

/// Owns deterministic FIFO reuse, discarded with its validation attempt.
pub(super) struct PlannerValidationContext {
    entries: VecDeque<Entry>,
    payload_bytes: usize,
    maximum_entries: usize,
    maximum_payload_bytes: usize,
}

impl Default for PlannerValidationContext {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            payload_bytes: 0,
            maximum_entries: MAX_PLANNER_VALIDATION_ENTRIES,
            maximum_payload_bytes: MAX_PLANNER_VALIDATION_PAYLOAD_BYTES,
        }
    }
}

impl PlannerValidationContext {
    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.payload_bytes = 0;
    }

    #[cfg(test)]
    pub(super) fn retained_usage(&self) -> (usize, usize) {
        (self.entries.len(), self.payload_bytes)
    }

    pub(super) fn request(&self, id: ContentId) -> Option<ValidatedPlannerRequest> {
        self.entries
            .iter()
            .find(|entry| entry.record.request_id() == id)
            .map(|entry| entry.record.request().clone())
    }

    pub(super) fn step(&self, id: ContentId) -> Option<ValidatedPlannerStep> {
        self.entries.iter().find_map(|entry| match &entry.record {
            ValidatedRecord::Step {
                id: cached_id,
                value,
                ..
            } if *cached_id == id => Some(value.as_ref().clone()),
            _ => None,
        })
    }

    pub(super) fn insert_request(&mut self, id: ContentId, value: ValidatedPlannerRequest) {
        self.insert(ValidatedRecord::Request {
            id,
            value: Box::new(value),
        });
    }

    pub(super) fn insert_step(
        &mut self,
        id: ContentId,
        request_id: ContentId,
        value: ValidatedPlannerStep,
    ) {
        self.insert(ValidatedRecord::Step {
            id,
            request_id,
            value: Box::new(value),
        });
    }

    fn insert(&mut self, record: ValidatedRecord) {
        let Some(bytes) = record.payload_bytes() else {
            return;
        };
        if self.maximum_entries == 0 || bytes > self.maximum_payload_bytes {
            return;
        }

        // One request owns at most one tuple. A checked step supersedes its
        // request-only entry rather than retaining a duplicate payload.
        let request_id = record.request_id();
        self.entries
            .retain(|entry| entry.record.request_id() != request_id);
        self.payload_bytes = self.entries.iter().map(|entry| entry.payload_bytes).sum();
        while self.entries.len() >= self.maximum_entries
            || self.payload_bytes > self.maximum_payload_bytes - bytes
        {
            if let Some(evicted) = self.entries.pop_front() {
                self.payload_bytes -= evicted.payload_bytes;
            }
        }
        self.entries.push_back(Entry {
            record,
            payload_bytes: bytes,
        });
        self.payload_bytes += bytes;
    }

    #[cfg(test)]
    pub(super) fn with_limits(entries: usize, payload_bytes: usize) -> Self {
        Self {
            maximum_entries: entries.min(MAX_PLANNER_VALIDATION_ENTRIES),
            maximum_payload_bytes: payload_bytes.min(MAX_PLANNER_VALIDATION_PAYLOAD_BYTES),
            ..Self::default()
        }
    }
}
