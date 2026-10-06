//! Retained, read-only method-41 source composition.
//!
//! One admitted BSA request owns the lazy policy read, both durable cuts,
//! original native candidate result and exact response bytes. Comparisons
//! borrow the same runtime, output custody and resolver directory. Neither a
//! successful read nor local terminal delivery grants allocation or an effect.

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, StorageExecutionCaptureCandidateV1};
use aos_sandbox_core::{ProtocolVersion, RawPairedClockSample};
use aos_sandbox_linux::boot::KernelBootId;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};
use aos_sandbox_protocol::storage_capture_candidate::{
    STORAGE_CAPTURE_CANDIDATE_BYTES_V1, ValidatedStorageCaptureCandidateV1,
    decode_storage_capture_candidate_response_for_query_v1,
};
use buffa::Message as _;

use super::{StorageBrokerRuntime, StorageRuntimeError, StorageRuntimeReadiness, trusted_paired_clock_sample};
use crate::broker::{AuthenticatedCaptureCandidateCutV1, StorageBrokerError};
use crate::execution_capture_policy::{
    CaptureAllocationPolicyErrorV1, CaptureAllocationV1, OriginalCapturePolicyReadV1,
};
use crate::execution_output::{CaptureCandidateErrorV1, ExecutionOutputLedgerErrorV1};
use crate::execution_output_credential::StorageExecutionOutputCustodyV1;
use crate::resolver::protected_catalog::{SelectedStorageResolverPolicyV1, StorageResolverPolicyError};

#[derive(Debug, thiserror::Error)]
#[error("original Storage capture candidate is closed with its source results retained")]
struct CaptureCandidateClosedV1;

#[derive(Clone, Copy, Eq, PartialEq)]
enum BookendCauseV1 {
    Clock,
    LateClock,
    Cut,
    Resolver,
    Policy,
    Credential,
    Head,
    Response,
    Changed,
}

struct CaptureCandidateBookendV1 {
    clock: Option<Result<RawPairedClockSample, StorageRuntimeError>>,
    late_clock: Option<Result<RawPairedClockSample, StorageRuntimeError>>,
    cut: Option<Result<AuthenticatedCaptureCandidateCutV1, StorageBrokerError>>,
    resolver: Option<Result<SelectedStorageResolverPolicyV1, StorageResolverPolicyError>>,
    policy: OriginalCapturePolicyReadV1,
    credential: Option<Result<(), crate::service::StorageServiceError>>,
    head: Option<Result<u64, ExecutionOutputLedgerErrorV1>>,
    response: Option<Result<ValidatedStorageCaptureCandidateV1, aos_sandbox_protocol::ProtocolValidationError>>,
    first: Option<BookendCauseV1>,
}

impl CaptureCandidateBookendV1 {
    fn empty() -> Self {
        Self {
            clock: None,
            late_clock: None,
            cut: None,
            resolver: None,
            policy: OriginalCapturePolicyReadV1::empty(),
            credential: None,
            head: None,
            response: None,
            first: None,
        }
    }

    fn field_error(&self, field: BookendCauseV1) -> Option<&(dyn std::error::Error + 'static)> {
        match field {
            BookendCauseV1::Clock => self.clock.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            BookendCauseV1::LateClock => self.late_clock.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            BookendCauseV1::Cut => self.cut.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            BookendCauseV1::Resolver => self.resolver.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            BookendCauseV1::Policy => self.policy.failure().or_else(|| self.policy.postcheck_debt()),
            BookendCauseV1::Credential => self.credential.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            BookendCauseV1::Head => self.head.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            BookendCauseV1::Response => self.response.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            BookendCauseV1::Changed => (self.first == Some(BookendCauseV1::Changed))
                .then_some(&CaptureCandidateClosedV1 as &dyn std::error::Error),
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.field_error(self.first?)
    }

    fn postcheck_debt(
        &self,
        primary: Option<BookendCauseV1>,
    ) -> Option<&(dyn std::error::Error + 'static)> {
        // Visit retained fields in observation order, not just this reservoir's
        // first selector. Only the exact primary field is already accounted for.
        for field in [
            BookendCauseV1::Clock,
            BookendCauseV1::Cut,
            BookendCauseV1::Resolver,
            BookendCauseV1::Policy,
            BookendCauseV1::Credential,
            BookendCauseV1::Head,
            BookendCauseV1::LateClock,
            BookendCauseV1::Response,
            BookendCauseV1::Changed,
        ] {
            if Some(field) != primary {
                if let Some(error) = self.field_error(field) {
                    return Some(error);
                }
            }
            if field == BookendCauseV1::Policy
                && (primary != Some(field) || self.policy.failure().is_some())
            {
                // If policy post-debt itself was selected as primary, do not
                // report it twice. A failed read's independent final identity
                // debt remains separate from that original native read error.
                if let Some(error) = self.policy.postcheck_debt() {
                    return Some(error);
                }
            }
        }
        None
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CandidateCauseV1 {
    Bookend(usize),
    Native,
    ResponseCopy,
    PolicyPin,
    Closed,
}

/// Keeps one genuine received request and its partial source recipe.
///
/// Empty slots allocate no backend objects or descriptors. The request clone
/// is immutable DATA from the actual receipt, not a new authority constructor.
/// Its bounded allocations, inline slots and retained policy FDs are real
/// costs; this owner makes no resource-bank funding or qualification claim.
pub(crate) struct OriginalCaptureCandidateV1 {
    request: AuthenticatedBrokerMethodRequestV1,
    version: ProtocolVersion,
    boot: KernelBootId,
    lease: Option<Result<super::repair_worker_drain::WorkerDispatchLease, ()>>,
    bookends: [CaptureCandidateBookendV1; 4],
    native: Option<Result<[u8; STORAGE_CAPTURE_CANDIDATE_BYTES_V1], CaptureCandidateErrorV1>>,
    response: Option<Vec<u8>>,
    response_copy: Option<Result<Vec<u8>, std::collections::TryReserveError>>,
    first: Option<CandidateCauseV1>,
    attempted: bool,
    handed_off: bool,
    retired: bool,
}

impl Drop for OriginalCaptureCandidateV1 {
    fn drop(&mut self) {
        // A failed recipe cannot silently lose the original opened file or
        // native result. Only an authenticated successor retires success.
        if !self.retired {
            std::process::abort();
        }
    }
}

impl OriginalCaptureCandidateV1 {
    pub(crate) fn empty(
        request: &AuthenticatedBrokerMethodRequestV1,
        version: ProtocolVersion,
        boot: KernelBootId,
    ) -> Self {
        Self {
            request: request.clone(),
            version,
            boot,
            lease: None,
            bookends: std::array::from_fn(|_| CaptureCandidateBookendV1::empty()),
            native: None,
            response: None,
            response_copy: None,
            first: None,
            attempted: false,
            handed_off: false,
            retired: false,
        }
    }

    pub(crate) const fn original_request(&self) -> &AuthenticatedBrokerMethodRequestV1 {
        &self.request
    }

    pub(crate) fn close_on_reentry(&mut self) {
        self.first.get_or_insert(CandidateCauseV1::Closed);
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            CandidateCauseV1::Bookend(index) => self.bookends[index].failure(),
            CandidateCauseV1::Native => self.native.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateCauseV1::ResponseCopy => self.response_copy.as_ref()?.as_ref().err()
                .map(|error| error as &dyn std::error::Error),
            CandidateCauseV1::PolicyPin => Some(&CaptureAllocationPolicyErrorV1::Changed),
            CandidateCauseV1::Closed => Some(&CaptureCandidateClosedV1),
        }
    }

    pub(crate) fn postcheck_debt(&self) -> Option<&(dyn std::error::Error + 'static)> {
        for (index, bookend) in self.bookends.iter().enumerate() {
            let primary = if self.first == Some(CandidateCauseV1::Bookend(index)) {
                bookend.first
            } else {
                None
            };
            if let Some(error) = bookend.postcheck_debt(primary) {
                return Some(error);
            }
        }
        None
    }

    pub(crate) fn take_response(&mut self) -> Option<Vec<u8>> {
        if self.first.is_some() || self.postcheck_debt().is_some() || self.handed_off {
            return None;
        }
        match self.response_copy.take()? {
            Ok(body) => {
                self.handed_off = true;
                Some(body)
            }
            Err(error) => {
                self.response_copy = Some(Err(error));
                None
            }
        }
    }

    pub(crate) fn retire_on_successor(&mut self, successor: &AuthenticatedBrokerMethodRequestV1) -> bool {
        if self.first.is_some() || self.postcheck_debt().is_some() || !self.handed_off
            || successor.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || successor.session_binding() != self.request.session_binding()
            || self.request.client_sequence().checked_add(1) != Some(successor.client_sequence())
        {
            return false;
        }
        // The actual BSA receipt authenticated the signed predecessor link.
        // This final DATA comparison neither admits a request nor issues proof.
        self.retired = true;
        true
    }

    fn mark_bookend(&mut self, index: usize) {
        if self.bookends[index].first.is_some() {
            self.first.get_or_insert(CandidateCauseV1::Bookend(index));
        }
    }
}

impl StorageBrokerRuntime {
    pub(crate) fn observe_original_capture_candidate(
        &self,
        attempt: &mut OriginalCaptureCandidateV1,
        output: &StorageExecutionOutputCustodyV1,
        process_allocation_pin: &mut Option<CaptureAllocationV1>,
    ) {
        if attempt.attempted {
            attempt.first.get_or_insert(CandidateCauseV1::Closed);
            return;
        }
        attempt.attempted = true;
        if attempt.request.method() != BrokerMethod::BROKER_METHOD_STORAGE_READ_EXECUTION_CAPTURE_CANDIDATE
            || attempt.request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || self.readiness != StorageRuntimeReadiness::Ready
            || attempt.request.authorization().is_none()
        {
            attempt.first = Some(CandidateCauseV1::Closed);
            return;
        }
        attempt.lease = Some(self.worker_dispatch.enter());
        if !matches!(&attempt.lease, Some(Ok(_))) {
            attempt.first = Some(CandidateCauseV1::Closed);
            return;
        }
        self.capture_candidate_bookend(attempt, output, 0);
        if attempt.first.is_some() {
            return;
        }
        let before = &attempt.bookends[0];
        let (Some(Ok(cut)), Some(Ok(resolver)), Some(allocation)) = (
            &before.cut, &before.resolver, before.policy.allocation(),
        ) else {
            attempt.first = Some(CandidateCauseV1::Closed);
            return;
        };
        // The full first authentic Root policy is process-pinned, not merely
        // request-pinned. A signed successor retires request custody only;
        // it cannot admit publication rotation without restarting Storage.
        match process_allocation_pin {
            Some(pinned) if *pinned != allocation => {
                attempt.first = Some(CandidateCauseV1::PolicyPin);
                return;
            }
            Some(_) => {}
            None => *process_allocation_pin = Some(allocation),
        }
        attempt.native = Some(output.ledger().observe_authenticated_capture_candidate(
            cut, resolver.policy(), allocation, &self.pin_contract,
        ));
        if matches!(&attempt.native, Some(Err(_))) {
            attempt.first = Some(CandidateCauseV1::Native);
        } else if let Some(Ok(candidate)) = &attempt.native {
            attempt.response = Some(StorageExecutionCaptureCandidateV1 {
                canonical_candidate: candidate.to_vec(),
                ..Default::default()
            }.encode_to_vec());
        }
        // Keep the native result before the independent final cut, even when
        // the physical observation failed. Native failure stays first cause.
        self.capture_candidate_bookend(attempt, output, 1);
        if attempt.first.is_some() || attempt.postcheck_debt().is_some() {
            return;
        }
        let Some(body) = &attempt.response else {
            attempt.first = Some(CandidateCauseV1::Closed);
            return;
        };
        let mut copy = Vec::new();
        attempt.response_copy = Some(copy.try_reserve_exact(body.len()).map(|()| {
            copy.extend_from_slice(body);
            copy
        }));
        if matches!(&attempt.response_copy, Some(Err(_))) {
            attempt.first = Some(CandidateCauseV1::ResponseCopy);
            attempt.bookends[1] = CaptureCandidateBookendV1::empty();
            self.capture_candidate_bookend(attempt, output, 1);
        }
    }

    pub(crate) fn recheck_original_capture_candidate(
        &self,
        attempt: &mut OriginalCaptureCandidateV1,
        output: &StorageExecutionOutputCustodyV1,
        before_signing: bool,
    ) {
        if attempt.first.is_some() || attempt.postcheck_debt().is_some() {
            return;
        }
        let index = if before_signing { 2 } else { 3 };
        // A completed comparison can be superseded by a fresh comparison,
        // never a failure. The original opening and source cut stay retained.
        if attempt.bookends[index].clock.is_some() {
            attempt.bookends[index] = CaptureCandidateBookendV1::empty();
        }
        self.capture_candidate_bookend(attempt, output, index);
    }

    fn capture_candidate_bookend(
        &self,
        attempt: &mut OriginalCaptureCandidateV1,
        output: &StorageExecutionOutputCustodyV1,
        index: usize,
    ) {
        let original = &attempt.bookends[0];
        let assignment = original.cut.as_ref().and_then(|result| result.as_ref().ok())
            .map(|cut| cut.query().assignment());
        let bookend = &mut attempt.bookends[index];
        bookend.clock = Some(trusted_paired_clock_sample());
        if matches!(&bookend.clock, Some(Err(_))) {
            bookend.first = Some(BookendCauseV1::Clock);
        }
        if let (Some(Ok(clock)), Some(artifacts)) = (&bookend.clock, attempt.request.authorization()) {
            if clock.host_boot_id() != attempt.boot.into_bytes()
                || clock.boottime_nanoseconds() >= attempt.request.deadline_boottime_nanoseconds()
            {
                bookend.first.get_or_insert(BookendCauseV1::Changed);
            } else {
                bookend.cut = Some(self.coordinator.authenticate_capture_candidate(
                    &attempt.request, artifacts, attempt.version, clock,
                ));
                if matches!(&bookend.cut, Some(Err(_))) {
                    bookend.first.get_or_insert(BookendCauseV1::Cut);
                }
            }
        }
        let assignment = assignment.or_else(|| bookend.cut.as_ref()
            .and_then(|result| result.as_ref().ok()).map(|cut| cut.query().assignment()));
        // No new policy I/O until the first authentic cut has established the
        // complete assignment. Later debt can still compare this same source.
        if let (Some(directory), Some(assignment)) = (&self.resolver_policies, assignment) {
            bookend.resolver = Some(directory.load().and_then(|catalog| catalog.select(assignment)));
            if matches!(&bookend.resolver, Some(Err(_))) {
                bookend.first.get_or_insert(BookendCauseV1::Resolver);
            }
            directory.read_original_capture_policy(&mut bookend.policy, self.configuration_binding);
            if bookend.policy.failure().is_some() || bookend.policy.postcheck_debt().is_some() {
                bookend.first.get_or_insert(BookendCauseV1::Policy);
            }
        } else {
            bookend.first.get_or_insert(BookendCauseV1::Changed);
        }
        if let Some(root) = &self.held_reader_state_directory {
            bookend.credential = Some(output.recheck(root));
            if matches!(&bookend.credential, Some(Err(_))) {
                bookend.first.get_or_insert(BookendCauseV1::Credential);
            }
        } else {
            bookend.first.get_or_insert(BookendCauseV1::Changed);
        }
        bookend.head = Some(output.ledger().candidate_head_sequence());
        if matches!(&bookend.head, Some(Err(_))) {
            bookend.first.get_or_insert(BookendCauseV1::Head);
        }
        bookend.late_clock = Some(trusted_paired_clock_sample());
        match &bookend.late_clock {
            Some(Err(_)) => { bookend.first.get_or_insert(BookendCauseV1::LateClock); }
            Some(Ok(clock)) if clock.host_boot_id() != attempt.boot.into_bytes()
                || clock.boottime_nanoseconds() >= attempt.request.deadline_boottime_nanoseconds() =>
            { bookend.first.get_or_insert(BookendCauseV1::Changed); }
            _ => {}
        }
        if let (Some(Ok(cut)), Some(Ok(resolver)), Some(allocation)) = (
            &bookend.cut, &bookend.resolver, bookend.policy.allocation(),
        ) {
            if cut.query().host_boot_id() != attempt.boot.into_bytes()
                || resolver.binding().catalog_digest() != allocation.resolver_catalog_digest()
            {
                bookend.first.get_or_insert(BookendCauseV1::Changed);
            }
            if let (Some(body), Some(Ok(clock))) = (&attempt.response, &bookend.late_clock) {
                bookend.response = Some(decode_storage_capture_candidate_response_for_query_v1(
                    body, cut.query(), attempt.request.maximum_response_bytes(), clock.boottime_nanoseconds(),
                ));
                match &bookend.response {
                    Some(Err(_)) => { bookend.first.get_or_insert(BookendCauseV1::Response); }
                    Some(Ok(response)) => {
                        if bookend.head.as_ref().and_then(|result| result.as_ref().ok()).copied()
                            != Some(response.output_journal_sequence())
                            || response.catalog_head() != (cut.catalog().binding().generation(), cut.catalog().binding().digest())
                        {
                            bookend.first.get_or_insert(BookendCauseV1::Changed);
                        }
                    }
                    None => {}
                }
            }
        }
        if index != 0 {
            let original = &attempt.bookends[0];
            let current = &attempt.bookends[index];
            let matches = match (&original.cut, &current.cut, &original.resolver, &current.resolver) {
                (Some(Ok(before)), Some(Ok(after)), Some(Ok(old_policy)), Some(Ok(new_policy))) =>
                    before.matches(after) && old_policy.binding() == new_policy.binding()
                        && old_policy.policy() == new_policy.policy()
                        && original.policy.allocation() == current.policy.allocation(),
                _ => false,
            };
            if !matches {
                attempt.bookends[index].first.get_or_insert(BookendCauseV1::Changed);
            }
        }
        attempt.mark_bookend(index);
    }
}
