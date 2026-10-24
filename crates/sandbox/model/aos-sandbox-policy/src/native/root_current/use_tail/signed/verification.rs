//! Verifies C's returned signing bytes against Root's SAME original preparation.
//!
//! This comparison retains the actual received signature/model/error. It does
//! not construct a broker local-lease record or a Storage effect grant. The
//! original verified Ownership response and fresh readonly compiler remain
//! resident in the caller throughout the genuine Root interval.

use super::super::super::initial_bundle::RootInitialBundleOwnershipOriginalV1 as RootCurrentBundleOwnershipStateV1;
use super::super::reserved::RootUseReservedOriginalV1 as RootCurrentUseReservedStateV1;
use super::RootSignedBoundErrorV1 as Error;
use aos_sandbox_model::format::{CanonicalCborError, decode_signature};
use aos_sandbox_model::model::Signature;
use aos_sandbox_model::{
    BrokerPlanExpectation, BrokerPlanRequest, BrokerPlanVerificationError, DecodeLimits,
    RawPairedClockSample, VerifiedBrokerPlan, verify_broker_plan,
};
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HistoryErrorV1, continuation::SignedPreparationBundleDataV1,
};
use aos_sandbox_protocol::semantics::StoragePreparationSemanticsError;
use std::error::Error as StdError;

#[derive(Default)]
pub(super) struct RootSignedVerificationV1 {
    exact_plan: Option<Result<(), HistoryErrorV1>>,
    signature: Option<Result<Signature, CanonicalCborError>>,
    statement: Option<Result<(), HistoryErrorV1>>,
    plan: Option<Result<VerifiedBrokerPlan, BrokerPlanVerificationError>>,
    lease: Option<Result<(), HistoryErrorV1>>,
    expected_body: Option<Result<Vec<u8>, StoragePreparationSemanticsError>>,
    body: Option<Result<(), HistoryErrorV1>>,
    matched: Option<Result<(), BrokerPlanVerificationError>>,
    request_id: Option<[u8; 16]>,
    result: Option<Result<(), Error>>,
    closed: bool,
}

impl RootSignedVerificationV1 {
    pub(super) fn verify_once(
        &mut self,
        bundle: SignedPreparationBundleDataV1<'_>,
        reserved: &RootCurrentUseReservedStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1,
        sample: RawPairedClockSample,
        cutoff: u64,
    ) -> Result<(), Error> {
        if self.result.is_some() || self.closed {
            self.closed = true;
            return Err(Error::Incomplete);
        }
        self.result = Some(self.verify_inner(bundle, reserved, ownership, sample, cutoff));
        self.require_complete_v1()
    }

    fn verify_inner(
        &mut self,
        bundle: SignedPreparationBundleDataV1<'_>,
        reserved: &RootCurrentUseReservedStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1,
        sample: RawPairedClockSample,
        cutoff: u64,
    ) -> Result<(), Error> {
        let readonly = reserved.completed_controller_v1()?;
        readonly.require_live_at_v1(sample)?;
        let original = readonly.prospective_use_plan_v1()?;
        let prepared = original.preparation_data_v1();
        self.exact_plan = Some(if bundle.plan == prepared.canonical_plan() {
            Ok(())
        } else {
            Err(HistoryErrorV1::Correlation)
        });
        positive(&self.exact_plan)?;
        self.signature = Some(decode_signature(bundle.signature, DecodeLimits::default()));
        let signature = positive(&self.signature)?;
        self.statement = Some(
            if signature.statement() == prepared.signing_request().statement() {
                Ok(())
            } else {
                Err(HistoryErrorV1::Correlation)
            },
        );
        positive(&self.statement)?;
        let expected = original.plan_data_v1();
        self.plan = Some(verify_broker_plan(
            bundle.plan,
            signature,
            original.anchor_v1(),
            BrokerPlanExpectation {
                audience: expected.audience(),
                protocol: expected.protocol(),
                protocol_version: expected.protocol_version(),
                assignment: expected.assignment(),
                node: expected.node(),
                now_seconds: sample.wall_seconds(),
            },
            DecodeLimits::default(),
        ));
        let plan = positive(&self.plan)?;
        // The exact plan was constructed from this original verified lease by
        // the sole common preparation engine. Its expiry already intersects
        // lease/policy/cutoff, and the real readonly liveness check ran above.
        let lease = ownership
            .completed_response_v1()?
            .value()
            .ok_or(Error::Incomplete)?;
        self.lease = Some(
            if lease.node() == plan.plan().node()
                && lease.signer() == plan.plan().ownership_authority()
                && sample.wall_seconds() >= lease.authority_issued_seconds()
                && sample.wall_seconds() < lease.authority_expires_seconds()
                && plan.plan().expires_seconds() <= lease.authority_expires_seconds()
            {
                Ok(())
            } else {
                Err(HistoryErrorV1::Correlation)
            },
        );
        positive(&self.lease)?;
        let protected = readonly.protected_storage_preparation_v1()?;
        self.expected_body =
            Some(protected.signed_request_body_v1(plan.plan_digest(), bundle.signature, cutoff));
        self.body = Some(
            if positive(&self.expected_body)?.as_slice() == bundle.request_body {
                Ok(())
            } else {
                Err(HistoryErrorV1::Correlation)
            },
        );
        positive(&self.body)?;
        let grant = expected.grants().first().ok_or(Error::Incomplete)?;
        self.matched = Some(
            plan.match_request(BrokerPlanRequest {
                verb: grant.verb(),
                target: grant.target(),
                argument_commitment: protected.argument_commitment(),
                request_bytes: u32::try_from(bundle.request_body.len())
                    .map_err(|_| Error::Incomplete)?,
                descriptor_count: 0,
            })
            .map(|_| ()),
        );
        positive(&self.matched)?;
        self.request_id =
            Some(protected.signed_request_id_v1(plan.plan_digest(), bundle.signature));
        Ok(())
    }

    pub(super) fn require_complete_v1(&self) -> Result<(), Error> {
        if !self.closed
            && matches!(self.result, Some(Ok(())))
            && self.failure().is_none()
            && self.request_id.is_some()
        {
            Ok(())
        } else {
            Err(Error::Incomplete)
        }
    }

    pub(super) fn request_id_v1(&self) -> Result<[u8; 16], Error> {
        self.require_complete_v1()?;
        self.request_id.ok_or(Error::Incomplete)
    }

    pub(super) fn verified_plan_v1(&self) -> Result<&VerifiedBrokerPlan, Error> {
        self.require_complete_v1()?;
        positive(&self.plan)
    }

    pub(super) fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.exact_plan)
            .or_else(|| cause(&self.signature))
            .or_else(|| cause(&self.statement))
            .or_else(|| cause(&self.plan))
            .or_else(|| cause(&self.lease))
            .or_else(|| cause(&self.expected_body))
            .or_else(|| cause(&self.body))
            .or_else(|| cause(&self.matched))
            .or_else(|| cause(&self.result))
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Error> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(Error::Incomplete)
}

fn cause<T, E: StdError + 'static>(
    slot: &Option<Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|error| error as _)
}
