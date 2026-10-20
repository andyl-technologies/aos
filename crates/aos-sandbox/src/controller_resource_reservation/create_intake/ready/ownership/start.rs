//! Advances one genuine accepted Start through the sole Ownership contact body.
//!
//! The new Start C original funds all credentials, retained attempts and exact
//! record traffic. No old J or Cache-held currentness callback is selected.
//! Query/resume always names the same actual claim; the preceding lease is an
//! exact compare-and-swap fence and never a renewed Start time authority.

use super::*;
use crate::OriginalStartHostRootLoanV1;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_ownership_protocol::ExpectedOwnershipLease;

#[derive(Clone, Copy)]
enum First { CredentialsFunding, Credentials, Claim, FlightFunding, Growth, Flight(usize), LeaseScope, NativeAfter, Reentry }

pub(in crate::controller_resource_reservation::create_intake) struct StartOwnershipOriginalV1 {
    credentials: credentials::ControllerOwnershipOriginalV1,
    credential_funding: Option<Result<(), ResourceReservationErrorV1>>,
    claim: Option<Result<OwnershipClaimV1, OwnershipError>>,
    attempts: Vec<OwnershipFlightV1>,
    funding: Option<Result<(), ResourceReservationErrorV1>>,
    growth: Option<Result<(), TryReserveError>>,
    verified: Option<usize>,
    lease_scope: Option<Result<(), OwnershipError>>,
    progress: Option<Result<CreateStorageOwnershipProgressV1, OwnershipError>>,
    native_after: Option<Result<(), ResourceReservationErrorV1>>,
    first: Option<First>,
}

impl StartOwnershipOriginalV1 {
    pub(in crate::controller_resource_reservation::create_intake) fn new() -> Self {
        Self {credentials: Default::default(), credential_funding:None, claim:None,
            attempts:Vec::new(), funding:None, growth:None, verified:None,
            progress:None, lease_scope:None, native_after:None, first:None}
    }

    pub(in crate::controller_resource_reservation::create_intake) fn completed_v1(&self) -> bool {
        self.first.is_none() && self.verified.is_some() && matches!(self.native_after, Some(Ok(())))
    }

    pub(in crate::controller_resource_reservation::create_intake) fn lease_v1(&self)
        -> Result<&SignedOwnershipLease, ResourceReservationErrorV1> {
        if !self.completed_v1() {return Err(ResourceReservationErrorV1::Conflict);}
        self.attempts.get(self.verified.ok_or(ResourceReservationErrorV1::Conflict)?)
            .and_then(|flight|flight.signed.value()).ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn claim_v1(&self)
        -> Result<&OwnershipClaimV1, ResourceReservationErrorV1> {
        self.lease_v1()?;
        self.claim.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn resident_demand_v1(&self)
        -> Result<ResourceVector, ResourceReservationErrorV1> {
        let bad=||ResourceReservationErrorV1::Conflict;
        let bytes=std::mem::size_of::<Self>().checked_mul(2)
            .and_then(|bytes|bytes.checked_add(self.attempts.capacity().checked_mul(std::mem::size_of::<OwnershipFlightV1>())?.checked_mul(2)?))
            .and_then(|bytes|u64::try_from(bytes).ok()).ok_or_else(bad)?;
        let mut demand=pricing::credential_representation_demand_v1(false).ok_or_else(bad)?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes,bytes))?;
        if !self.attempts.is_empty() {
            let one=pricing::flight_representation_demand_v1(self.credentials.verifier().map_err(|_|bad())?,false)
                .ok_or_else(bad)?;
            for _ in &self.attempts {demand=demand.checked_add(one)?;}
        }
        Ok(demand)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn progress_once_v1(
        &mut self,loan:&mut OriginalStartHostRootLoanV1<'_, '_>,controller:&Journal,
    )->Result<CreateStorageOwnershipProgressV1,ResourceReservationErrorV1> {
        if self.first.is_some() || self.verified.is_some() {
            self.first.get_or_insert(First::Reentry);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // A previous positive native result may be retired only after the
        // genuine lower next-turn entry. Failed/uncertain transport stays in
        // its own immutable prior attempt and is never replaced or replayed.
        if self.credential_funding.is_none() {
            self.credential_funding=Some(loan.require_complete_v1(controller,self.resident_demand_v1()?));
            if !matches!(self.credential_funding,Some(Ok(()))) {
                self.first=Some(First::CredentialsFunding);
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.credentials.capture_once();
            if self.credentials.require_complete().is_err() {
                self.first=Some(First::Credentials);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        if self.claim.is_none() {
            self.claim=Some((|| {
                loan.require_current_v1(controller)?;
                let (_,_,previous)=loan.original_create_v1().publication_material_v1()?;
                let (manifest, _) = loan.start_assignment_v2(controller)?;
                let model=manifest.manifest();
                let seconds = initial_renewal_duration_v1(loan.start_origin_data_v1().accepted_v1())?;
                let assignment=LeaseAssignment::new(model.sandbox(),model.incarnation(),model.epoch(),manifest.digest())?;
                let expected=ExpectedOwnershipLease::new(previous.generation(),previous.digest())?;
                Ok(OwnershipClaimV1::advance(loan.parent_operation_v1().into_bytes(),assignment,
                    model.desired_generation(),model.node(),expected,
                    seconds.min(aos_sandbox_ownership_protocol::MAXIMUM_REQUESTED_DURATION_SECONDS))?)
            })());
            if !matches!(self.claim,Some(Ok(_))) {
                self.first=Some(First::Claim);
                return Err(ResourceReservationErrorV1::Conflict);
            }
        }
        let count=self.attempts.len().checked_add(1).ok_or(ResourceReservationErrorV1::Conflict)?;
        let one=pricing::flight_representation_demand_v1(self.credentials.verifier()
            .map_err(|_|ResourceReservationErrorV1::Conflict)?,false).ok_or(ResourceReservationErrorV1::Conflict)?;
        let demand=self.resident_demand_v1()?.checked_add(one)?
            .checked_add(pricing::flight_traffic_demand_v1().ok_or(ResourceReservationErrorV1::Conflict)?)?;
        self.funding=Some(loan.require_complete_v1(controller,demand));
        if !matches!(self.funding,Some(Ok(()))) {
            self.first=Some(First::FlightFunding);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.growth=Some(self.attempts.try_reserve_exact(1));
        if !matches!(self.growth,Some(Ok(()))) {
            self.first=Some(First::Growth);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.attempts.push(OwnershipFlightV1::default());
        let index=count-1;
        let flight=&mut self.attempts[index];
        let (origin,cutoff)=loan.original_horizon_v1();
        let (manifest, _) = loan.start_assignment_v2(controller)?;
        flight.primary=Some(flight.run_engine(&self.credentials,retained(&self.claim)
            .map_err(|_|ResourceReservationErrorV1::Conflict)?,manifest,origin,cutoff,Some(loan.start_origin_data_v1())));
        // This same owning native End executes even after contact/parse/signature
        // failure. Its result stays with the actual transport, before outer C.
        flight.finish_local_once_v1();
        flight.result=Some((|| {
            let progress=*retained(&flight.primary)?;
            if matches!(flight.connected,Some(Ok(_))) && !flight.ending.as_ref().is_some_and(|ending|ending.is_complete()) {
                return Ok(CreateStorageOwnershipProgressV1::Unavailable);
            }
            Ok(progress)
        })());
        self.progress=Some(match retained(&flight.result) {
            Ok(progress)=>Ok(*progress), Err(_)=>Err(OwnershipError::Closed),
        });
        let progress=match retained(&self.progress) {
            Ok(progress)=>*progress,
            Err(_)=>{self.first=Some(First::Flight(index));return Err(ResourceReservationErrorV1::Conflict);}
        };
        if matches!(progress,CreateStorageOwnershipProgressV1::Rejected(_)) {
            self.first=Some(First::Flight(index));
        }
        if progress==CreateStorageOwnershipProgressV1::Verified {
            self.lease_scope = Some((|| {
                let signed = flight.signed.value().ok_or(OwnershipError::Closed)?;
                let accepted = loan.start_origin_data_v1().accepted_v1();
                let latest_issue = latest_permitted_issuer_wall_v1(accepted)?;
                if signed.authority_issued_seconds() > latest_issue
                    || signed.authority_expires_seconds() > accepted.original_resident_authority_expiry_v1() {
                    return Err(OwnershipError::Closed);
                }
                Ok(())
            })());
            if !matches!(self.lease_scope, Some(Ok(()))) {
                self.first = Some(First::LeaseScope);
                return Err(ResourceReservationErrorV1::Conflict);
            }
            self.verified=Some(index);
        }
        Ok(progress)
    }

    pub(in crate::controller_resource_reservation::create_intake) fn prepare_entered_native_turn_v1(&mut self) {
        if matches!(self.native_after,Some(Err(_))) {std::process::abort();}
        self.native_after=None;
    }

    pub(in crate::controller_resource_reservation::create_intake) fn retain_native_after_v1(
        &mut self,result:Result<(),ResourceReservationErrorV1>,
    ) {
        if self.native_after.is_some() {std::process::abort();}
        self.native_after=Some(result);
        if !matches!(self.native_after,Some(Ok(()))) {self.first.get_or_insert(First::NativeAfter);}
    }

    pub(in crate::controller_resource_reservation::create_intake) fn selected_original_v1(&self)->bool {
        matches!(self.first,Some(First::CredentialsFunding|First::FlightFunding|First::NativeAfter))
    }

    pub(in crate::controller_resource_reservation::create_intake) fn failure(&self)->Option<&(dyn Error+'static)> {
        match self.first? {
            First::CredentialsFunding=>error(&self.credential_funding),
            First::Credentials=>self.credentials.failure(),
            First::Claim=>error(&self.claim),
            First::FlightFunding=>error(&self.funding),
            First::Growth=>error(&self.growth),
            First::Flight(index)=>self.attempts.get(index).and_then(|flight|flight.contacted_failure_v1()
                .or_else(||error(&flight.result))).or_else(||error(&self.progress)),
            First::LeaseScope=>error(&self.lease_scope),
            First::NativeAfter=>error(&self.native_after),
            First::Reentry=>Some(&CLOSED as &(dyn Error+'static)),
        }.or(Some(&CLOSED))
    }
}

// The SAME ordinary verifier requires issued <= observed_after_wall - skew.
// validate_origin_clock independently requires observed_after_wall < the fixed
// acquisition wall expiry. With integer wall seconds and nonnegative signed
// skew, every acceptable issuer time is at most acquisition_expiry - 1. Using
// that latest permitted time avoids spending a generation on a request whose
// full duration would outlive the immutable parent after transport latency.
fn latest_permitted_issuer_wall_v1(
    accepted: aos_sandbox_protocol::domain_ledger::operation::AcceptedStartOriginDataV1,
) -> Result<i64, OwnershipError> {
    accepted.original_wall_expiry_v1().and_then(|expiry| expiry.checked_sub(1))
        .ok_or(OwnershipError::Closed)
}

fn initial_renewal_duration_v1(
    accepted: aos_sandbox_protocol::domain_ledger::operation::AcceptedStartOriginDataV1,
) -> Result<u64, OwnershipError> {
    let latest_issue = latest_permitted_issuer_wall_v1(accepted)?;
    let duration = accepted.original_resident_authority_expiry_v1()
        .checked_sub(latest_issue).and_then(|seconds| u64::try_from(seconds).ok())
        .filter(|seconds| *seconds > 0).ok_or(OwnershipError::Closed)?;
    Ok(duration.min(aos_sandbox_ownership_protocol::MAXIMUM_REQUESTED_DURATION_SECONDS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;
    use aos_sandbox_protocol::domain_ledger::operation::AcceptedStartOriginDataV1;

    fn accepted(capability: i64, policy: i64, timeout_seconds: u64) -> AcceptedStartOriginDataV1 {
        let clock = RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(), [2; 16],
            100, 10_000_000_000,
        ).unwrap();
        AcceptedStartOriginDataV1::from_data_v1(clock, 90_000_000_000,
            capability, policy, timeout_seconds * 1_000_000_000).unwrap()
    }

    #[test]
    fn initial_renewal_survives_acquisition_latency_without_exceeding_parent() {
        let original = accepted(300, 250, 30);
        let seconds = initial_renewal_duration_v1(original).unwrap();
        let latest = latest_permitted_issuer_wall_v1(original).unwrap();
        assert_eq!(latest, 129);
        assert_eq!(seconds, 121);
        assert_eq!(latest + i64::try_from(seconds).unwrap(), 250);
        assert!(seconds > 30);
    }

    #[test]
    fn initial_renewal_preserves_stricter_parent_and_issuer_limits() {
        let original = accepted(120, 250, 30);
        assert_eq!(initial_renewal_duration_v1(original).unwrap(), 1);
        let long = accepted(i64::MAX, i64::MAX, 30);
        assert_eq!(initial_renewal_duration_v1(long).unwrap(),
            aos_sandbox_ownership_protocol::MAXIMUM_REQUESTED_DURATION_SECONDS);
    }
}

const CLOSED:ResourceReservationErrorV1=ResourceReservationErrorV1::Conflict;
