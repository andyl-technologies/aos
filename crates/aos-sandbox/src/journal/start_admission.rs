//! Rejoins the exact Start native entry to the same intrinsic Journal barrier.

use super::*;
use crate::controller_resource_reservation::StartNativeStateV1;

pub(crate) struct StartAdmissionJournalIdentityV1 {instance:std::sync::Arc<JournalAuthorityInstance>}

impl Journal {
    pub(crate) fn start_admission_identity_v1(&self,original:&StartNativeStateV1)
        ->Result<StartAdmissionJournalIdentityV1,JournalError> {
        original.require_current_v1(self).map_err(|_|JournalError::ProtectedBoundary)?;
        Ok(StartAdmissionJournalIdentityV1{instance:std::sync::Arc::clone(&self.authority_instance)})
    }
    pub(crate) fn require_start_admission_entry_v1(&self,entry:&crate::AcceptedStartEntryOriginalV1)
        ->Result<(),crate::ResourceReservationErrorV1> {
        self.start_admission.as_ref().ok_or(crate::ResourceReservationErrorV1::Conflict)?
            .require_entry_v1(entry,self)
    }
    pub(crate) fn bind_start_admission_plan_v1(&mut self,
        original:&crate::controller_resource_reservation::AcceptedStartPlanOriginalV1<'_>,
    )->Result<(),crate::ResourceReservationErrorV1> {
        let mut scope=self.start_admission.take().ok_or(crate::ResourceReservationErrorV1::Conflict)?;
        let returned=scope.bind_actual_plan_v1(original,self);
        self.start_admission=Some(scope);
        returned
    }
    pub(crate) fn fence_start_admission_v1(&mut self,identity:&StartAdmissionJournalIdentityV1)->Result<(),JournalError> {
        if !std::sync::Arc::ptr_eq(&identity.instance,&self.authority_instance) {return Err(JournalError::ProtectedBoundary);}
        self.native.poison();
        Ok(())
    }
}
