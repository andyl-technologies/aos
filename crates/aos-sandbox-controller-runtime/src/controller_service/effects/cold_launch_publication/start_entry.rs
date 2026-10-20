//! Hands genuine completed Create custody to the fresh Start native entry.
//!
//! The caller extracts the resident issuer only for this synchronous method,
//! passes the full actual Runtime header, then restores it before inspecting
//! any result. All old Root/Action/Attempt/Session models remain owned and
//! separately invoiced; no expired Create horizon funds the new operation.

use super::*;
use aos_sandbox::AcceptedStartEntryOriginalV1;
use aos_sandbox::public_api_session::PublicApiPeer;

impl OriginalCreateProvisioningIssuerV1 {
    fn begin_start_entry_once_v1<T:Sized>(&mut self,header:&T,controller:&mut Journal,
        source:&ProtectedSourceDomainJournalOwnerV1,peer:&PublicApiPeer,encoded:&[u8],
    )->Result<AcceptedStartEntryOriginalV1,ResourceReservationErrorV1> {
        self.require_healthy().map_err(|_|ResourceReservationErrorV1::Conflict)?;
        if !self.final_exchange.completed_v1() {return Err(ResourceReservationErrorV1::Conflict);}
        let original=self.native.as_mut().ok_or(ResourceReservationErrorV1::Conflict)?;
        let root=self.root.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let action=self.action.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?;
        let custody=self.pre_ack.attempt.borrow_create_stopped_terminal_custody_v1(
            original,controller,source)?;
        let entry=original.begin_original_start_entry_once_v1(&custody,root,action,
            controller,peer,encoded,header);
        Ok(entry)
    }
}

impl super::super::ProductionEffectExecutor {
    pub(in crate::controller_service::effects) fn prepare_start_entry_v1(&mut self,peer:&PublicApiPeer,encoded:&[u8],
        controller:&mut Journal,
    )->Result<Option<AcceptedStartEntryOriginalV1>,ResourceReservationErrorV1> {
        if self.start_entry.is_some() || self.start_entry_preparation.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        // No await, callback or Result projection can observe this temporary
        // header placeholder. The issuer returns unconditionally; Source never moves.
        let mut issuer=std::mem::replace(&mut self.create_provisioning,
            OriginalCreateProvisioningIssuerV1::new());
        let result=issuer.begin_start_entry_once_v1(&*self,controller,&self.source_domains,peer,encoded);
        self.create_provisioning=issuer;
        match result {
            Ok(mut entry)=>{
                self.start_entry_preparation=Some(Ok(()));
                // The original issuer is already back in its actual header.
                // The new paid entry rejoins that SAME stored association.
                let _=entry.observe_create_history_from_attempt_once_v1(
                    &self.create_provisioning.pre_ack.attempt,controller,&mut self.source_domains);
                Ok(Some(entry))
            }
            Err(cause)=>{self.start_entry_preparation=Some(Err(cause));Err(ResourceReservationErrorV1::Conflict)}
        }
    }
}
