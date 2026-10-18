//! Submits funded inline publication while retaining the actual reply on failure.
//!
//! The exclusive physical turn and synchronized funding precede the RPC mutex.
//! Kernel/content verification borrows the registered reply, so an unsuccessful
//! verification cannot discard its actual descriptor before owner reconciliation.

use super::running::PublisherRunningContext;
use super::{Client, Error, PeerPublishedObject, RequestPayload, invalidate, receipt};
use crate::{
    host_cache::PublisherRunningTurn,
    publisher_local::{
        socket::ReceivedPacket,
        wire::{BodyKey, BodyKind, Claim, Operation},
    },
};
use std::{fs::File, os::fd::AsFd, sync::Arc};
use terrane::host::{cache::HostDomainLocation, publication::PublicationClaim};

impl Client<HostDomainLocation> {
    /// Publishes actual inline plaintext under the physical owner's funded turn.
    ///
    /// The source and reply slots already belong to the retained executor job.
    /// Any accepted raw reply remains in that slot until all native and content
    /// checks succeed; failures require recovery rather than an automatic retry.
    ///
    /// # Errors
    /// Refuses foreign/stale custody, absent funding, non-inline claims, occupied
    /// reply slots, failed exchanges or native/kernel/plaintext verification.
    pub(crate) fn publish_inline_running(
        &self,
        source: &File,
        claim: PublicationClaim,
        context: &PublisherRunningContext,
        turn: &mut PublisherRunningTurn<'_>,
        reply: &mut Option<ReceivedPacket>,
    ) -> Result<PeerPublishedObject<HostDomainLocation>, Error> {
        let claim = self.inline_claim(claim)?;
        turn.check_publication(context, &claim, source)?;
        if reply.is_some() {
            return Err(Error::Invalid("publication reply slot already occupied"));
        }
        let descriptor = claim.descriptor().encode();
        let payload = RequestPayload {
            claim: Some(Claim {
                descriptor: descriptor.clone(),
                chunk_profile: self.config.chunk_profile_name.clone(),
                plaintext_size: claim.plaintext_size(),
                ..Default::default()
            }),
            body: Some(BodyKey {
                kind: BodyKind::Sealed as i32,
                descriptor,
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut state = self.lock()?;
        self.require_running_context(&state, context)?;
        let result = (|| {
            let received = self.exchange_payload_files(
                &mut state,
                Operation::Publish,
                payload,
                &[source.as_fd()],
            )?;
            *reply = Some(received);
            receipt::published_retained(
                reply,
                Arc::clone(&self.layout),
                self.config.identities.publish_uid,
                claim,
            )
        })();
        if result.is_err() {
            invalidate(&mut state);
        }
        result
    }
}
