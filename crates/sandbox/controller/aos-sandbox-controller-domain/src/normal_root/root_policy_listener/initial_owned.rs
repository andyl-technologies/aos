//! Moves the same accepted Initial originals without releasing failed custody.
//!
//! The peer wrapper stays on its Flight in a nonissuing taken state. Partial
//! extraction restores every moved original. Failed programme custody stays
//! with its actual Current guard through owed disposition. Final return needs
//! the genuine future terminal provider; no generic restoration is exposed.

use aos_sandbox_policy::native::{RootCurrentAcceptedOriginalsV1, RootOwnedCurrentOriginalV1};

use super::{
    NormalRootStartupErrorV1, NormalRootStartupErrorV1 as Error, RootPolicyAcceptedFlightV1,
    serving,
};

impl<'listener, 'startup> RootPolicyAcceptedFlightV1<'listener, 'startup> {
    /// Moves the same admitted Initial producer and retained stream together.
    ///
    /// # Errors
    /// Refuses repeated, foreign or incomplete custody, restoring every
    /// partially moved original before returning its actual error.
    pub(crate) fn take_initial_current_originals_v1(
        &mut self,
    ) -> Result<RootCurrentAcceptedOriginalsV1<'startup>, Error> {
        // These are passive custody/order checks at the already-admitted
        // Initial slot, not a fresh native peer or selected-service sample.
        if self.closed.is_some()
            || self.finished
            || self.dispatch.is_some()
            || !self.transferred
            || self.purpose_peer.is_some()
            || self.purpose_admission.is_some()
            || !matches!(self.controller_admission, Some(Ok(())))
        {
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        let peer = match self.controller_peer.as_mut() {
            Some(peer) => peer,
            None => {
                self.closed.get_or_insert(Error::Service);
                return Err(Error::Service);
            }
        };
        let stream = match self.native.take() {
            Some(Ok(stream)) => stream,
            original => {
                self.native = original;
                self.closed.get_or_insert(Error::Service);
                return Err(Error::Service);
            }
        };
        match peer.take_initial_original_v1() {
            Ok(peer) => Ok(RootCurrentAcceptedOriginalsV1::from_taken_originals_v1(
                peer, stream,
            )),
            Err(error) => {
                // The peer wrapper restored its own whole variant. Restore
                // this same stream before exposing the failed handoff.
                self.native = Some(Ok(stream));
                self.closed.get_or_insert(Error::Service);
                Err(error)
            }
        }
    }

    /// Ends the actual native-owned socket before the same independent Root post.
    ///
    /// # Errors
    /// Retains failed dispatch, actual shutdown or independently owed Root
    /// currentness; every programme original remains with its owning attempt.
    pub(crate) fn finish_owned_current_negative_once_v1(
        &mut self,
        original: &mut RootOwnedCurrentOriginalV1<'startup>,
    ) -> Result<(), Error> {
        let returned: Result<(), Box<dyn std::error::Error>> = Err(Box::new(
            crate::policy_compiler::create_storage_current::RootCreateStorageCurrentErrorV1::Open,
        ));
        let kind = serving::ServingDispatchV1::Initial;
        macro_rules! owned_socket_stage_v1 {
            () => {{
                original.observe_negative_shutdown_once_v1();
                // This is the actual Copy result borrowed from the same native
                // shutdown owner, never a caller-supplied completion Result.
                self.shutdown = original.negative_shutdown_result_v1().copied();
            }};
        }
        self::dispatch_programme_v1!(self, returned, kind, owned_socket_stage_v1)
    }

    /// Quotes the actual atomic move, rollback and shutdown projections.
    pub(crate) fn initial_owned_transfer_control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        type Peer<'a> = super::super::RootControllerPeerReceivingV1<'a>;
        type Bundle<'a> = RootCurrentAcceptedOriginalsV1<'a>;
        type Native<'a> = RootOwnedCurrentOriginalV1<'a>;
        super::super::RootControllerPeerReceivingV1::initial_custody_control_bytes_v1()?
            .checked_add(size_of::<&mut Self>().checked_mul(3)?)?
            .checked_add(size_of::<Result<Bundle<'startup>, Error>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<&mut Peer<'startup>>>().checked_mul(3)?)?
            .checked_add(
                size_of::<
                    Option<
                        Result<
                            aos_linux_descriptors::unix_stream::RetainedUnixStream,
                            aos_linux_descriptors::Error,
                        >,
                    >,
                >()
                .checked_mul(3)?,
            )?
            .checked_add(size_of::<(&mut Self, &mut Native<'startup>)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<(), Error>>().checked_mul(3)?)?
            .checked_add(size_of::<Option<Result<(), rustix::io::Errno>>>().checked_mul(3)?)?
            .checked_add(size_of::<bool>().checked_mul(9)?)?
            .checked_add(size_of::<Option<usize>>().checked_mul(3)?)
    }
}

// The ordinary expansion is byte-conserved at every old dispatch frontier.
// Only the private socket adapter differs for the genuinely owned programme.
#[rustfmt::skip]
macro_rules! dispatch_programme_v1 {
    ($owner:ident, $returned:ident, $kind:ident, $socket:ident) => {{
        let invalid = $owner.closed.is_some() || $owner.dispatch.is_some() || !$owner.transferred;
        if $owner.finish_order.is_none() {
            $owner.finish_order = Some(if invalid { Err(NormalRootStartupErrorV1::Service) } else { Ok(()) });
        }
        if $owner.dispatch.is_none() {
            $owner.dispatch = Some($returned);
        } else if $owner.rejected_dispatch.is_none() {
            $owner.rejected_dispatch = Some($returned);
        } else {
            // No unbounded rejected-offer list or implicit dropping of a new
            // whole error. The offered owner remains on this stack at death.
            std::process::abort();
        }
        if invalid {
            $owner.closed.get_or_insert(NormalRootStartupErrorV1::Service);
        }
        // An invalid handler disposition cannot cancel the already armed post.
        // Keep its offered result and every native owner through that post.
        if !matches!($kind, serving::ServingDispatchV1::DeleteCompletion | serving::ServingDispatchV1::ExecutionNoApply | serving::ServingDispatchV1::StopCleanup) {
            $socket!();
        }
        $owner.finish_native_post_once();
        $owner.finished = !invalid
            && matches!($owner.dispatch, Some(Ok(())))
            && $owner.socket_disposition_matches_v1($kind)
            && matches!($owner.after, Some(Ok(())));
        if $owner.finished {
            $owner.complete_serving_dispatch_v1($kind)
        } else {
            $owner.listener.failed = true;
            Err(NormalRootStartupErrorV1::Service)
        }
    }};
}

pub(super) use dispatch_programme_v1;
