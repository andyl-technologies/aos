//! Parks a reached peer value before the same trailing endpoint observation.
//!
//! The ordinary and liveness-only callers immediately use this same engine.
//! The selected result owner contains no socket or peer constructor authority.

use super::*;
use super::super::current_replay::{ReplayValue, security_value};
use super::super::peer_liveness::{
    ObservedBrokerPeerOriginalV1, recovery_peer_liveness_footprint_v1,
};

#[derive(Default)]
pub(in crate::recovery) struct CurrentPeerOriginalsV1 {
    endpoint_before_native: crate::endpoint::RetainedEndpointRevalidationOriginalV1,
    endpoint_after_native: crate::endpoint::RetainedEndpointRevalidationOriginalV1,
    endpoint_before: Option<Result<(), BrokerSessionSecurityError>>,
    native: ObservedBrokerPeerOriginalV1,
    peer: Option<Result<ObservedBrokerPeerExecutionV1, BrokerSessionSecurityError>>,
    endpoint_after: Option<Result<(), BrokerSessionSecurityError>>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    closed: Option<BrokerSessionSecurityError>,
}

impl CurrentPeerOriginalsV1 {
    pub(in crate::recovery) fn observe_once(
        &mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.endpoint_before.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let result = match journal.observe_peer_current_engine(
            transcript,
            connection_peer,
            None,
            Some(self),
        ) {
            Ok(value) => {
                drop(value);
                Ok(())
            }
            Err(cause) => Err(cause),
        };
        self.returned = Some(result);
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(BrokerSessionSecurityError::Currentness)
        }
    }

    pub(in crate::recovery) fn value(&self) -> Option<&ObservedBrokerPeerExecutionV1> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        self.peer.as_ref()?.as_ref().ok()
    }

    pub(in crate::recovery) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T>(
            result: &Option<Result<T, BrokerSessionSecurityError>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            result.as_ref()?.as_ref().err().map(|cause| cause as _)
        }

        self.endpoint_before_native.failure().or_else(|| cause(&self.endpoint_before))
            .or_else(|| self.native.failure())
            .or_else(|| cause(&self.peer))
            .or_else(|| self.endpoint_after_native.failure())
            .or_else(|| cause(&self.endpoint_after))
            .or_else(|| cause(&self.returned))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(crate) fn retained_endpoint_open_files_v1() -> Option<usize> {
        usize::try_from(crate::endpoint::RetainedEndpointRevalidationOriginalV1::receiving_demand_v1()?
            .get(aos_sandbox_core::ResourceDimension::OpenFiles)).ok()?.checked_mul(2)
    }

    pub(in crate::recovery) fn receiving_footprint_v1() -> Option<(usize, usize)> {
        let (native_bytes, native_cells, native_construction) =
            recovery_peer_liveness_footprint_v1();
        let endpoint_bytes = usize::try_from(
            crate::endpoint::RetainedEndpointRevalidationOriginalV1::receiving_demand_v1()?
                .get(aos_sandbox_core::ResourceDimension::MemoryBytes)).ok()?.checked_mul(2)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(endpoint_bytes)?
            .checked_add(std::mem::size_of::<ReplayValue<'static, ObservedBrokerPeerExecutionV1>>())?
            .checked_add(std::mem::size_of::<[
                Result<ReplayValue<'static, ObservedBrokerPeerExecutionV1>, BrokerSessionSecurityError>; 2
            ]>())?
            .checked_add(std::mem::size_of::<[usize; 6]>())?
            .checked_add(native_bytes)?
            .checked_add(native_construction)?;
        // The two interval Results and closure references occupy Memory. They
        // introduce no namespace entries or additional native observations.
        // Four operation/return Results and the once-only refusal cell.
        Some((bytes, native_cells.checked_add(5)?))
    }
}

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn observe_peer_current_engine<'owner>(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        connection_peer: &ConnectionPeerIdentity,
        liveness_only: Option<&mut ObservedBrokerPeerOriginalV1>,
        originals: Option<&'owner mut CurrentPeerOriginalsV1>,
    ) -> Result<ReplayValue<'owner, ObservedBrokerPeerExecutionV1>, BrokerSessionSecurityError> {
        let retained_post = originals.is_some();
        let (before, native, peer_slot, after, before_native, after_native) = match originals {
            Some(originals) => {
                // These are mutually exclusive private call recipes. Combining
                // two destinations would silently substitute one live sample.
                if liveness_only.is_some() {
                    std::process::abort();
                }
                (
                    Some(&mut originals.endpoint_before),
                    Some(&mut originals.native),
                    Some(&mut originals.peer),
                    Some(&mut originals.endpoint_after),
                    Some(&mut originals.endpoint_before_native),
                    Some(&mut originals.endpoint_after_native),
                )
            }
            None => (None, liveness_only, None, None, None, None),
        };
        let observed = (|| {
            security_value(match before_native {
                Some(original) => self.endpoint.revalidate_into_v1(original),
                None => self.endpoint.revalidate(),
            }, before)?;
            let process_execution_id = match self.endpoint.role() {
                BrokerSessionDurableEndpointV1::Client => transcript.broker_process(),
                BrokerSessionDurableEndpointV1::Broker => transcript.client_process(),
            };
            let observed = match native {
                Some(originals) => ObservedBrokerPeerExecutionV1::from_connection_with_originals(
                    connection_peer,
                    process_execution_id,
                    Some(originals),
                ),
                None => ObservedBrokerPeerExecutionV1::from_connection(
                    connection_peer,
                    process_execution_id,
                ),
            };
            security_value(observed, peer_slot)
        })();

        if observed.is_err() && !retained_post {
            return observed;
        }

        // A paid retained interval keeps its endpoint post independent of the
        // preceding native result. Ordinary callers keep their short circuit.
        let post = security_value(match after_native {
            Some(original) => self.endpoint.revalidate_into_v1(original),
            None => self.endpoint.revalidate(),
        }, after);
        let peer = observed?;
        post?;
        Ok(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::lifecycle_test_fixture::LifecycleTerminalFixture;

    #[test]
    fn failed_entry_still_retains_the_independent_endpoint_post() {
        let mut fixture = LifecycleTerminalFixture::new();
        let transcript = fixture.currentness.as_ref().unwrap().transcript.clone();
        LifecycleTerminalFixture::replace_client_key(&fixture.client_path);
        let mut originals = CurrentPeerOriginalsV1::default();

        assert!(originals.observe_once(
            &mut fixture.journal, &transcript, fixture.socket.peer(),
        ).is_err());

        let before = originals.endpoint_before.as_ref().unwrap().as_ref().unwrap_err();
        let after = originals.endpoint_after.as_ref().unwrap().as_ref().unwrap_err();
        let native_before = originals.endpoint_before_native.failure().unwrap();
        let native_after = originals.endpoint_after_native.failure().unwrap();
        assert!(!std::ptr::eq(before, after));
        assert!(!std::ptr::addr_eq(native_before, native_after));
        assert!(originals.peer.is_none());
        assert!(originals.native.failure().is_none());
        assert!(originals.value().is_none());
        assert!(std::ptr::addr_eq(originals.failure().unwrap(), native_before));
    }

    #[test]
    fn ordinary_and_retained_peer_match_and_reentry_keeps_the_original() {
        let mut fixture = LifecycleTerminalFixture::new();
        let transcript = fixture.currentness.as_ref().unwrap().transcript.clone();
        let ordinary = fixture.journal.observe_peer(&transcript, fixture.socket.peer()).unwrap();
        let mut originals = CurrentPeerOriginalsV1::default();

        originals.observe_once(&mut fixture.journal, &transcript, fixture.socket.peer()).unwrap();

        let retained = originals.value().unwrap();
        assert_eq!(retained.uid, ordinary.uid);
        assert_eq!(retained.gid, ordinary.gid);
        assert_eq!(retained.pid, ordinary.pid);
        assert_eq!(retained.process_execution_id, ordinary.process_execution_id);
        assert!(originals.failure().is_none());
        let first = retained as *const _;
        LifecycleTerminalFixture::replace_client_key(&fixture.client_path);
        assert!(originals.observe_once(
            &mut fixture.journal, &transcript, fixture.socket.peer(),
        ).is_err());
        assert!(originals.value().is_none());
        assert_eq!(originals.peer.as_ref().unwrap().as_ref().unwrap() as *const _, first);
        assert!(matches!(originals.endpoint_after, Some(Ok(()))));
        assert!(originals.failure().is_some());
    }
}

#[cfg(test)]
mod dedicated_endpoint_tests {
    use super::*;
    use super::super::lifecycle_test_fixture::LifecycleTerminalFixture;

    #[test]
    fn failed_primary_and_owed_peer_each_keep_both_native_endpoint_prefixes() {
        let mut fixture = LifecycleTerminalFixture::new();
        let transcript = fixture.currentness.as_ref().unwrap().transcript.clone();
        let mut primary = CurrentPeerOriginalsV1::default();
        let mut owed = CurrentPeerOriginalsV1::default();
        LifecycleTerminalFixture::replace_client_key(&fixture.client_path);

        assert!(primary.observe_once(&mut fixture.journal, &transcript, fixture.socket.peer()).is_err());
        assert!(owed.observe_once(&mut fixture.journal, &transcript, fixture.socket.peer()).is_err());

        for endpoint in [&primary.endpoint_before_native, &primary.endpoint_after_native,
            &owed.endpoint_before_native, &owed.endpoint_after_native]
        {
            assert!(endpoint.failure().is_some());
            // Each check fails on the held key before opening fresh files,
            // retaining its own two completed manifest reads instead.
            assert_eq!(endpoint.retained_file_count_v1(), 0);
            let (first, repeated) = endpoint.retained_manifest_pair_v1().unwrap();
            assert!(!first.is_empty());
            assert_eq!(first, repeated);
        }
        assert!(primary.endpoint_after.is_some());
        assert!(owed.endpoint_after.is_some());
        let primary_bytes = primary.endpoint_before_native
            .retained_manifest_pair_v1().unwrap().0.as_ptr();
        let owed_bytes = owed.endpoint_before_native
            .retained_manifest_pair_v1().unwrap().0.as_ptr();
        assert_ne!(primary_bytes, owed_bytes);

        assert!(primary.observe_once(&mut fixture.journal, &transcript, fixture.socket.peer()).is_err());
        assert!(owed.observe_once(&mut fixture.journal, &transcript, fixture.socket.peer()).is_err());
        assert_eq!(primary.endpoint_before_native
            .retained_manifest_pair_v1().unwrap().0.as_ptr(), primary_bytes);
        assert_eq!(owed.endpoint_before_native
            .retained_manifest_pair_v1().unwrap().0.as_ptr(), owed_bytes);
    }

    #[test]
    fn complete_positive_peer_physically_disposes_its_fresh_endpoint_prefixes() {
        let mut fixture = LifecycleTerminalFixture::new();
        let transcript = fixture.currentness.as_ref().unwrap().transcript.clone();
        let mut original = CurrentPeerOriginalsV1::default();

        original.observe_once(&mut fixture.journal, &transcript, fixture.socket.peer()).unwrap();

        assert_eq!(original.endpoint_before_native.retained_file_count_v1(), 0);
        assert_eq!(original.endpoint_after_native.retained_file_count_v1(), 0);
        assert!(original.value().is_some());
    }
}
