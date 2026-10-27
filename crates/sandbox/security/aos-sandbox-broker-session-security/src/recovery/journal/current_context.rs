//! Retains the actual fixed context before its trailing endpoint/floor posts.
//!
//! Ordinary callers use the same ordered engine and receive their actual local
//! value. Selected callers park every reached Result before the next operation;
//! the capture lends no endpoint, peer, trust root, payer or live authority.

use super::*;
use super::super::current_replay::{ReplayValue, security_value};
use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestContextOriginalsV1;

#[derive(Default)]
pub(in crate::recovery) struct CurrentContextOriginalsV1 {
    source_endpoint: [crate::endpoint::RetainedEndpointRevalidationOriginalV1; 2],
    floor_before: Option<Result<(), BrokerSessionSecurityError>>,
    endpoint_before: Option<Result<(), BrokerSessionSecurityError>>,
    manifest: BrokerSessionManifestContextOriginalsV1,
    context: Option<Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError>>,
    endpoint_after: Option<Result<(), BrokerSessionSecurityError>>,
    binding: Option<Result<(), BrokerSessionSecurityError>>,
    floor_after: Option<Result<(), BrokerSessionSecurityError>>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    closed: Option<BrokerSessionSecurityError>,
}

impl CurrentContextOriginalsV1 {
    pub(in crate::recovery) fn observe_once(
        &mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        self.observe_with_storage_receiving_v3(journal, transcript, None)
    }

    pub(in crate::recovery) fn observe_with_storage_receiving_v3(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        receiving: Option<&mut dyn StorageFloorFinancialSourceV2>,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.floor_before.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }

        let returned = match journal.current_context_with_storage_receiving_v2(transcript, Some(self), receiving) {
            Ok(value) => {
                drop(value);
                Ok(())
            }
            Err(cause) => Err(cause),
        };
        self.returned = Some(returned);
        if matches!(self.returned, Some(Ok(()))) {
            Ok(())
        } else {
            Err(BrokerSessionSecurityError::Currentness)
        }
    }

    pub(in crate::recovery) fn value(
        &self,
    ) -> Option<&ProtectedBrokerSessionVerificationContextV1> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        self.context.as_ref()?.as_ref().ok()
    }

    pub(in crate::recovery) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn cause<T>(
            value: &Option<Result<T, BrokerSessionSecurityError>>,
        ) -> Option<&(dyn std::error::Error + 'static)> {
            value.as_ref()?.as_ref().err().map(|cause| cause as _)
        }

        cause(&self.floor_before)
            .or_else(|| self.source_endpoint[0].failure())
            .or_else(|| cause(&self.endpoint_before))
            .or_else(|| self.manifest.failure())
            .or_else(|| cause(&self.context))
            .or_else(|| self.source_endpoint[1].failure())
            .or_else(|| cause(&self.endpoint_after))
            .or_else(|| cause(&self.binding))
            .or_else(|| cause(&self.floor_after))
            .or_else(|| cause(&self.returned))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    pub(in crate::recovery) fn receiving_footprint_v1() -> Option<(usize, usize)> {
        let (keys, cells) = BrokerSessionManifestContextOriginalsV1::receiving_footprint_v1();
        let memory = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<
                ReplayValue<'static, ProtectedBrokerSessionVerificationContextV1>,
            >())?
            .checked_add(keys)?
            .checked_add(std::mem::size_of::<Result<
                ReplayValue<'static, ProtectedBrokerSessionVerificationContextV1>,
                BrokerSessionSecurityError>>())?
            .checked_add(std::mem::size_of::<Option<Result<
                ReplayValue<'static, ()>, BrokerSessionSecurityError>>>().checked_mul(3)?)?;
        // Seven direct stage/return Results and the sticky refusal cell.
        Some((memory, cells.checked_add(8)?))
    }
}

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn current_context_with_originals<'owner>(
        &mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        originals: Option<&'owner mut CurrentContextOriginalsV1>,
    ) -> Result<
        ReplayValue<'owner, ProtectedBrokerSessionVerificationContextV1>,
        BrokerSessionSecurityError,
    > {
        self.current_context_with_storage_receiving_v2(transcript, originals, None)
    }

    pub(super) fn current_context_with_storage_receiving_v2<'owner>(&mut self,
        transcript: &VerifiedBrokerSessionTranscriptV1,
        originals: Option<&'owner mut CurrentContextOriginalsV1>,
        mut receiving: Option<&mut dyn super::tpm_floor::storage_receiving::StorageFloorFinancialSourceV2>,
    ) -> Result<ReplayValue<'owner, ProtectedBrokerSessionVerificationContextV1>, BrokerSessionSecurityError> {
        if originals.is_none() {
            if let Some(source) = receiving.as_mut() {
                return self.current_context_with_storage_archive_v3(transcript, &mut **source)
                    .map(ReplayValue::Ordinary);
            }
        }
        let source_retained = receiving.is_some();
        let retained_posts = originals.is_some();
        let (
            floor_before,
            endpoint_before,
            manifest,
            context_slot,
            endpoint_after,
            binding,
            floor_after,
            endpoint_before_native,
            endpoint_after_native,
        ) = match originals {
            Some(originals) => {
                let [before_native, after_native] = &mut originals.source_endpoint;
                (
                Some(&mut originals.floor_before),
                Some(&mut originals.endpoint_before),
                Some(&mut originals.manifest),
                Some(&mut originals.context),
                Some(&mut originals.endpoint_after),
                Some(&mut originals.binding),
                Some(&mut originals.floor_after),
                source_retained.then_some(before_native),
                source_retained.then_some(after_native),
            )},
            None => (None, None, None, None, None, None, None, None, None),
        };
        let primary = (|| {
            security_value(self.require_floor_current_with_storage_receiving_v2(receiving.as_mut()
                .map(|source| &mut **source as &mut dyn super::tpm_floor::storage_receiving::StorageFloorFinancialSourceV2)), floor_before)?;
            security_value(match endpoint_before_native {
                Some(original) => self.endpoint.revalidate_into_v1(original),
                None => self.endpoint.revalidate(),
            }, endpoint_before)?;
            let observed = match manifest {
                Some(originals) => self.endpoint.context_retaining_v1(transcript, originals),
                None => self.endpoint.context(transcript),
            };
            security_value(observed, context_slot)
        })();
        if !retained_posts && primary.is_err() { return primary; }

        // Selected callers prearm both actual after destinations. A refused
        // primary cannot suppress either the endpoint or floor observation.
        let endpoint_post = security_value(match endpoint_after_native {
            Some(original) => self.endpoint.revalidate_into_v1(original),
            None => self.endpoint.revalidate(),
        }, endpoint_after);
        let same_binding = match (primary.as_ref(), endpoint_post.as_ref()) {
            (Ok(context), Ok(_)) => Some(if context.protected_context_digest()
                != transcript.protected_context_digest()
                || context.protocol() != transcript.protocol()
                || context.client_process() != transcript.client_process()
                || context.broker_process() != transcript.broker_process()
            { Err(BrokerSessionSecurityError::Currentness) } else { Ok(()) }),
            _ => None,
        };
        let comparison = same_binding.map(|value| security_value(value, binding));
        let floor_post = if retained_posts || comparison.as_ref().is_some_and(Result::is_ok) {
            Some(security_value(self.require_floor_current_with_storage_receiving_v2(receiving), floor_after))
        } else { None };

        let context = primary?;
        endpoint_post?;
        comparison.ok_or(BrokerSessionSecurityError::Currentness)??;
        floor_post.ok_or(BrokerSessionSecurityError::Currentness)??;
        Ok(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::lifecycle_test_fixture::LifecycleTerminalFixture;

    #[test]
    fn trailing_binding_refusal_keeps_the_actual_constructed_context() {
        let mut client = LifecycleTerminalFixture::new();
        let mut storage = LifecycleTerminalFixture::storage_broker();
        let transcript = client.currentness.as_ref().unwrap().transcript.clone();
        // Both real protected endpoints stay owned. The unrelated Storage
        // context must be rejected against the original Host transcript.
        std::mem::swap(&mut client.journal.endpoint, &mut storage.journal.endpoint);
        let mut originals = CurrentContextOriginalsV1::default();

        assert!(originals.observe_once(&mut client.journal, &transcript).is_err());

        assert!(matches!(originals.floor_before, Some(Ok(()))));
        assert!(matches!(originals.endpoint_before, Some(Ok(()))));
        assert!(matches!(originals.context, Some(Ok(_))));
        assert!(matches!(originals.endpoint_after, Some(Ok(()))));
        assert!(matches!(originals.binding, Some(Err(_))));
        assert!(matches!(originals.floor_after, Some(Ok(()))));
        assert!(originals.value().is_none());
        let actual = originals.binding.as_ref().unwrap().as_ref().unwrap_err();
        assert!(std::ptr::eq(originals.failure().unwrap()
            .downcast_ref::<BrokerSessionSecurityError>().unwrap(), actual));
        let context = originals.context.as_ref().unwrap().as_ref().unwrap() as *const _;

        assert!(originals.observe_once(&mut client.journal, &transcript).is_err());
        assert_eq!(originals.context.as_ref().unwrap().as_ref().unwrap() as *const _, context);
        assert!(std::ptr::eq(originals.failure().unwrap()
            .downcast_ref::<BrokerSessionSecurityError>().unwrap(),
            originals.binding.as_ref().unwrap().as_ref().unwrap_err()));
    }
    #[test]
    fn selected_early_context_refusal_still_enters_endpoint_and_floor_afters() {
        let mut fixture = LifecycleTerminalFixture::new();
        let transcript = fixture.currentness.as_ref().unwrap().transcript.clone();
        LifecycleTerminalFixture::replace_client_key(&fixture.client_path);
        let mut original = CurrentContextOriginalsV1::default();

        assert!(original.observe_once(&mut fixture.journal, &transcript).is_err());

        assert!(matches!(original.floor_before, Some(Ok(()))));
        assert!(matches!(original.endpoint_before, Some(Err(_))));
        assert!(original.context.is_none());
        assert!(matches!(original.endpoint_after, Some(Err(_))));
        assert!(matches!(original.floor_after, Some(Ok(()))));
        assert!(original.binding.is_none());
        assert!(original.failure().is_some());
    }

}
