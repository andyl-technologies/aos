//! Checks closed native17 handshake fields and their actual retained backing.

use super::*;

historical_struct!(ResumeSession {
    session_id: Id,
    incarnation_id: Id,
    resume_token: Bytes,
    unresolved_operation_ids: IdSet,
});

impl ObserveMetadata for ResumeSession {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            session_id,
            incarnation_id,
            resume_token,
            unresolved_operation_ids,
        } = self;
        observer.observe(session_id)?;
        observer.observe(incarnation_id)?;
        observer.observe(resume_token)?;
        observer.observe(unresolved_operation_ids)?;
        Ok(())
    }
}

impl HistoricalType for HelloRequest {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let versions = ledger.read::<Vec<String>>(fields.named("versions")?, build)?;
        let session_id = ledger.read::<Id>(fields.named("session_id")?, build)?;
        let controller_nonce = ledger.read::<Bytes>(fields.named("controller_nonce")?, build)?;
        let required_features = ledger.read::<IdSet>(fields.named("required_features")?, build)?;
        let optional_features = ledger.read::<IdSet>(fields.named("optional_features")?, build)?;
        let limits = ledger.read::<Limits>(fields.named("limits")?, build)?;
        let admission_token = ledger.read::<Bytes>(fields.named("admission_token")?, build)?;
        let pending = fields.pair()?.ok_or_else(invalid)?;
        let (resume_session, pending) = if plain_string(pending.0)? == "resume_session" {
            if pending.1 == b"null" {
                return Err(invalid());
            }
            (
                ledger.read::<Option<ResumeSession>>(pending.1, build)?,
                fields.pair()?.ok_or_else(invalid)?,
            )
        } else {
            (build.then_some(None), pending)
        };
        if plain_string(pending.0)? != "extensions" {
            return Err(invalid());
        }
        let extensions = ledger.read::<Extensions>(pending.1, build)?;
        fields.finish()?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            versions: versions.ok_or_else(invalid)?,
            session_id: session_id.ok_or_else(invalid)?,
            controller_nonce: controller_nonce.ok_or_else(invalid)?,
            required_features: required_features.ok_or_else(invalid)?,
            optional_features: optional_features.ok_or_else(invalid)?,
            limits: limits.ok_or_else(invalid)?,
            admission_token: admission_token.ok_or_else(invalid)?,
            resume_session: resume_session.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }
}

impl ObserveMetadata for HelloRequest {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            versions,
            session_id,
            controller_nonce,
            required_features,
            optional_features,
            limits,
            admission_token,
            resume_session,
            extensions,
        } = self;
        observer.observe(versions)?;
        observer.observe(session_id)?;
        observer.observe(controller_nonce)?;
        observer.observe(required_features)?;
        observer.observe(optional_features)?;
        observer.observe(limits)?;
        observer.observe(admission_token)?;
        observer.observe(resume_session)?;
        observer.observe(extensions)?;
        Ok(())
    }
}

historical_struct!(ResumedOperation {
    operation_id: Id,
    operation_state: OperationState,
    outcome: Nullable<Map<String, Value>>,
});

impl ObserveMetadata for ResumedOperation {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            operation_id,
            operation_state,
            outcome,
        } = self;
        observer.observe(operation_id)?;
        observer.observe(operation_state)?;
        observer.observe(outcome)?;
        Ok(())
    }
}

historical_struct!(HelloResult {
    version: String,
    session_id: Id,
    incarnation_id: Id,
    controller_nonce: Bytes,
    provider_nonce: Bytes,
    selected_features: IdSet,
    limits: Limits,
    resume_token: Nullable<Bytes>,
    provider_identity: ProviderManifest,
    resumed_operations: Vec<ResumedOperation>,
});

impl ObserveMetadata for HelloResult {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            version,
            session_id,
            incarnation_id,
            controller_nonce,
            provider_nonce,
            selected_features,
            limits,
            resume_token,
            provider_identity,
            resumed_operations,
        } = self;
        observer.observe(version)?;
        observer.observe(session_id)?;
        observer.observe(incarnation_id)?;
        observer.observe(controller_nonce)?;
        observer.observe(provider_nonce)?;
        observer.observe(selected_features)?;
        observer.observe(limits)?;
        observer.observe(resume_token)?;
        observer.observe(provider_identity)?;
        observer.observe(resumed_operations)?;
        Ok(())
    }
}

#[path = "handshake/native17_build.rs"]
mod native17_build;
