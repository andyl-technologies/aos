//! Validates the genuine initial owner's held main with the ordinary schema engine.
//!
//! Both loans must belong to the same current Source original. The read context
//! lends only its actual immutable map and captured normal public manifest. It
//! constructs no Journal, native endpoint, signing key or namespace authority.

use aos_sandbox_broker_session_protocol::manifest::BrokerSessionManifestV1;
use aos_sandbox_controller_domain::method46_initial_startup::{
    METHOD46_INITIAL_SESSION_SCHEMA_BYTES_V1, METHOD46_INITIAL_SESSION_SCHEMA_CELLS_V1,
    Method46InitialMainReadbackLoanV1,
};

use super::super::schema_read::{SchemaReadDataV1, SessionSchemaContextV1, SessionSchemaReadV1};
use super::*;
use crate::method46_initial_provisioning::Method46InitialProvisionDecodeOriginalV1;

struct InitialSessionSchemaContextV1<'read, 'main, 'provision> {
    main: &'read Method46InitialMainReadbackLoanV1<'main>,
    provision: &'read Method46InitialProvisionDecodeOriginalV1<'provision>,
    original: &'read mut StorageFloorSchemaOriginalV3,
    role: BrokerSessionDurableEndpointV1,
    node: [u8; 16],
}

// The real Source pays this fixed bound before replay and before any of these
// slots exists. Dynamic encoded/model geometry comes from its actual held file.
const INITIAL_SCHEMA_RETAINED_BYTES_V1: usize = 2 * size_of::<StorageFloorSchemaOriginalV3>()
    + SLOTS
        * (size_of::<StoredReadOriginalsV1>()
            + size_of::<StoredBrokerSessionHistoryDecodeCaptureV1>()
            + size_of::<BrokerSessionManifestContextOriginalsV1>()
            + size_of::<Vec<u8>>()
            + size_of::<Vec<(Vec<u8>, Vec<u8>)>>()
            + size_of::<Vec<[u8; 16]>>()
            + BrokerSessionManifestContextOriginalsV1::receiving_footprint_v1().0
            + 2 * aos_sandbox_broker_session_protocol::manifest::BROKER_SESSION_MANIFEST_BYTES
            + 2 * size_of::<ProtectedBrokerSessionVerificationContextV1>()
            + 2 * size_of::<
                SessionSchemaReadV1<InitialSessionSchemaContextV1<'static, 'static, 'static>>,
            >()
            + 2 * size_of::<SchemaReadDataV1<'static>>());
const _: () = assert!(INITIAL_SCHEMA_RETAINED_BYTES_V1 <= METHOD46_INITIAL_SESSION_SCHEMA_BYTES_V1);

const _: () = assert!(
    SLOTS * (BrokerSessionManifestContextOriginalsV1::receiving_footprint_v1().1 + 7) + 2
        <= METHOD46_INITIAL_SESSION_SCHEMA_CELLS_V1
);

impl InitialSessionSchemaContextV1<'_, '_, '_> {
    fn manifest(&self) -> Result<&BrokerSessionManifestV1, BrokerSessionSecurityError> {
        self.provision
            .schema_manifest_for_main_v1(self.main)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }
}

impl SessionSchemaContextV1 for InitialSessionSchemaContextV1<'_, '_, '_> {
    fn read_data(&mut self) -> Result<SchemaReadDataV1<'_>, BrokerSessionSecurityError> {
        self.manifest()?;
        self.main
            .read_map_data_v1()
            .map(SchemaReadDataV1::Initial)
            .map_err(|_| BrokerSessionSecurityError::Currentness)
    }

    fn endpoint_role(&self) -> BrokerSessionDurableEndpointV1 {
        self.role
    }

    fn protocol_and_node(&self) -> (BrokerSessionProtocolV1, [u8; 16]) {
        (BrokerSessionProtocolV1::Storage, self.node)
    }

    fn purpose(&self) -> SessionPurpose {
        SessionPurpose::Ordinary
    }

    #[cfg(feature = "online-nix")]
    fn online_seed_data(&self) -> Option<([u8; 24], [u8; 640])> {
        None
    }

    fn closed_host_prepared_request_id_v2(
        &self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<Option<[u8; 16]>, BrokerSessionSecurityError> {
        self.manifest()?;
        super::super::host_terminal_archive::closed_host_prepared_request_id_data_v2(stored)
    }

    fn historical_endpoint_publication(
        &mut self,
        protocol: BrokerSessionProtocolV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        let process = match self.role {
            BrokerSessionDurableEndpointV1::Client => transcript.client_process(),
            BrokerSessionDurableEndpointV1::Broker => transcript.broker_process(),
        };
        Ok(self
            .manifest()?
            .binding()
            .endpoint_publication_data_v1(protocol, self.role, process))
    }

    fn schema_complete_scope_v3<T>(
        &mut self,
        scope: Option<SchemaScopeV3>,
        result: &Result<T, BrokerSessionSecurityError>,
    ) {
        StorageFloorSchemaOriginalV3::schema_complete_scope_v3(Some(self.original), scope, result)
    }

    fn schema_decode_stored_v3(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> Result<StoredProtocolHistoryV1, BrokerSessionSecurityError> {
        self.manifest()?;
        StorageFloorSchemaOriginalV3::schema_decode_stored_v3(Some(self.original), key, value)
    }

    fn schema_retain_entries_v3(
        &mut self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BrokerSessionSecurityError> {
        // The actual returned collection must enter its original even when a
        // previous comparison failed; no currentness refusal may discard it.
        StorageFloorSchemaOriginalV3::schema_retain_entries_v3(Some(self.original), entries, result)
    }

    fn schema_retain_ids_v3(
        &mut self,
        ids: Vec<[u8; 16]>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<[u8; 16]>, BrokerSessionSecurityError> {
        StorageFloorSchemaOriginalV3::schema_retain_ids_v3(Some(self.original), ids, result)
    }

    fn schema_retain_value_v3(
        &mut self,
        value: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, BrokerSessionSecurityError> {
        StorageFloorSchemaOriginalV3::schema_retain_value_v3(Some(self.original), value)
    }

    fn schema_scope_v3(&self) -> Option<SchemaScopeV3> {
        StorageFloorSchemaOriginalV3::schema_scope_v3(Some(self.original))
    }

    fn stable_endpoint_identity(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        Ok(self
            .manifest()?
            .binding()
            .stable_endpoint_identity_data_v2(protocol, self.role))
    }

    fn read_optional_schema(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        self.manifest()?;
        if self.original.traffic.len() == SLOTS {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut work = StoredReadOriginalsV1::new();
        let result = SessionSchemaReadV1 {
            context: InitialSessionSchemaContextV1 {
                main: self.main,
                provision: self.provision,
                original: self.original,
                role: self.role,
                node: self.node,
            },
        }
        .read_optional_schema_captured(protocol, &mut work, true);
        let selected = if result.is_ok() {
            work.schema_selected_clone_v3()
        } else {
            None
        };
        self.original.traffic.push(work);
        result.map(|_| selected)
    }

    fn historical_context(
        &mut self,
        archived: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        let manifest = self
            .provision
            .schema_manifest_for_main_v1(self.main)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        if self.original.contexts.len() == SLOTS {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.original
            .contexts
            .push(BrokerSessionManifestContextOriginalsV1::default());
        let capture = self
            .original
            .contexts
            .last_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        manifest
            .verification_context_retaining_v1(
                archived.boot_id(),
                archived.client_process(),
                archived.broker_process(),
                capture,
            )
            .map_err(Into::into)
    }
}

impl StorageFloorSchemaOriginalV3 {
    /// Runs the complete ordinary schema recipe on the same initial held main.
    ///
    /// # Errors
    /// Retains schema/codec failure, foreign or ended loans, allocation refusal
    /// and reentry. This DATA comparison grants no initial effect authority.
    pub(crate) fn validate_initial_captured_v1(
        &mut self,
        main: &Method46InitialMainReadbackLoanV1<'_>,
        provision: &Method46InitialProvisionDecodeOriginalV1<'_>,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.returned.is_some() {
            self.closed
                .get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let result = (|| {
            // Authenticate the payer association before reserving any slots.
            let role = provision
                .schema_endpoint_for_main_v1(main)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            let node = provision
                .schema_manifest_for_main_v1(main)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                .node_id();
            self.prepare()?;
            SessionSchemaReadV1 {
                context: InitialSessionSchemaContextV1 {
                    main,
                    provision,
                    original: self,
                    role,
                    node,
                },
            }
            .validate_all_schema_data_v1()?;
            provision
                .schema_manifest_for_main_v1(main)
                .map_err(|_| BrokerSessionSecurityError::Currentness)?;
            Ok(())
        })();
        self.returned = Some(result);
        match self.returned.as_ref() {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error.clone()),
            None => std::process::abort(),
        }
    }

    /// Reports a complete retained schema comparison without granting authority.
    pub(crate) fn initial_schema_completed_data_v1(&self) -> bool {
        self.attempted && matches!(self.returned, Some(Ok(()))) && self.failure().is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_manifest_context_stays_with_its_exact_negative_schema_scope() {
        let (manifest, _) =
            crate::test_signed_endpoint::manifest_and_secrets(BrokerSessionProtocolV1::Storage);
        let mut original = StorageFloorSchemaOriginalV3::new();
        original.prepare().unwrap();
        let scope = StorageFloorSchemaOriginalV3::schema_scope_v3(Some(&original));
        original
            .contexts
            .push(BrokerSessionManifestContextOriginalsV1::default());
        let result = manifest.verification_context_retaining_v1(
            [0; 16],
            [2; 16],
            [3; 16],
            &mut original.contexts[0],
        );
        assert!(result.is_err());
        let first = original.failure().unwrap() as *const dyn std::error::Error;
        let refused = Err::<(), _>(BrokerSessionSecurityError::Currentness);

        StorageFloorSchemaOriginalV3::schema_complete_scope_v3(
            Some(&mut original),
            scope,
            &refused,
        );
        assert!(original.prepare().is_err());

        assert_eq!(original.contexts.len(), 1);
        assert!(std::ptr::eq(
            first,
            original.failure().unwrap() as *const dyn std::error::Error
        ));
        assert!(!original.initial_schema_completed_data_v1());
    }

    #[test]
    fn completed_context_comparison_retires_only_its_successful_pure_scope() {
        let (manifest, _) =
            crate::test_signed_endpoint::manifest_and_secrets(BrokerSessionProtocolV1::Storage);
        let mut original = StorageFloorSchemaOriginalV3::new();
        original.prepare().unwrap();
        let scope = StorageFloorSchemaOriginalV3::schema_scope_v3(Some(&original));
        original
            .contexts
            .push(BrokerSessionManifestContextOriginalsV1::default());
        let context = manifest
            .verification_context_retaining_v1([1; 16], [2; 16], [3; 16], &mut original.contexts[0])
            .unwrap();
        let expected = manifest
            .verification_context([1; 16], [2; 16], [3; 16])
            .unwrap();
        assert_eq!(context, expected);
        let compared = Ok::<_, BrokerSessionSecurityError>(());

        StorageFloorSchemaOriginalV3::schema_complete_scope_v3(
            Some(&mut original),
            scope,
            &compared,
        );

        assert!(original.contexts.is_empty());
        assert!(original.failure().is_none());
        // A complete pure subcomparison cannot create a whole initial result.
        assert!(!original.initial_schema_completed_data_v1());
    }
}
