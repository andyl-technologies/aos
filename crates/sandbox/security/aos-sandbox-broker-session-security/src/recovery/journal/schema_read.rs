//! Shares the complete read-only Session schema recipe across held read contexts.
//!
//! The native adapter keeps the original Journal namespace claim and endpoint
//! revalidation bookends. Context hooks supply reads and retain actual failed
//! prefixes; this engine neither constructs nor exports a writer or floor token.

use super::storage_floor_schema::{SchemaAuthorityV3, SchemaScopeV3};
use super::*;

/// Borrows the actual namespace read guard without exposing its native authority.
pub(super) struct SchemaReadDataV1<'a> {
    native: SchemaAuthorityV3<'a>,
}

impl SchemaReadDataV1<'_> {
    pub(super) fn get(&mut self, key: &[u8]) -> Result<Option<&[u8]>, BrokerSessionSecurityError> {
        self.native.get(key)
    }

    pub(super) fn records(
        &mut self,
    ) -> Result<impl Iterator<Item = (&[u8], &[u8])>, BrokerSessionSecurityError> {
        self.native.records()
    }
}

/// Supplies original read observations and passive failure destinations.
pub(super) trait SessionSchemaContextV1 {
    fn read_data(&mut self) -> Result<SchemaReadDataV1<'_>, BrokerSessionSecurityError>;
    fn endpoint_role(&self) -> BrokerSessionDurableEndpointV1;
    fn protocol_and_node(&self) -> (BrokerSessionProtocolV1, [u8; 16]);
    fn purpose(&self) -> SessionPurpose;
    #[cfg(feature = "online-nix")]
    fn online_seed_data(&self) -> Option<([u8; 24], [u8; 640])>;
    fn closed_host_prepared_request_id_v2(
        &self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<Option<[u8; 16]>, BrokerSessionSecurityError>;

    fn historical_endpoint_publication(
        &mut self,
        protocol: BrokerSessionProtocolV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError>;

    fn schema_complete_scope_v3<T>(
        &mut self,
        scope: Option<SchemaScopeV3>,
        result: &Result<T, BrokerSessionSecurityError>,
    );

    fn schema_decode_stored_v3(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> Result<StoredProtocolHistoryV1, BrokerSessionSecurityError>;

    fn schema_retain_entries_v3(
        &mut self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BrokerSessionSecurityError>;

    fn schema_retain_ids_v3(
        &mut self,
        ids: Vec<[u8; 16]>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<[u8; 16]>, BrokerSessionSecurityError>;

    fn schema_retain_value_v3(
        &mut self,
        value: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, BrokerSessionSecurityError>;

    fn schema_scope_v3(&self) -> Option<SchemaScopeV3>;

    fn stable_endpoint_identity(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError>;

    fn read_optional_schema(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError>;

    fn historical_context(
        &mut self,
        archived: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError>;
}

/// Borrows the existing owner; every native hook retains its previous ordering.
pub(super) struct NativeSessionSchemaContextV1<'a> {
    journal: &'a mut ProtectedBrokerSessionJournalV1,
}

impl SessionSchemaContextV1 for NativeSessionSchemaContextV1<'_> {
    fn read_data(&mut self) -> Result<SchemaReadDataV1<'_>, BrokerSessionSecurityError> {
        self.journal
            .schema_authority_v3()
            .map(|native| SchemaReadDataV1 { native })
    }

    fn endpoint_role(&self) -> BrokerSessionDurableEndpointV1 {
        self.journal.endpoint.role()
    }

    fn protocol_and_node(&self) -> (BrokerSessionProtocolV1, [u8; 16]) {
        self.journal.endpoint.protected_protocol_and_node()
    }

    fn purpose(&self) -> SessionPurpose {
        self.journal.purpose
    }

    #[cfg(feature = "online-nix")]
    fn online_seed_data(&self) -> Option<([u8; 24], [u8; 640])> {
        self.journal
            .online_schema
            .as_ref()
            .map(|schema| (schema.key, schema.seed))
    }

    fn closed_host_prepared_request_id_v2(
        &self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<Option<[u8; 16]>, BrokerSessionSecurityError> {
        self.journal.closed_host_prepared_request_id_v2(stored)
    }

    fn historical_endpoint_publication(
        &mut self,
        protocol: BrokerSessionProtocolV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.journal
            .historical_endpoint_publication(protocol, transcript)
    }

    fn schema_complete_scope_v3<T>(
        &mut self,
        scope: Option<SchemaScopeV3>,
        result: &Result<T, BrokerSessionSecurityError>,
    ) {
        self.journal.schema_complete_scope_v3(scope, result)
    }

    fn schema_decode_stored_v3(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> Result<StoredProtocolHistoryV1, BrokerSessionSecurityError> {
        self.journal.schema_decode_stored_v3(key, value)
    }

    fn schema_retain_entries_v3(
        &mut self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BrokerSessionSecurityError> {
        self.journal.schema_retain_entries_v3(entries, result)
    }

    fn schema_retain_ids_v3(
        &mut self,
        ids: Vec<[u8; 16]>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<[u8; 16]>, BrokerSessionSecurityError> {
        self.journal.schema_retain_ids_v3(ids, result)
    }

    fn schema_retain_value_v3(
        &mut self,
        value: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, BrokerSessionSecurityError> {
        self.journal.schema_retain_value_v3(value)
    }

    fn schema_scope_v3(&self) -> Option<SchemaScopeV3> {
        self.journal.schema_scope_v3()
    }

    fn stable_endpoint_identity(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.journal.stable_endpoint_identity(protocol)
    }

    fn read_optional_schema(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        self.journal.read_optional_schema(protocol)
    }

    fn historical_context(
        &mut self,
        archived: &ProtectedBrokerSessionVerificationContextV1,
    ) -> Result<ProtectedBrokerSessionVerificationContextV1, BrokerSessionSecurityError> {
        self.journal.endpoint.historical_context(archived)
    }
}

/// Runs one schema recipe using the actual borrowed read context.
pub(super) struct SessionSchemaReadV1<C> {
    pub(super) context: C,
}

impl<C: SessionSchemaContextV1> SessionSchemaReadV1<C> {
    pub(super) fn schema_authority_v3(
        &mut self,
    ) -> Result<SchemaReadDataV1<'_>, BrokerSessionSecurityError> {
        self.context.read_data()
    }

    pub(super) fn closed_host_prepared_request_id_v2(
        &self,
        stored: &StoredProtocolHistoryV1,
    ) -> Result<Option<[u8; 16]>, BrokerSessionSecurityError> {
        self.context.closed_host_prepared_request_id_v2(stored)
    }

    pub(super) fn historical_endpoint_publication(
        &mut self,
        protocol: BrokerSessionProtocolV1,
        transcript: &VerifiedBrokerSessionTranscriptV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.context
            .historical_endpoint_publication(protocol, transcript)
    }

    pub(super) fn schema_complete_scope_v3<T>(
        &mut self,
        scope: Option<SchemaScopeV3>,
        result: &Result<T, BrokerSessionSecurityError>,
    ) {
        self.context.schema_complete_scope_v3(scope, result)
    }

    pub(super) fn schema_decode_stored_v3(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> Result<StoredProtocolHistoryV1, BrokerSessionSecurityError> {
        self.context.schema_decode_stored_v3(key, value)
    }

    pub(super) fn schema_retain_entries_v3(
        &mut self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BrokerSessionSecurityError> {
        self.context.schema_retain_entries_v3(entries, result)
    }

    pub(super) fn schema_retain_ids_v3(
        &mut self,
        ids: Vec<[u8; 16]>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<[u8; 16]>, BrokerSessionSecurityError> {
        self.context.schema_retain_ids_v3(ids, result)
    }

    pub(super) fn schema_retain_value_v3(
        &mut self,
        value: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, BrokerSessionSecurityError> {
        self.context.schema_retain_value_v3(value)
    }

    pub(super) fn schema_scope_v3(&self) -> Option<SchemaScopeV3> {
        self.context.schema_scope_v3()
    }

    pub(super) fn stable_endpoint_identity(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<[u8; 32], BrokerSessionSecurityError> {
        self.context.stable_endpoint_identity(protocol)
    }

    pub(super) fn validate_all_schema_data_v1(&mut self) -> Result<(), BrokerSessionSecurityError> {
        for protocol in [
            BrokerSessionProtocolV1::Host,
            BrokerSessionProtocolV1::Storage,
            BrokerSessionProtocolV1::Mount,
            BrokerSessionProtocolV1::Network,
            BrokerSessionProtocolV1::MountFuse,
            BrokerSessionProtocolV1::Nix,
        ] {
            let _ = self.context.read_optional_schema(protocol)?;
        }
        self.validate_host_argument_archives()?;
        self.validate_host_terminal_archives()?;
        self.validate_storage_group_archives()?;
        self.validate_storage_inventory_archives()?;
        self.validate_storage_inventory_abandonments()?;
        self.validate_operator_repair_inventory_archives()?;
        Ok(())
    }
}

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn schema_read_engine_v1(
        &mut self,
    ) -> SessionSchemaReadV1<NativeSessionSchemaContextV1<'_>> {
        SessionSchemaReadV1 {
            context: NativeSessionSchemaContextV1 { journal: self },
        }
    }
}

/// Narrows archive decoding to its canonical codec and passive retention hook.
pub(super) trait SchemaStoredDecodeV1 {
    fn schema_decode_stored_v3(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> Result<StoredProtocolHistoryV1, BrokerSessionSecurityError>;
}

impl SchemaStoredDecodeV1 for ProtectedBrokerSessionJournalV1 {
    fn schema_decode_stored_v3(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> Result<StoredProtocolHistoryV1, BrokerSessionSecurityError> {
        ProtectedBrokerSessionJournalV1::schema_decode_stored_v3(self, key, value)
    }
}

impl<C: SessionSchemaContextV1> SchemaStoredDecodeV1 for SessionSchemaReadV1<C> {
    fn schema_decode_stored_v3(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> Result<StoredProtocolHistoryV1, BrokerSessionSecurityError> {
        self.context.schema_decode_stored_v3(key, value)
    }
}
