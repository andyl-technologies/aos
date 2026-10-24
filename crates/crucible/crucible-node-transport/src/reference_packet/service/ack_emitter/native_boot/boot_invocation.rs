//! Constructs boot7 only after its actual inherited invocation claim is spent.

use super::super::bootstrap::admitted::OriginalNativeStartupBootstrap;
use super::*;
use crate::reference_packet::service::native_startup::{
    PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA, PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA,
    PacketNativeInvocationPurposeData,
};
use crate::retained_metadata::serialization_storage::OriginalJsonValueStorageExtentData;

/// Counts additional invocation attempt/helper views beside the original window.
///
/// These coexist with the complete original14 constructor window. Purpose DATA
/// never supplies native currency.
pub(super) const fn attempt_counter_scratch_data() -> usize {
    2 * size_of::<&serde_json::Value>()
        + 2 * size_of::<&PacketNative5SourceLaunch>()
        + 2 * size_of::<PacketNativeInvocationPurposeData>()
        + 2 * size_of::<&mut OriginalNativeStartupBootstrap>()
        + size_of::<&mut Option<OriginalNativeStartupBootAttempt>>()
        + size_of::<&mut OriginalNativeStartupBootAttempt>()
        + 2 * size_of::<&mut Option<Rc<RefCell<NativeAckBoot>>>>()
        + size_of::<Rc<RefCell<NativeAckBoot>>>()
        + size_of::<&mut Vec<u8>>()
        + 2 * size_of::<Vec<u8>>()
        + 2 * size_of::<Result<(), ProviderError>>()
        + 2 * size_of::<bool>()
        // Keep the earlier decoded-child loan windows conservative. No shared
        // boot exists before the independent native row authenticates.
        + size_of::<&BootData>()
        + size_of::<Option<&BootData>>()
        + size_of::<Result<&BootData, ProviderError>>()
        + private_boot_parser_counter_scratch_data()
}

// The raw extent projector and exhaustive launch observer retain their original
// windows. These are the new caller, checked-sum and refusal-control views.
const fn private_boot_parser_counter_scratch_data() -> usize {
    2 * size_of::<&mut OriginalNativeStartupBootstrap>()
        + 2 * size_of::<&OriginalNativeStartupBootstrap>()
        + 3 * size_of::<&PacketNative5SourceLaunch>()
        + size_of::<Option<&mut OriginalNativeStartupBootstrap>>()
        + 2 * size_of::<OriginalJsonValueStorageExtentData>()
        + size_of::<Result<OriginalJsonValueStorageExtentData, ProviderError>>()
        + 5 * size_of::<usize>()
        + size_of::<u64>()
        + 2 * size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
        + size_of::<Result<u64, ProviderError>>()
        + 4 * size_of::<Result<(), ProviderError>>()
        + 4 * size_of::<bool>()
}

impl NativeAckBoot {
    /// Borrows the original invocation's authenticated Hello registration.
    ///
    /// The private birth and both retained body digests remain independent of
    /// the public Hello request. Birth admission separately checked this
    /// immutable registration's digest before marking the original ready.
    /// Other boot editions keep their existing plan.
    ///
    /// # Errors
    /// Refuses another creator or a changed, incomplete invocation birth.
    pub(crate) fn original_invocation_hello_registration_data(
        &self,
    ) -> Result<Option<&serde_json::Value>, ProviderError> {
        self.ensure_origin()?;
        if self.data.schema != PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            return Ok(None);
        }
        self.authenticate_original_invocation_body_data()?;
        Ok(Some(&self.data.expected_host_registration))
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn prepare_original_invocation_into(
        value: OriginalNativeBootValue<'_>,
        launch: &PacketNative5SourceLaunch,
        original_launch_body: Vec<u8>,
        purpose: PacketNativeInvocationPurposeData,
        startup: &mut OriginalNativeStartupBootstrap,
        attempt: &mut Option<OriginalNativeStartupBootAttempt>,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), ProviderError> {
        if completed.is_some() || attempt.is_some() {
            return Err(ProviderError::Conflict(
                "native invocation boot already attempted",
            ));
        }
        let retained = attempt.insert(OriginalNativeStartupBootAttempt {
            launch_body: original_launch_body,
            scalars: None,
            data: None,
        });
        let result = Self::prepare_original_invocation_attempt_data(
            value, launch, purpose, startup, retained, completed,
        );

        // The native owner takes both children together. Earlier refusals keep
        // the inline attempt, and neither path can renew the inherited claim.
        if completed.is_some() {
            *attempt = None;
        }
        if result.is_err() {
            startup.failed = true;
        }
        result
    }

    fn prepare_original_invocation_attempt_data(
        value: OriginalNativeBootValue<'_>,
        launch: &PacketNative5SourceLaunch,
        purpose: PacketNativeInvocationPurposeData,
        startup: &mut OriginalNativeStartupBootstrap,
        attempt: &mut OriginalNativeStartupBootAttempt,
        completed: &mut Option<Rc<RefCell<Self>>>,
    ) -> Result<(), ProviderError> {
        startup.ensure_original()?;
        crate::connection::serialized_credit(value.value, startup.maximum_boot_bytes)?;
        let shape = shape::inspect_data(value.value)?;
        attempt.scalars = Some(shape.copy_scalars_data()?);
        let scalars = attempt.scalars.as_ref().ok_or(ProviderError::Correlation(
            "native invocation decoded scalars absent",
        ))?;
        if scalars.schema != PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            return Err(ProviderError::Correlation(
                "native invocation private boot class",
            ));
        }
        scalars.authenticate_native_grammar_data(
            launch,
            PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA,
        )?;
        let admitted = startup.claim_invocation_birth_data(
            shape.claim_inputs_data(launch, &attempt.launch_body, value.body, scalars),
            &purpose,
        )?;
        let scalars = attempt.scalars.take().ok_or(ProviderError::Correlation(
            "native invocation decoded scalars transferred",
        ))?;
        // Keep scalar refusal custody separate from native-funded child copies.
        attempt.data = Some(shape.copy_children_data(scalars));
        let data = attempt.data.take().ok_or(ProviderError::Correlation(
            "native invocation decoded boot transferred",
        ))?;
        Self::prepare_data_into(
            data,
            launch,
            std::mem::take(&mut attempt.launch_body),
            Some(admitted),
            Some(purpose),
            completed,
        )
    }

    // A private, already constructed boot selects the decoder. A decoded schema
    // label or a caller's purpose cannot switch an ordinary/boot6 owner.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn decode_original_launch_data(
        &self,
    ) -> Result<PacketNative5SourceLaunch, ProviderError> {
        self.ensure_origin()?;
        if self.data.schema != PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            return PacketNative5SourceLaunch::decode(&self.launch_body, 1024 * 1024);
        }
        let original = self.startup.as_ref().ok_or(ProviderError::Correlation(
            "native invocation origin absent",
        ))?;
        if !original.native_birth_issued
            || self
                .data
                .source_birth
                .get("schema")
                .and_then(serde_json::Value::as_str)
                != Some(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA)
            || self.data.birth_id.as_slice() != original.birth_id
            || blake3::hash(&self.launch_body).as_bytes() != &original.launch_digest
        {
            return Err(ProviderError::Correlation(
                "native invocation retained origin differs",
            ));
        }
        let value = canonical::parse_json(&self.launch_body, 1024 * 1024)?;
        let fields = value.as_object().ok_or(ProviderError::Correlation(
            "native invocation launch object",
        ))?;
        if fields.len() != 3
            || fields
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                != Some(6)
        {
            return Err(ProviderError::Correlation(
                "native invocation launch closed class",
            ));
        }
        let purpose = PacketNativeInvocationPurposeData::from_original_value_data(
            fields.get("invocation").ok_or(ProviderError::Correlation(
                "native invocation launch purpose",
            ))?,
        )?;
        if purpose
            != PacketNativeInvocationPurposeData::from_original_value_data(
                self.data
                    .source_birth
                    .get("invocation")
                    .ok_or(ProviderError::Correlation(
                        "native invocation Source purpose",
                    ))?,
            )?
        {
            return Err(ProviderError::Correlation(
                "native invocation retained purpose differs",
            ));
        }
        let launch = PacketNative5SourceLaunch::deserialize(fields.get("launch").ok_or(
            ProviderError::Correlation("native invocation nested launch"),
        )?)
        .map_err(ContractError::from)?;
        launch.validate()?;
        purpose.authenticate_target_data(&launch)?;
        Ok(launch)
    }
}

impl NativeAckBoot {
    // This raw origin/data guard admits only the already claimed constructor's
    // first baseline requests. It grants no Query, Prepare, Capture or Arm scope.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_original_invocation_birth_data(
        &self,
    ) -> Result<PacketNativeInvocationPurposeData, ProviderError> {
        let purpose = self.authenticate_original_invocation_body_data()?;
        PacketNativeInvocationPurposeData::from_original_value_data(purpose)
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_original_invocation_baseline_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_invocation_body_data()?;
        if !self.verified
            || self
                .startup
                .as_ref()
                .is_none_or(|original| !original.baseline_complete)
        {
            return Err(ProviderError::Correlation(
                "native invocation baseline incomplete",
            ));
        }
        Ok(())
    }
}

impl NativeAckBoot {
    fn authenticate_original_invocation_body_data(
        &self,
    ) -> Result<&serde_json::Value, ProviderError> {
        self.ensure_origin()?;
        let original = self.startup.as_ref().ok_or(ProviderError::Correlation(
            "native invocation origin absent",
        ))?;
        if !self.ready
            || !original.native_birth_issued
            || self.data.schema != PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA
            || self
                .data
                .source_birth
                .as_object()
                .is_none_or(|fields| fields.len() != 19)
            || self
                .data
                .source_birth
                .get("schema")
                .and_then(serde_json::Value::as_str)
                != Some(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA)
            || self.data.birth_id.as_slice() != original.birth_id
            || blake3::hash(&self.launch_body).as_bytes() != &original.launch_digest
            || blake3::hash(&self.source_body).as_bytes() != &original.source_digest
        {
            return Err(ProviderError::Correlation(
                "native invocation retained baseline differs",
            ));
        }
        self.data
            .source_birth
            .get("invocation")
            .ok_or(ProviderError::Correlation(
                "native invocation retained purpose absent",
            ))
    }

    // This is the actual private, immutable birth's provenance. No public DATA
    // or enum can set ready/issued, and every identity was compared before ready.
    // The existing token/report scopes still enforce current Connection currency.
    /// Selects the original route only from this genuine immutable private birth.
    ///
    /// # Errors
    /// Refuses a foreign, unfinished or changed invocation origin or tag.
    pub(crate) fn permits_original_invocation_without_fresh_query_data(
        &self,
    ) -> Result<bool, ProviderError> {
        self.ensure_origin()?;
        if self.data.schema != PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            return Ok(false); // Legacy dispatcher remains unchanged; no new purpose inferred.
        }
        let purpose = self.authenticate_original_invocation_body_data()?;
        original_execution_tag(purpose)
    }

    /// Checks the report role against the completed original private purpose.
    ///
    /// # Errors
    /// Refuses unfinished baseline, changed origin or the opposite report role.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_original_invocation_report_purpose_data(
        &self,
        purpose: crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_invocation_baseline_data()?;
        let original = self.permits_original_invocation_without_fresh_query_data()?;
        match purpose {
            crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose::OriginalObserve12 if original => Ok(()),
            crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose::FreshCompletedAdmit13 if !original => Ok(()),
            _ => Err(ProviderError::Correlation("native invocation report purpose differs")),
        }
    }

    /// Requires the genuine completed restoration-target baseline for Prepare.
    ///
    /// # Errors
    /// Refuses an original-execution purpose or any missing baseline identity.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn authenticate_original_invocation_prepare_target_data(
        &self,
    ) -> Result<(), ProviderError> {
        self.authenticate_original_invocation_baseline_data()?;
        if self.permits_original_invocation_without_fresh_query_data()? {
            return Err(ProviderError::Correlation(
                "original invocation cannot acquire fresh Prepare",
            ));
        }
        Ok(())
    }

    // The private launch bank is immutable. verify_admit fully validated this
    // same wrapper before verified became true; Prepare reuses only its exact
    // nested original, with no additional owned bank or repeated schema build.
    /// Borrows the exact verified launch5 span without reconstructing its bank.
    ///
    /// # Errors
    /// Refuses foreign or unfinished invocation, wrong purpose or wrapper syntax.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn original_verified_launch_literal_data(
        &self,
    ) -> Result<&[u8], ProviderError> {
        self.ensure_origin()?;
        if self.data.schema != PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA {
            return Ok(&self.launch_body);
        }
        self.authenticate_original_invocation_prepare_target_data()?;
        let mut fields =
            crate::protocol_snapshot::owned11::OriginalOwned11Fields::object(&self.launch_body)?;
        fields.named("invocation")?;
        let original = fields.named("launch")?;
        if fields.named("schema_version")? != b"6" {
            return Err(ProviderError::Correlation(
                "native invocation launch version",
            ));
        }
        fields.finish()?;
        Ok(original)
    }
}

// This tests only an already authenticated immutable purpose's discriminator.
// It cannot issue a private origin, scope or permission from a decoded Value.
fn original_execution_tag(purpose: &serde_json::Value) -> Result<bool, ProviderError> {
    match purpose.get("purpose").and_then(serde_json::Value::as_str) {
        Some("original_execution")
            if purpose
                .get("source")
                .is_some_and(serde_json::Value::is_null) =>
        {
            Ok(true)
        }
        Some("restoration_target")
            if purpose
                .get("source")
                .is_some_and(serde_json::Value::is_object) =>
        {
            Ok(false)
        }
        _ => Err(ProviderError::Correlation(
            "native invocation purpose unavailable",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_typed_boot_refusal_preserves_original_payload_without_startup_authority() {
        let mut output = None;
        let data = BootData {
            schema: PACKET_NATIVE_INVOCATION_PRIVATE_BOOT_SCHEMA.into(),
            private_key: Bytes::new(vec![0; 32]),
            birth_id: Bytes::new(vec![1; 32]),
            source_birth: serde_json::json!({"incomplete":"original payload"}),
            expected_host_registration: serde_json::json!({"incomplete":"host payload"}),
            private_launch: Id::new("private-launch").unwrap(),
            host_executable: canonical::content_ref(b"inert", "application/test").unwrap(),
        };
        let source_pointer = data.source_birth["incomplete"].as_str().unwrap().as_ptr();
        let original =
            NativeAckBoot::retain_boot_data_into(data, b"incomplete".to_vec(), None, &mut output);
        assert!(Rc::ptr_eq(&original, output.as_ref().unwrap()));
        {
            let owner = original.borrow();
            assert!(owner.authenticate_original_invocation_birth_data().is_err());
            assert!(
                owner
                    .permits_original_invocation_without_fresh_query_data()
                    .is_err()
            );
            assert!(
                owner
                    .authenticate_original_invocation_prepare_target_data()
                    .is_err()
            );
            assert!(owner.authenticate_original_invocation_report_purpose_data(
                crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
            ).is_err());
            assert_eq!(
                owner.data.source_birth["incomplete"]
                    .as_str()
                    .unwrap()
                    .as_ptr(),
                source_pointer
            );
            assert_eq!(owner.data.source_birth["incomplete"], "original payload");
            assert!(!owner.ready);
            assert!(!owner.verified);
            assert!(owner.startup.is_none());
        }
        assert!(output.is_some());
    }

    #[test]
    fn discriminator_data_never_treats_absence_or_opposite_source_shape_as_original() {
        let original = serde_json::json!({"purpose":"original_execution","source":null});
        let target = serde_json::json!({"purpose":"restoration_target","source":{"inert":"data"}});
        assert!(original_execution_tag(&original).unwrap());
        assert!(!original_execution_tag(&target).unwrap());
        for changed in [
            serde_json::json!({}),
            serde_json::json!({"purpose":"original_execution"}),
            serde_json::json!({"purpose":"original_execution","source":{}}),
            serde_json::json!({"purpose":"restoration_target","source":null}),
            serde_json::json!({"purpose":"unknown","source":null}),
            serde_json::json!({"purpose":true,"source":null}),
        ] {
            assert!(original_execution_tag(&changed).is_err());
        }
    }
}

#[cfg(test)]
#[path = "boot_invocation_attempt_tests.rs"]
mod attempt_tests;
