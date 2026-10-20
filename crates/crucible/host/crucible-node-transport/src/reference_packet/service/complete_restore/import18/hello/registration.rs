//! Retains actual registration authority checks and the borrowed wire view.
//!
//! Planned grammar, prospective projection and hash DATA share one lower body.

use super::*;
use crate::handshake::{ConnectionAuthority, Limits};
use crate::retained_metadata::serialization_storage::{OriginalSerializationStorageProjection as Projection, original_serialization_counter_scratch_data};
use serde::Serialize;
use serde_json::Value;
use crucible_source_birth_data::profile::reference_packet::service::complete_restore::import18::hello::registration as shared_registration;
pub use shared_registration::PacketNativeImport18RegistrationSideData;

/// Retains the original upper prospective DATA API without authority conversion.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct PacketNativeImport18ProspectiveHostRegistrationData {
    data: shared_registration::PacketNativeImport18ProspectiveHostRegistrationData,
}

impl PacketNativeImport18ProspectiveHostRegistrationData {
    /// Returns the retained complete-plan identity as inert comparison DATA.
    ///
    /// This observes the same immutable lower projection and supplies no grant.
    pub const fn planned_identity_data(&self) -> [u8; 32] {
        self.data.planned_identity_data()
    }

    /// Returns the same defining prospective array10 encoded extent.
    pub const fn maximum_encoded_bytes_data(&self) -> usize {
        self.data.maximum_encoded_bytes_data()
    }

    /// Checks the same complete original planned object and immutable declaration.
    ///
    /// # Errors
    /// Preserves the original field, target, roster and identity refusals.
    pub fn authenticate_planned_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        declaration: &PacketNativeImport18HelloDeclarationData,
        planned: &Value,
    ) -> Result<(), ProviderError> {
        self.data
            .authenticate_planned_data(launch, &declaration.data, planned)
    }

    /// Checks the same planned object from inert borrowed launch fields.
    ///
    /// # Errors
    /// Preserves the original field, target, roster and identity refusals.
    pub fn authenticate_planned_from_fields_data(
        &self,
        fields: &PacketNative5LaunchValidationFields<'_>,
        declaration: &PacketNativeImport18HelloDeclarationData,
        planned: &Value,
    ) -> Result<(), ProviderError> {
        self.data
            .authenticate_planned_from_fields_data(fields, &declaration.data, planned)
    }
}

/// Projects the original historical grammar from the same complete plan.
///
/// # Errors
/// Preserves the original grammar, target, projection and maximum refusals.
pub fn native_import18_prospective_host_registration_data(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
    maximum: usize,
) -> Result<PacketNativeImport18ProspectiveHostRegistrationData, ProviderError> {
    shared_registration::native_import18_prospective_host_registration_data(
        launch,
        &declaration.data,
        planned,
        maximum,
    )
    .map(|data| PacketNativeImport18ProspectiveHostRegistrationData { data })
}

/// Projects the original historical grammar from immutable launch fields.
///
/// # Errors
/// Preserves the original grammar, target, projection and maximum refusals.
pub fn native_import18_prospective_host_registration_from_fields_data(
    fields: &PacketNative5LaunchValidationFields<'_>,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
    maximum: usize,
) -> Result<PacketNativeImport18ProspectiveHostRegistrationData, ProviderError> {
    shared_registration::native_import18_prospective_host_registration_from_fields_data(
        fields,
        &declaration.data,
        planned,
        maximum,
    )
    .map(|data| PacketNativeImport18ProspectiveHostRegistrationData { data })
}

use shared_registration::{BACKING_MARKER, HISTORICAL_SCHEMA, PLANNED_SCHEMA};
use shared_registration::{sorted_strings_data as sorted_strings, text_data as text};

fn authenticate_plan(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
) -> Result<(), ProviderError> {
    shared_registration::authenticate_plan_data(launch, &declaration.data, planned)
}

/// Compares the same complete plan with an independently guarded actual authority.
///
/// Every selected feature/key/typed extension and receiving coordinate is
/// checked; the native role first proves its own defining connection Id before
/// projecting the peer's controller role. Kernel/Hello/Source/Connection custody
/// remains the private caller's independent conjunction. Success is DATA only.
///
/// # Errors
/// Refuses stale authority, a different target/plan, unknown feature/key, nonempty
/// typed extensions, changed limits or another actual role's connection Id.
pub fn authenticate_native_import18_current_host_registration_data(
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
    planned: &Value,
    authority: &ConnectionAuthority,
    side: PacketNativeImport18RegistrationSideData,
) -> Result<(), ProviderError> {
    authenticate_plan(launch, declaration, planned)?;
    declaration.authenticate_authority_data(authority)?;
    let [binding] = launch.selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    if authority.session_id() != &binding.authority.session_id
        || authority.incarnation_id() != &binding.authority.incarnation_id
        || authority.limits() != launch.limits
        || authority
            .selected_extensions()
            .is_none_or(|extensions| !extensions.is_empty())
    {
        return Err(refused());
    }
    let expected = match side {
        PacketNativeImport18RegistrationSideData::Controller => text(planned, "connection_id")?,
        PacketNativeImport18RegistrationSideData::Native => NATIVE_IMPORT18_CONNECTION_ID,
    };
    if authority.connection_id().as_str() != expected {
        return Err(refused());
    }
    authority.ensure_live()
}

#[derive(Serialize)]
struct Registration<'a> {
    schema: &'static str,
    role: &'static str,
    connection_id: &'a Id,
    session_id: &'a Id,
    incarnation_id: &'a Id,
    limits: Limits,
    features: &'a IdSet,
    extensions: &'a [crucible_node_format::ExtensionSelection],
    envelope_extensions: &'a std::collections::BTreeSet<String>,
}

/// Borrows the complete current registration9 DATA without copying its children.
///
/// The actual issuer first proves its same Connection/Hello/Source and role.
/// The Host connection Id is independently obtained from the retained original
/// plan; the native-role normalization does not create that Host authority.
///
/// # Errors
/// Refuses revoked authority or an absent actual typed extension registration.
pub fn native_import18_current_registration_wire_data<'a>(
    authority: &'a ConnectionAuthority,
    controller_connection_id: Option<&'a Id>,
) -> Result<impl Serialize + 'a, ProviderError> {
    authority.ensure_live()?;
    Ok(Registration {
        schema: PLANNED_SCHEMA,
        role: if controller_connection_id.is_some() {
            "controller"
        } else {
            "native"
        },
        connection_id: controller_connection_id.unwrap_or(authority.connection_id()),
        session_id: authority.session_id(),
        incarnation_id: authority.incarnation_id(),
        limits: authority.limits(),
        features: authority.selected_features(),
        extensions: authority.selected_extensions().ok_or_else(refused)?,
        envelope_extensions: authority.envelope_extensions(),
    })
}

/// Names actual authority/wire views and immutable adapter result controls.
pub fn native_import18_registration_counter_scratch_data() -> usize {
    shared_registration::native_import18_registration_counter_scratch_data()
        + size_of::<Registration<'static>>()
        + size_of::<&ConnectionAuthority>()
        + size_of::<Result<Registration<'static>, ProviderError>>()
        + size_of::<&PacketNativeImport18HelloDeclarationData>()
        + size_of::<&shared::PacketNativeImport18HelloDeclarationData>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<PacketNativeImport18ProspectiveHostRegistrationData>()
        + size_of::<shared_registration::PacketNativeImport18ProspectiveHostRegistrationData>()
        + size_of::<Result<PacketNativeImport18ProspectiveHostRegistrationData, ProviderError>>()
        + size_of::<
            Result<
                shared_registration::PacketNativeImport18ProspectiveHostRegistrationData,
                ProviderError,
            >,
        >()
        + size_of::<&PacketNativeImport18ProspectiveHostRegistrationData>()
        + size_of::<&shared_registration::PacketNativeImport18ProspectiveHostRegistrationData>()
        + PacketNativeImport18HelloDeclarationData::wrapper_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_strings_refuse_duplicates_nonstrings_and_reordered_keys() {
        sorted_strings(&[Value::String("a".into()), Value::String("b".into())]).unwrap();
        assert!(sorted_strings(&[Value::String("a".into()), Value::String("a".into())]).is_err());
        assert!(sorted_strings(&[Value::String("b".into()), Value::String("a".into())]).is_err());
        assert!(sorted_strings(&[Value::Null]).is_err());
    }

    #[test]
    fn actual_historical_schema_eleven_is_the_defining_array_of_ten_fields() {
        let (_handshake, authority, _, _) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        let historical = serde_json::to_value(authority.historical_owned_view()).unwrap();
        let fields = historical.as_array().unwrap();
        assert_eq!(fields.len(), 10);
        assert_eq!(fields[0], HISTORICAL_SCHEMA);
        assert_eq!(fields[9], BACKING_MARKER);
        assert_eq!(fields[1], authority.connection_id().as_str());
        assert_eq!(fields[2], authority.session_id().as_str());
        assert_eq!(fields[3], authority.incarnation_id().as_str());
        assert!(fields[4].as_str().unwrap().parse::<u64>().is_ok());
    }
}

/// Projects the same immutable native registration fields before Birth.
pub(super) fn prospective_native_registration_projection_data(
    out: &mut Projection,
    launch: &PacketNative5SourceLaunch,
    declaration: &PacketNativeImport18HelloDeclarationData,
) -> Result<(), ProviderError> {
    shared_registration::prospective_native_registration_projection_data(
        out,
        launch,
        &declaration.data,
    )
}

// A changed private serializer field roster must also update the prospective
// producer. This witness constructs neither registration DATA nor authority.
const _: fn(&Registration<'static>) = |value| {
    let Registration {
        schema: _,
        role: _,
        connection_id: _,
        session_id: _,
        incarnation_id: _,
        limits: _,
        features: _,
        extensions: _,
        envelope_extensions: _,
    } = value;
};

#[cfg(test)]
#[path = "registration/fields_tests.rs"]
mod fields_tests;
