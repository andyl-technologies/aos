//! Retains the strict version-six private launch before validation callbacks.
//!
//! ```json
//! {"schema_version":6,"invocation":{},"launch":{"schema_version":5}}
//! ```
//!
//! The nested launch remains the unchanged complete native-five declaration.
//! Invocation DATA does not alter model configuration, world, formats or live
//! authority, and cannot select the actual native constructor by itself.

use super::super::PacketNative5SourceLaunch;
use super::invocation::PacketNativeInvocationPurposeData;
use crate::ProviderError;
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;

/// Retains an explicit invocation and its full unchanged typed native declaration.
///
/// It has no live boot, controller, Source member or socket. The actual selected
/// private bootstrap independently authenticates its inherited parent and MAC.
pub struct PacketNative6InvocationLaunch {
    purpose: PacketNativeInvocationPurposeData,
    launch: PacketNative5SourceLaunch,
}

impl PacketNative6InvocationLaunch {
    /// Retains the completed typed launch before schema/currentness validation.
    ///
    /// The caller retains the original raw/Value frame before entering this
    /// decoder. Legacy bare version-five objects never imply a new purpose.
    ///
    /// # Errors
    /// Refuses occupied output, unknown fields/version, invalid purpose, typed
    /// launch/schema failure or any disagreement with the complete current target.
    /// Once constructed, the output remains owned even on later validation error.
    pub fn decode_original_value_into(
        value: &Value,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(invalid());
        }
        let fields = value.as_object().ok_or_else(invalid)?;
        if fields.len() != 3
            || fields.get("schema_version").and_then(Value::as_u64) != Some(6)
            || !fields.contains_key("invocation")
            || !fields.contains_key("launch")
        {
            return Err(invalid());
        }
        let purpose =
            PacketNativeInvocationPurposeData::from_original_value_data(&fields["invocation"])?;
        let launch = PacketNative5SourceLaunch::deserialize(&fields["launch"])
            .map_err(crucible_node_format::ContractError::from)?;
        *output = Some(Self { purpose, launch });
        let original = output.as_ref().ok_or_else(invalid)?;
        original.launch.validate()?;
        original.purpose.authenticate_target_data(&original.launch)
    }

    /// Borrows complete typed declaration DATA without exposing a live owner.
    pub fn launch_data(&self) -> &PacketNative5SourceLaunch {
        &self.launch
    }

    /// Copies the explicit bounded purpose DATA without issuing authority.
    pub const fn invocation_data(&self) -> PacketNativeInvocationPurposeData {
        self.purpose
    }
}

/// Serializes an actual unchanged launch beside its explicit invocation DATA.
///
/// The Source must retain its genuine private Core member before encoding this
/// view. Neither this view nor its resulting bytes are a native construction grant.
pub struct PacketNative6InvocationLaunchView<'a> {
    /// Borrows the complete original typed launch, including all selected grammar.
    pub launch: &'a PacketNative5SourceLaunch,
    /// Borrows the actual member's complete invocation provenance.
    pub invocation: &'a PacketNativeInvocationPurposeData,
}

impl Serialize for PacketNative6InvocationLaunchView<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("NativeInvocationLaunch", 3)?;
        fields.serialize_field("schema_version", &6u16)?;
        fields.serialize_field("invocation", self.invocation)?;
        fields.serialize_field("launch", self.launch)?;
        fields.end()
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("native invocation launch edition")
}
