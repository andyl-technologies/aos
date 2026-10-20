//! Owns the new startup JSON bodies independently of their private prefix.
//!
//! ```text
//! selected9 = {schema_version:9,mechanism,launch,prebirth_recipe_identity,initial_funding}
//! source18 = {schema,declaration:<SourceDeclaration18>,mechanism,prebirth_recipe,initial_funding}
//! boot18 = {schema,private_key,birth_id,source_birth,expected_host_registration,
//!           private_launch,host_executable}
//! ```
//!
//! These serializers borrow actual retained operands. Their inert parsers issue
//! no Source purpose, native policy, memory admission or completed import. The
//! private receiver checks prefix bounds and all three raw hashes before parsing;
//! independently derived initial funding precedes every body parser. Full native
//! recomputation follows completed seven-bank custody before model/Hold effects.

use super::super::restored_settled18::{
    NATIVE_IMPORT18_PRIVATE_BOOT_SCHEMA, NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA,
};
use super::*;
use crate::reference_packet::service::{
    PacketNative5SourceLaunch, native_startup::PacketNativeStartupAllocationRow,
};
use serde::Serializer;
use serde_json::Value;
use std::mem::size_of;

#[path = "startup_wire/allocation_partials.rs"]
mod allocation_partials;

#[path = "startup_wire/source_declaration.rs"]
mod source_declaration;

pub(in crate::reference_packet) use source_declaration::{
    native_import18_source_declaration_formatter_requested_data,
    native_import18_source_declaration_projection_counter_scratch_data,
    native_import18_source_declaration_projection_data,
    native_import18_source_declaration_serialization_data,
};

pub use source_declaration::{
    NATIVE_IMPORT18_SOURCE_DECLARATION_SCHEMA, PacketNativeImport18SourceDeclarationView,
    PacketNativeImport18SourceDeclarationWireData,
    native_import18_source_declaration_counter_scratch_data,
    native_import18_source_declaration_wire_data,
};

#[derive(Serialize, Deserialize)]
enum SourceSchema {
    #[serde(rename = "source-owned.packet-canonical-ack-source-binding/18")]
    Import18,
}

#[derive(Deserialize)]
enum BootSchema {
    #[serde(rename = "source-owned.packet-canonical-ack-private-boot/18")]
    Import18,
}

fn version9<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u16, D::Error> {
    let version = u16::deserialize(deserializer)?;
    if version != 9 {
        return Err(serde::de::Error::custom(
            "native import private wrapper version9",
        ));
    }
    Ok(version)
}

// A numeric literal is checked explicitly: string "9" is never a wire alias.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Retains the complete new selected-launch body as inert parsed DATA.
pub struct PacketNativeImport18SelectedLaunchWireData {
    #[serde(deserialize_with = "version9")]
    schema_version: u16,
    mechanism: PacketNativeImport18Selection,
    launch: PacketNative5SourceLaunch,
    prebirth_recipe_identity: [u8; 32],
    initial_funding: PacketNativeStartupAllocationRow,
}

#[derive(Serialize)]
struct SelectedLaunchView<'a> {
    schema_version: u16,
    mechanism: PacketNativeImport18Selection,
    launch: &'a PacketNative5SourceLaunch,
    prebirth_recipe_identity: [u8; 32],
    initial_funding: &'a PacketNativeStartupAllocationRow,
}

#[derive(Clone, Copy)]
struct RecipeRef<'a>(&'a PacketNativeImport18PrebirthRecipeData);

impl Serialize for RecipeRef<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.borrowed_wire_data().serialize(serializer)
    }
}

/// Borrows the exact typed Source binding for admitted projection and encoding.
#[derive(Clone, Copy, Serialize)]
pub struct PacketNativeImport18SourceBindingView<'a> {
    schema: &'static str,
    declaration: PacketNativeImport18SourceDeclarationView<'a>,
    mechanism: PacketNativeImport18Selection,
    prebirth_recipe: RecipeRef<'a>,
    initial_funding: &'a PacketNativeStartupAllocationRow,
}

/// Retains the new Source wrapper without recreating its live Source owner.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18SourceBindingWireData {
    schema: SourceSchema,
    declaration: PacketNativeImport18SourceDeclarationWireData,
    mechanism: PacketNativeImport18Selection,
    prebirth_recipe: PacketNativeImport18PrebirthRecipeWireData,
    initial_funding: PacketNativeStartupAllocationRow,
}

#[derive(Serialize)]
struct PrivateBootView<'a> {
    schema: &'static str,
    private_key: &'a Bytes,
    birth_id: &'a Bytes,
    source_birth: &'a Value,
    expected_host_registration: &'a Value,
    private_launch: &'a Id,
    host_executable: &'a ContentRef,
}

/// Borrows the prospective exact private boot over its actual typed Source view.
///
/// It exists to quote encoding before the enclosing retained Source Value is
/// constructed. It supplies no opaque Initial/recipe/Birth constructor or grant.
#[derive(Serialize)]
pub struct PacketNativeImport18PrivateBootProjectionView<'a> {
    schema: &'static str,
    private_key: &'a Bytes,
    birth_id: &'a Bytes,
    source_birth: PacketNativeImport18SourceBindingView<'a>,
    expected_host_registration: &'a Value,
    private_launch: &'a Id,
    host_executable: &'a ContentRef,
}

/// Borrows complete actual private operands before creating the wrapper DOM.
///
/// The typed Source view comes from the same independently admitted original
/// declaration, opaque recipe and Initial owner as the final source bank. The
/// serializer emits the identical field roster to the final retained-Value
/// writer. Real key/birth banks and their base64 formatters remain separately
/// admitted before this constructor or its serialization is invoked.
///
/// # Errors
/// Refuses malformed private key or birth lengths.
pub fn native_import18_private_boot_projection_wire_data<'a>(
    private_key: &'a Bytes,
    birth_id: &'a Bytes,
    source_birth: PacketNativeImport18SourceBindingView<'a>,
    expected_host_registration: &'a Value,
    private_launch: &'a Id,
    host_executable: &'a ContentRef,
) -> Result<PacketNativeImport18PrivateBootProjectionView<'a>, ProviderError> {
    if private_key.as_slice().len() != 32 || birth_id.as_slice().len() != 32 {
        return Err(invalid());
    }
    Ok(PacketNativeImport18PrivateBootProjectionView {
        schema: NATIVE_IMPORT18_PRIVATE_BOOT_SCHEMA,
        private_key,
        birth_id,
        source_birth,
        expected_host_registration,
        private_launch,
        host_executable,
    })
}

/// Retains the distinct private-boot18 body without constructing a Boot owner.
///
/// The key remains private-channel DATA. Its equality with the genuine private
/// Boot member and complete Source/launch/lease joins are separate required
/// checks; a prefix MAC under a carried key supplies none of that provenance.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNativeImport18PrivateBootWireData {
    schema: BootSchema,
    private_key: Bytes,
    birth_id: Bytes,
    source_birth: PacketNativeImport18SourceBindingWireData,
    expected_host_registration: Value,
    private_launch: Id,
    host_executable: ContentRef,
}

/// Borrows exactly the new selected-launch roster without invoking serializers.
///
/// Actual immutable launch/Source/Birth guards and full selection authentication
/// precede publication. Formatting and encoding happen only under their own row.
///
/// # Errors
/// Refuses another base launch edition or an incomplete initial funding row.
pub fn native_import18_selected_launch_wire_data<'a>(
    mechanism: PacketNativeImport18Selection,
    launch: &'a PacketNative5SourceLaunch,
    recipe: &PacketNativeImport18PrebirthRecipeData,
    initial_funding: &'a PacketNativeStartupAllocationRow,
) -> Result<impl Serialize + 'a, ProviderError> {
    initial_funding.requested_peak_data()?;
    if launch.schema_version != 5 {
        return Err(invalid());
    }
    Ok(SelectedLaunchView {
        schema_version: 9,
        mechanism,
        launch,
        prebirth_recipe_identity: recipe.identity_data(),
        initial_funding,
    })
}

/// Borrows the Source wrapper around its independently retained declaration18.
///
/// The declaration retains the actual pre-report Source birth unchanged. Every
/// new phase allocation belongs solely to the real initial/full recipe rows.
///
/// # Errors
/// Refuses an incomplete initial row. The private-field declaration view is
/// obtained only through its defining borrowed constructor and actual Source guards.
pub fn native_import18_source_binding_wire_data<'a>(
    declaration: PacketNativeImport18SourceDeclarationView<'a>,
    mechanism: PacketNativeImport18Selection,
    recipe: &'a PacketNativeImport18PrebirthRecipeData,
    initial_funding: &'a PacketNativeStartupAllocationRow,
) -> Result<PacketNativeImport18SourceBindingView<'a>, ProviderError> {
    initial_funding.requested_peak_data()?;
    Ok(PacketNativeImport18SourceBindingView {
        schema: NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA,
        declaration,
        mechanism,
        prebirth_recipe: RecipeRef(recipe),
        initial_funding,
    })
}

/// Borrows the exact private-boot18 roster from the actual new Source member.
///
/// The retained Source value was independently encoded through the new Source
/// wrapper. This helper checks its closed outer roster without making a second
/// parsed copy or qualifying any live Source or native owner.
///
/// # Errors
/// Refuses malformed key/birth lengths or another Source wrapper roster/schema.
pub fn native_import18_private_boot_wire_data<'a>(
    private_key: &'a Bytes,
    birth_id: &'a Bytes,
    source_birth: &'a Value,
    expected_host_registration: &'a Value,
    private_launch: &'a Id,
    host_executable: &'a ContentRef,
) -> Result<impl Serialize + 'a, ProviderError> {
    if private_key.as_slice().len() != 32 || birth_id.as_slice().len() != 32 {
        return Err(invalid());
    }
    source18(source_birth)?;
    Ok(PrivateBootView {
        schema: NATIVE_IMPORT18_PRIVATE_BOOT_SCHEMA,
        private_key,
        birth_id,
        source_birth,
        expected_host_registration,
        private_launch,
        host_executable,
    })
}

impl PacketNativeImport18SelectedLaunchWireData {
    /// Borrows the actual complete parsed launch without validating a policy.
    pub fn launch_data(&self) -> &PacketNative5SourceLaunch {
        &self.launch
    }

    /// Checks version, same announced identity and independently derived initial row.
    ///
    /// Full launch selection, source ownership, prefix/key and body joins remain
    /// mandatory. The announced recipe is never treated as a validated model.
    ///
    /// # Errors
    /// Refuses another edition, recipe identity or independent initial row.
    pub fn authenticate_initial_data(
        &self,
        recipe_identity: &[u8; 32],
        initial_funding: &PacketNativeStartupAllocationRow,
    ) -> Result<(), ProviderError> {
        self.initial_funding.requested_peak_data()?;
        initial_funding.requested_peak_data()?;
        if self.schema_version != 9
            || self.launch.schema_version != 5
            || self.mechanism != PacketNativeImport18Selection::SourceSignedImport18
            || &self.prebirth_recipe_identity != recipe_identity
            || &self.initial_funding != initial_funding
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl PacketNativeImport18SourceBindingWireData {
    /// Borrows the complete distinct declaration for funded semantic validation.
    pub fn declaration_data(&self) -> &PacketNativeImport18SourceDeclarationWireData {
        &self.declaration
    }

    /// Borrows the same full announcement without turning it into a recipe.
    pub fn announced_recipe_data(&self) -> &PacketNativeImport18PrebirthRecipeWireData {
        &self.prebirth_recipe
    }

    /// Checks the complete real declaration and the separately retained announcement.
    ///
    /// The expected declaration is independently derived from actual fresh launch
    /// and Source operands. This equality does not qualify caller provenance.
    ///
    /// # Errors
    /// Refuses changed declaration fields, another recipe or initial funding row.
    pub fn authenticate_initial_data(
        &self,
        expected_declaration: &Value,
        launch: &PacketNative5SourceLaunch,
        announced: &PacketNativeImport18PrebirthRecipeWireData,
        initial_funding: &PacketNativeStartupAllocationRow,
    ) -> Result<(), ProviderError> {
        self.declaration.authenticate_launch_data(launch)?;
        self.declaration
            .authenticate_value_data(expected_declaration)?;
        self.prebirth_recipe.validate_data()?;
        announced.validate_data()?;
        self.initial_funding.requested_peak_data()?;
        initial_funding.requested_peak_data()?;
        if !matches!(self.schema, SourceSchema::Import18)
            || self.mechanism != PacketNativeImport18Selection::SourceSignedImport18
            || &self.prebirth_recipe != announced
            || &self.initial_funding != initial_funding
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl PacketNativeImport18PrivateBootWireData {
    /// Borrows the actual parsed Source wrapper without creating Source authority.
    pub fn source_binding_data(&self) -> &PacketNativeImport18SourceBindingWireData {
        &self.source_birth
    }

    /// Compares every private boot operand with its genuine completed member.
    ///
    /// The caller separately authenticates the Source binding and prefix body
    /// hashes. This checks no old boot7 or Invocation15 grant and constructs no
    /// native Boot from matching private-channel DATA.
    ///
    /// # Errors
    /// Refuses another schema, key, birth, Host registration, launch or executable.
    pub fn authenticate_operands_data(
        &self,
        private_key: &[u8; 32],
        birth_id: &[u8; 32],
        expected_host_registration: &Value,
        private_launch: &Id,
        host_executable: &ContentRef,
    ) -> Result<(), ProviderError> {
        if !matches!(self.schema, BootSchema::Import18)
            || self.private_key.as_slice() != private_key
            || self.birth_id.as_slice() != birth_id
            || &self.expected_host_registration != expected_host_registration
            || &self.private_launch != private_launch
            || &self.host_executable != host_executable
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn source18(value: &Value) -> Result<(), ProviderError> {
    exact_object(
        value,
        &[
            "schema",
            "declaration",
            "mechanism",
            "prebirth_recipe",
            "initial_funding",
        ],
        NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA,
    )?;
    source_declaration::declaration_roster(value.get("declaration").ok_or_else(invalid)?)
}

fn exact_object(value: &Value, fields: &[&str], schema: &str) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.len() != fields.len()
        || fields.iter().any(|field| !object.contains_key(*field))
        || object.get("schema").and_then(Value::as_str) != Some(schema)
    {
        return Err(invalid());
    }
    Ok(())
}

/// Names actual borrowed-view output construction windows only.
///
/// The sequential maximum excludes raw/typed parser and serializer owners, all
/// of which require their independent complete construction rows.
pub fn native_import18_startup_wire_construction_transient_data() -> usize {
    let launch = size_of::<SelectedLaunchView<'static>>()
        + size_of::<Result<SelectedLaunchView<'static>, ProviderError>>();
    let source = size_of::<PacketNativeImport18SourceBindingView<'static>>()
        + size_of::<Result<PacketNativeImport18SourceBindingView<'static>, ProviderError>>()
        + size_of::<PacketNativeImport18SourceDeclarationView<'static>>();
    let boot = size_of::<PrivateBootView<'static>>()
        + size_of::<Result<PrivateBootView<'static>, ProviderError>>();
    let prospective_boot = size_of::<PacketNativeImport18PrivateBootProjectionView<'static>>()
        + size_of::<Result<PacketNativeImport18PrivateBootProjectionView<'static>, ProviderError>>(
        )
        + size_of::<PacketNativeImport18SourceBindingView<'static>>();
    launch.max(source).max(boot).max(prospective_boot)
}

/// Names actual new body/header, borrowed roster and equality controls only.
///
/// Raw body banks, serde parser/expanded typed construction, Bytes formatters,
/// launch/Host/declaration Value trees and full factory validation are independent
/// R/T/S terms. This is not their substitute or an initial funding producer.
pub fn native_import18_startup_wire_counter_scratch_data() -> usize {
    size_of::<SelectedLaunchView<'static>>()
        + size_of::<PacketNativeImport18SourceBindingView<'static>>()
        + size_of::<PrivateBootView<'static>>()
        + size_of::<PacketNativeImport18PrivateBootProjectionView<'static>>()
        + size_of::<Result<PacketNativeImport18PrivateBootProjectionView<'static>, ProviderError>>()
        + size_of::<RecipeRef<'static>>()
        + size_of::<Result<u16, serde_json::Error>>()
        + size_of::<&PacketNativeImport18SelectedLaunchWireData>()
        + size_of::<&PacketNativeImport18SourceBindingWireData>()
        + size_of::<&PacketNativeImport18PrivateBootWireData>()
        + size_of::<&serde_json::Map<String, Value>>()
        + size_of::<&[&str]>()
        + size_of::<&str>()
        + size_of::<&&str>()
        + size_of::<Option<&serde_json::Map<String, Value>>>()
        + size_of::<[&str; 3]>()
        + size_of::<[&str; 5]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<Option<&Value>>()
        + size_of::<Option<&str>>()
        + size_of::<Result<(), ProviderError>>()
        + native_import18_source_declaration_counter_scratch_data()
        + super::native_import18_prebirth_recipe_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_startup_bodies_do_not_parse_as_the_new_closed_rosters() {
        assert!(
            serde_json::from_str::<PacketNativeImport18SelectedLaunchWireData>(
                r#"{"schema_version":5}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<PacketNativeImport18SourceBindingWireData>(
            r#"{"schema":"source-owned.packet-canonical-ack-source-binding/15","invocation":{}}"#
        ).is_err());
        assert!(
            serde_json::from_str::<PacketNativeImport18PrivateBootWireData>(
                r#"{"schema":"source-owned.packet-canonical-ack-private-boot/7"}"#
            )
            .is_err()
        );
    }
}
