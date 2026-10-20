//! Projects the same normalized fields from genuine operands available before Birth.
//!
//! Future native PID/UID and fixed digests use their defining scalar widths.
//! Recipe24 and Initial3 come from their actual defining projection, never from
//! a fabricated recipe or row. All operands here remain unprivileged DATA.

use super::*;
use crate::reference_packet::service::PacketNative5SourceLaunch;
use crate::reference_packet::service::complete_restore::import18::hello::{
    native_import18_hello_negotiated_projection_data,
    native_import18_hello_projection_counter_scratch_data,
    native_import18_hello_registration_projection_data,
};
use crate::reference_packet::service::complete_restore::import18::startup_wire::{
    PacketNativeImport18SourceDeclarationView,
    native_import18_source_declaration_projection_counter_scratch_data,
    native_import18_source_declaration_projection_data,
};
use crate::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18HelloDeclarationData, native_import18_initial_row_projection_data,
    native_import18_prebirth_recipe_projection_data,
    native_import18_recipe_projection_counter_scratch_data,
};
use crate::reference_packet::service::complete_restore::restored_settled18::NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA;

/// Borrows the actual immutable pre-Birth DATA for the four future normalizations.
///
/// A private Source/Birth owner separately authenticates these operands against
/// the same BodyPlan, launch and target. Full compiled definition correspondence,
/// executable provenance, planned registration and Source custody remain its
/// independent obligations; this type implements none of those permissions.
pub(in crate::reference_packet) struct NativeImport18BootstrapProspectiveOperands<'a> {
    pub(in crate::reference_packet) launch: &'a PacketNative5SourceLaunch,
    pub(in crate::reference_packet) hello: &'a PacketNativeImport18HelloDeclarationData,
    pub(in crate::reference_packet) declaration: &'a PacketNativeImport18SourceDeclarationView<'a>,
    pub(in crate::reference_packet) private_launch: &'a Id,
    pub(in crate::reference_packet) host_executable: &'a ContentRef,
    pub(in crate::reference_packet) native_executable: &'a ContentRef,
    pub(in crate::reference_packet) expected_host_registration: &'a serde_json::Value,
    pub(in crate::reference_packet) import: &'a SchemaRef,
    pub(in crate::reference_packet) stage: &'a SchemaRef,
    pub(in crate::reference_packet) record: &'a SchemaRef,
}

/// Projects birth, kernel, policy and native registration in defining role order.
///
/// Nested declaration Bytes are already ordinary Strings in the actual retained
/// SourceBinding normalized by ACK. Their earlier SourceBinding construction has
/// an independent formatter term, exposed by the declaration component. These
/// shapes count each later normalized copy, without donating that earlier work.
///
/// # Errors
/// Refuses a changed Hello declaration/target, checked extent overflow or a
/// complete role above the independent projection restriction.
pub(in crate::reference_packet) fn native_import18_bootstrap_prospective_operands_data(
    operands: &NativeImport18BootstrapProspectiveOperands<'_>,
    maximum: usize,
) -> Result<[OriginalSerializationStorageData; 4], ProviderError> {
    if operands.launch.controller_pid.get() == 0
        || operands.launch.controller_pid.get() > i32::MAX as u64
        || operands.launch.controller_uid.get() > u32::MAX as u64
    {
        return Err(invalid());
    }
    for (reference, schema) in [
        (operands.import, "source-owned.packet-native-import/18"),
        (operands.stage, "source-owned.packet-native-import-stage/18"),
        (operands.record, "source-owned.packet-restored-native/18"),
    ] {
        if reference.id.as_str() != schema || reference.version != 18 {
            return Err(invalid());
        }
    }
    let mut birth = Projection::new(maximum)?;
    object(
        &mut birth,
        &[
            "schema",
            "birth_id",
            "private_launch",
            "host_executable",
            "source_binding",
            "expected_host_registration",
        ],
    )?;
    birth.add_string("source-owned.packet-native-import-bootstrap-birth-association/18")?;
    birth.add_unescaped_ascii_extent(43)?;
    birth.add_value(operands.private_launch)?;
    birth.add_value(operands.host_executable)?;
    source_binding(&mut birth, operands)?;
    birth.add_value(operands.expected_host_registration)?;
    let birth = birth.finish(maximum)?;

    let mut kernel = Projection::new(maximum)?;
    object(&mut kernel, &["schema", "controller", "native"])?;
    kernel.add_string("source-owned.packet-canonical-ack-kernel-binding/5")?;
    object(&mut kernel, &["pid", "uid", "executable"])?;
    kernel.add_value(&operands.launch.controller_pid)?;
    kernel.add_value(&operands.launch.controller_uid)?;
    kernel.add_value(&operands.launch.controller_executable)?;
    object(&mut kernel, &["pid", "uid", "executable"])?;
    // True constructor: PID is 1..=i32::MAX, UID is 0..=u32::MAX.
    // Both U64 decimal strings therefore have at most ten ASCII bytes.
    kernel.add_unescaped_ascii_extent(10)?;
    kernel.add_unescaped_ascii_extent(10)?;
    kernel.add_value(operands.native_executable)?;
    let kernel = kernel.finish(maximum)?;

    let mut policy = Projection::new(maximum)?;
    object(
        &mut policy,
        &[
            "schema",
            "source_binding",
            "recipe_identity",
            "definitions",
            "negotiated",
        ],
    )?;
    policy.add_string("source-owned.packet-native-import-bootstrap-policy-binding/18")?;
    source_binding(&mut policy, operands)?;
    policy.add_unescaped_ascii_extent(43)?;
    // This is the same actual immutable Serialize view, containing no Bytes.
    // Its real container participates in the Credit depth guard.
    let definitions = PacketNativeImport18BootstrapDefinitionsView {
        mechanism: PacketNativeImport18Selection::SourceSignedImport18,
        import: operands.import,
        stage: operands.stage,
        record: operands.record,
    };
    policy.add_value(&definitions)?;
    native_import18_hello_negotiated_projection_data(&mut policy, operands.launch, operands.hello)?;
    let policy = policy.finish(maximum)?;

    let mut registration = Projection::new(maximum)?;
    native_import18_hello_registration_projection_data(
        &mut registration,
        operands.launch,
        operands.hello,
    )?;
    Ok([birth, kernel, policy, registration.finish(maximum)?])
}

fn source_binding(
    out: &mut Projection,
    operands: &NativeImport18BootstrapProspectiveOperands<'_>,
) -> Result<(), ProviderError> {
    object(
        out,
        &[
            "schema",
            "declaration",
            "mechanism",
            "prebirth_recipe",
            "initial_funding",
        ],
    )?;
    out.add_string(NATIVE_IMPORT18_SOURCE_BINDING_SCHEMA)?;
    native_import18_source_declaration_projection_data(out, operands.declaration)?;
    out.add_value(&PacketNativeImport18Selection::SourceSignedImport18)?;
    native_import18_prebirth_recipe_projection_data(out)?;
    native_import18_initial_row_projection_data(out)
}

/// Names the real prospective component's fixed views, projections and iterators.
pub(in crate::reference_packet) fn native_import18_bootstrap_prospective_operands_counter_scratch_data()
-> usize {
    native_import18_source_declaration_projection_counter_scratch_data()
        + native_import18_recipe_projection_counter_scratch_data()
        + native_import18_hello_projection_counter_scratch_data()
        + native_import18_bootstrap_operands_counter_scratch_data()
        + size_of::<NativeImport18BootstrapProspectiveOperands<'static>>()
        + size_of::<&NativeImport18BootstrapProspectiveOperands<'static>>()
        + size_of::<Projection>() * 4
        + size_of::<Result<Projection, ProviderError>>()
        + size_of::<[OriginalSerializationStorageData; 4]>()
        + size_of::<Result<[OriginalSerializationStorageData; 4], ProviderError>>()
        + size_of::<Result<OriginalSerializationStorageData, ProviderError>>()
        + size_of::<PacketNativeImport18BootstrapDefinitionsView<'static>>()
        + size_of::<&PacketNativeImport18BootstrapDefinitionsView<'static>>()
        + size_of::<PacketNativeImport18Selection>()
        + size_of::<&PacketNativeImport18Selection>()
        + size_of::<&mut Projection>()
        + size_of::<&[&str]>()
        + size_of::<[(&SchemaRef, &str); 3]>()
        + size_of::<std::array::IntoIter<(&'static SchemaRef, &'static str), 3>>()
        + size_of::<(&SchemaRef, &str)>()
        + size_of::<u64>()
        + size_of::<[&str; 6]>()
        + size_of::<[&str; 5]>()
        + size_of::<[&str; 3]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<&&str>()
        + size_of::<usize>()
        + size_of::<Result<(), ProviderError>>()
}

const _: fn(&PacketNativeImport18BootstrapBirthView<'static>) = |view| {
    let PacketNativeImport18BootstrapBirthView {
        schema: _,
        birth_id: _,
        private_launch: _,
        host_executable: _,
        source_binding: _,
        expected_host_registration: _,
    } = view;
};

const _: fn(&PacketNativeImport18BootstrapKernelView<'static>) = |view| {
    let PacketNativeImport18BootstrapKernelView {
        schema: _,
        controller: _,
        native: _,
    } = view;
};

const _: fn(&PacketNativeImport18BootstrapProcessView<'static>) = |view| {
    let PacketNativeImport18BootstrapProcessView {
        pid: _,
        uid: _,
        executable: _,
    } = view;
};

const _: fn(&PacketNativeImport18BootstrapPolicyView<'static>) = |view| {
    let PacketNativeImport18BootstrapPolicyView {
        schema: _,
        source_binding: _,
        recipe_identity: _,
        definitions: _,
        negotiated: _,
    } = view;
};
