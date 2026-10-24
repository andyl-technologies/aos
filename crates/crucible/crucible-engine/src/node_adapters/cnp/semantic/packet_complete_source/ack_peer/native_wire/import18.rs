//! Writes the distinct wrapper9 sequence through the original private channel.
//!
//! The recipe, selected launch and Boot18 bodies are separately retained. Their
//! exact raw identities and lengths are bound by the one defining prefix codec.
//! Source member/lease/currentness and installed memory admission remain real
//! prerequisites; a copied header or a completed write creates none of them.

use super::*;
use crucible_node_format::Bytes;
use crucible_node_transport::reference_packet::service::complete_restore::import18::{
    PacketNativeImport18PrivatePrefixData, PacketNativeImport18Selection,
    encode_native_import18_private_prefix_data, native_import18_private_boot_wire_data,
    native_import18_selected_launch_wire_data,
};
use std::mem::size_of;

#[path = "import18/banks.rs"]
mod banks;
use banks::{Banks, Body};

/// Retains one private import18 sequence and every initialized partial bank.
///
/// This owner contains secret channel DATA and deliberately has no Debug,
/// Clone, decoder or public constructor. It stays in the actual launch peer
/// through refusal and supervised cleanup, alongside its unchanged writer.
#[must_use = "retain private startup bytes and partial cursors through refusal"]
pub struct PacketCompleteNativeImport18StartupWire {
    process: u32,
    thread: ThreadId,
    birth_id: [u8; 32],
    recipe_identity: [u8; 32],
    prefix: Option<PacketNativeImport18PrivatePrefixData>,
    prefix_written: usize,
    banks: Option<Banks>,
    prepared: bool,
}

impl PacketCompleteNativeImport18StartupWire {
    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    /// Counts actual partial capacities without revalidating or allocating.
    ///
    /// The containing peer separately counts this type's inline prefix/header.
    ///
    /// # Errors
    /// Refuses foreign origin or actual backing beyond the same admission.
    pub fn retained_requested_storage_precredit_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.origin()?;
        self.banks
            .as_ref()
            .map(|banks| banks.retained_backing(maximum))
            .transpose()
            .map(|bytes| bytes.unwrap_or(0))
    }

    /// Writes prefix9 followed by recipe, wrapper9 launch and Boot18 bodies.
    ///
    /// The actual Source once stage is spent before the first guard or I/O.
    /// Failure and unwind leave that stage in flight and preserve every cursor;
    /// no subsequent call retries an uncertain private-channel publication.
    ///
    /// # Errors
    /// Refuses another member, incomplete preparation, changed original Birth,
    /// unavailable private channel or any original guard/write failure.
    pub fn write_original(
        &mut self,
        material: &PacketCompleteAckPeerBootMaterial<'_>,
        writer: &mut impl Write,
    ) -> Result<(), OperationFailure> {
        self.origin()
            .map_err(|_| refused("import18 wire foreign origin"))?;
        let state = material.import18_state_data()?;
        state
            .begin_publication_data()
            .map_err(|_| refused("import18 publication already spent"))?;
        let authenticate = || {
            material
                .authenticate_original()
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            self.origin()?;
            let state = material
                .import18_state_data()
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            state.authenticate_publication_data()?;
            if !self.prepared
                || material.original.birth_id != self.birth_id
                || state.member.recipe_data().identity_data() != self.recipe_identity
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            Ok(())
        };
        // Keep cursor mutation separate from the immutable identity used by the
        // guard. No Source or whole-owner observation occurs under a mutable
        // Runtime/controller loan; this is only the original private writer.
        authenticate().map_err(|_| refused("import18 writer identity differs"))?;
        let prefix = self
            .prefix
            .as_ref()
            .ok_or_else(|| refused("import18 prefix absent"))?;
        while self.prefix_written < prefix.encoded_data().len() {
            material.authenticate_original()?;
            state
                .authenticate_publication_data()
                .map_err(|_| refused("import18 publication differs"))?;
            let remaining = &prefix.encoded_data()[self.prefix_written..];
            match writer.write(remaining) {
                Ok(0) => return Err(refused("import18 private writer made no progress")),
                Ok(count) if count <= remaining.len() => self.prefix_written += count,
                Ok(_) | Err(_) => return Err(refused("import18 private prefix write refused")),
            }
        }
        self.banks
            .as_mut()
            .ok_or_else(|| refused("import18 body banks absent"))?
            .write(writer, || {
                material
                    .authenticate_original()
                    .map_err(|_| RuntimeError::ForeignAuthority)?;
                state.authenticate_publication_data()
            })
            .map_err(|_| refused("import18 original body write refused"))?;
        material.authenticate_original()?;
        state
            .complete_publication_data()
            .map_err(|_| refused("import18 publication completion differs"))
    }

    pub(crate) fn construction_transient_data() -> usize {
        size_of::<Self>() + size_of::<Option<Self>>() + Banks::constructor_transient_bytes()
    }

    pub(crate) fn counter_scratch_data() -> usize {
        super::super::native_startup::OriginalNativeImport18Finalization::wire_counter_scratch_data()
            + Banks::counter_scratch_bytes()
            + size_of::<&PacketCompleteAckPeerBootMaterial<'static>>()
            + size_of::<Option<&Banks>>()
            + size_of::<Option<&mut Banks>>()
            + size_of::<Result<&mut Banks, RuntimeError>>()
            + size_of::<Result<&mut Banks, OperationFailure>>()
            + size_of::<Option<usize>>()
            + size_of::<Option<Result<usize, RuntimeError>>>()
            + size_of::<Result<Option<usize>, RuntimeError>>()
            + size_of::<Option<&PacketNativeImport18PrivatePrefixData>>()
            // The first closure captures borrowed material, finalization and
            // wire identity. The bank guard holds material and finalization.
            + size_of::<(&PacketCompleteAckPeerBootMaterial<'static>, &super::super::native_startup::OriginalNativeImport18Finalization, &Self)>()
            + size_of::<(&PacketCompleteAckPeerBootMaterial<'static>, &super::super::native_startup::OriginalNativeImport18Finalization)>()
            + size_of::<&Self>()
            + size_of::<&mut Self>()
            + size_of::<&mut Option<Self>>()
            + size_of::<Option<&PacketNativeImport18PrivatePrefixData>>()
            + size_of::<Result<&PacketNativeImport18PrivatePrefixData, OperationFailure>>()
            + size_of::<Result<(), OperationFailure>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<&[u8]>()
            + size_of::<std::io::Result<usize>>()
            + size_of::<std::ops::RangeFrom<usize>>()
            + size_of::<[usize; 3]>()
            + size_of::<Result<&[u8], RuntimeError>>()
            + size_of::<Result<(), crucible_node_transport::ProviderError>>()
            + size_of::<usize>()
    }
}

impl PacketCompleteAckPeerBootMaterial<'_> {
    /// Reserves process cleanup custody under the actual import18 member.
    ///
    /// The common allocation path retains its full executable, source, unused
    /// association, acquisition quote and failure-custody checks. The maximum
    /// comes only from this distinct installed member, never a decoded row.
    ///
    /// # Errors
    /// Refuses a foreign/incomplete member, changed executable, reused cleanup
    /// slot, existing association or actual acquisition beyond its admission.
    pub fn reserve_original_native_import18_launch_into(
        &self,
        directory: &std::path::Path,
        executable: &crucible_node_format::ContentRef,
        slot: &mut Option<Box<dyn crate::node_adapters::cnp::CnpSemanticProcessSlot>>,
        completed: &mut Option<crate::node_adapters::cnp::CnpSemanticLaunchReservation>,
    ) -> Result<(), OperationFailure> {
        let state = self.import18_state_data()?;
        self.reserve_native_launch_with_original_member_data(
            directory,
            executable,
            slot,
            completed,
            state.member.host_launch_requested_bytes,
        )
    }

    fn import18_state_data(
        &self,
    ) -> Result<&super::super::native_startup::OriginalNativeImport18Finalization, OperationFailure>
    {
        self.authenticate_original()?;
        if !self
            .source
            .is_original_native_import18_declaration_data()
            .map_err(|_| refused("import18 declaration unavailable"))?
            || self.original.native_startup.is_some()
        {
            return Err(refused("import18 member has another selection"));
        }
        let state = self
            .original
            .native_import18
            .as_ref()
            .ok_or_else(|| refused("import18 original member absent"))?;
        state
            .member
            .authenticate_boot_ready(self.source)
            .map_err(|_| refused("import18 original member expired"))?;
        Ok(state)
    }

    /// Prepares the same admitted private sequence in its caller-retained slot.
    ///
    /// The host constructor/formatter/parser rows precede this entry. The new
    /// Source member is consumed once before any reserve or fallible encoding;
    /// every actual bank and overcapacity allocation remains in `output`.
    ///
    /// # Errors
    /// Refuses changed selection/member/launch/Birth, an occupied output,
    /// capacity refusal, serializer failure or final original currentness loss.
    pub fn prepare_original_native_import18_wire_into(
        &self,
        launch: &PacketNative5SourceLaunch,
        canonical_base5: &[u8],
        output: &mut Option<PacketCompleteNativeImport18StartupWire>,
    ) -> Result<(), OperationFailure> {
        let state = self.import18_state_data()?;
        if output.is_some() {
            return Err(refused("import18 wire output occupied"));
        }
        self.source
            .authenticate_native_launch_data(launch)
            .map_err(|_| refused("import18 actual launch differs"))?;
        if state.member.launch_digest_data() != *blake3::hash(canonical_base5).as_bytes() {
            return Err(refused("import18 canonical base launch differs"));
        }
        state
            .begin_wire_data()
            .map_err(|_| refused("import18 wire already attempted"))?;
        *output = Some(PacketCompleteNativeImport18StartupWire {
            process: std::process::id(),
            thread: std::thread::current().id(),
            birth_id: self.original.birth_id,
            recipe_identity: state.member.recipe_data().identity_data(),
            prefix: None,
            prefix_written: 0,
            banks: None,
            prepared: false,
        });
        let wire = output
            .as_mut()
            .ok_or_else(|| refused("import18 wire slot absent"))?;
        Banks::reserve_into(state.member.wire_body_maximum_data(), &mut wire.banks)
            .map_err(|_| refused("import18 wire bank reservation refused"))?;
        let banks = wire
            .banks
            .as_mut()
            .ok_or_else(|| refused("import18 banks absent"))?;
        banks
            .fill(Body::Recipe, |writer| {
                render(state.member.recipe_data().borrowed_wire_data(), writer)
            })
            .map_err(|_| refused("import18 recipe encoding refused"))?;
        let initial = state.member.initial_data();
        let selected = native_import18_selected_launch_wire_data(
            PacketNativeImport18Selection::SourceSignedImport18,
            launch,
            state.member.recipe_data(),
            &initial,
        )
        .map_err(|_| refused("import18 selected launch differs"))?;
        banks
            .fill(Body::Launch, |writer| render(selected, writer))
            .map_err(|_| refused("import18 selected launch encoding refused"))?;

        let key = Bytes::new(self.original.key.to_vec());
        let birth = Bytes::new(self.original.birth_id.to_vec());
        let host = crucible_node_format::canonical::parse_json(
            &self.original.expected_host_registration,
            self.original.expected_host_registration.len(),
        )
        .map_err(|_| refused("import18 planned registration invalid"))?;
        let boot = native_import18_private_boot_wire_data(
            &key,
            &birth,
            state
                .source_binding_data()
                .map_err(|_| refused("import18 Source binding absent"))?,
            &host,
            &self.original.private_launch,
            &self.original.host_executable,
        )
        .map_err(|_| refused("import18 private boot differs"))?;
        banks
            .fill(Body::Boot, |writer| render(boot, writer))
            .map_err(|_| refused("import18 private boot encoding refused"))?;
        state
            .member
            .initial_funding_data()
            .authenticate_body_lengths_data([
                banks
                    .completed(Body::Recipe)
                    .map_err(|_| refused("import18 recipe absent"))?
                    .len(),
                banks
                    .completed(Body::Launch)
                    .map_err(|_| refused("import18 launch absent"))?
                    .len(),
                banks
                    .completed(Body::Boot)
                    .map_err(|_| refused("import18 boot absent"))?
                    .len(),
            ])
            .map_err(|_| refused("import18 initial body bounds differ"))?;
        wire.prefix = Some(
            encode_native_import18_private_prefix_data(
                state.member.recipe_data(),
                banks
                    .completed(Body::Recipe)
                    .map_err(|_| refused("import18 recipe absent"))?,
                banks
                    .completed(Body::Launch)
                    .map_err(|_| refused("import18 launch absent"))?,
                banks
                    .completed(Body::Boot)
                    .map_err(|_| refused("import18 boot absent"))?,
                &initial,
                &self.original.key,
            )
            .map_err(|_| refused("import18 prefix encoding refused"))?,
        );
        self.authenticate_original()?;
        wire.prepared = true;
        state
            .prepared_wire_data()
            .map_err(|_| refused("import18 wire completion differs"))
    }
}

fn render(value: impl serde::Serialize, writer: &mut impl Write) -> Result<(), RuntimeError> {
    let value = serde_json::to_value(value).map_err(|_| RuntimeError::ResourceLimit)?;
    crucible_node_format::canonical::canonical_json_to_writer(&value, writer)
        .map_err(|_| RuntimeError::ResourceLimit)
}
