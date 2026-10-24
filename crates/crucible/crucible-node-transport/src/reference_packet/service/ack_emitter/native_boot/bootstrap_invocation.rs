//! Authenticates the new inherited invocation prefix and its complete row recount.
//!
//! Only the separate selected private entry calls this constructor. Legacy
//! prefix14 and claim methods remain closed. A fixed purpose or allocation row
//! cannot create this origin; peer credentials, the private MAC, complete raw
//! identities and a spent same-channel scope must all agree first.

use super::*;
use crate::protocol_snapshot::owned11::OriginalOwned11Fields as Fields;
use crate::reference_packet::service::native_startup::{
    PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA, PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA,
    PacketNativeBirthStartupInputs, PacketNativeInvocationPreambleData,
    PacketNativeInvocationPurposeData, PacketNativeStartupAllocation,
    authenticate_original_native_invocation_preamble_data,
    decode_original_native_invocation_preamble_data,
    original_native_invocation_baseline_storage_data,
    original_native_invocation_construction_storage_data,
    original_native_invocation_counter_scratch_data,
};
use crucible_node_format::U64;

impl OriginalNativeStartupBootstrap {
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn read_invocation<
        S: AsFd,
    >(
        stream: &S,
    ) -> Result<Self, ProviderError> {
        let original_cut =
            crate::operational_time::OperationalDeadline::after(Duration::from_secs(5))
                .ok_or(ProviderError::Correlation("native original startup cut"))?;
        let peer = rustix::net::sockopt::socket_peercred(stream).map_err(std::io::Error::from)?;
        let parent = rustix::process::getppid()
            .ok_or(ProviderError::Correlation("native original parent absent"))?;
        if peer.pid != parent || peer.uid != rustix::process::geteuid() {
            return Err(ProviderError::Correlation(
                "native startup inherited parent differs",
            ));
        }
        let mut preamble = [0; ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES];
        let mut received = 0;
        while received < preamble.len() {
            if original_cut.is_expired() {
                return Err(ProviderError::Correlation(
                    "native startup pre-parser expired",
                ));
            }
            match rustix::net::recv(
                stream,
                &mut preamble[received..],
                rustix::net::RecvFlags::DONTWAIT,
            ) {
                Ok((_, 0)) => return Err(ProviderError::Frame("native startup prefix incomplete")),
                Ok((_, count)) => received += count,
                Err(error) if error == rustix::io::Errno::INTR => {}
                Err(error) if error == rustix::io::Errno::AGAIN => std::thread::yield_now(),
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
        }
        let data = decode_original_native_invocation_preamble_data(&preamble)?;
        authenticate_original_native_invocation_preamble_data(&preamble, &preamble[272..304])?;
        if data.controller_pid != u64::from(peer.pid.as_raw_nonzero().get() as u32)
            || data.controller_uid != u64::from(peer.uid.as_raw())
            || data.birth_id
                != blake3::derive_key(
                    "source-owned.packet-canonical-ack-birth/5",
                    &preamble[272..304],
                )
        {
            return Err(ProviderError::Correlation(
                "native startup prefix parent/birth differs",
            ));
        }
        // A valid private prefix must cover the actual fixed initial banks
        // before any Rc/frame/parser constructor. Full typed geometry is
        // recounted against the same rows before native model construction.
        let initial_retained = crate::reference_packet::service::native_startup::original_native_private_bootstrap_floor_data()?;
        if data.private_bootstrap.retained_requested_bytes.get() < initial_retained as u64 {
            return Err(ProviderError::ResourceExhausted(
                "native startup private bank floor",
            ));
        }
        let incoming = crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(
            (data.launch_bytes as usize).max(data.maximum_boot_bytes as usize),
        )?;
        if incoming.canonical_pass_requested_bytes()? as u64
            > data.private_bootstrap.maximum_simultaneous_transient_bytes.get()
            || crate::reference_packet::service::native_startup::original_native_birth_startup_counter_scratch_data().checked_add(
                    original_native_invocation_counter_scratch_data(),
                ).ok_or(ProviderError::ResourceExhausted("invocation counter extent"))? as u64
                > data.private_bootstrap.declared_counter_scratch_bytes.get()
        {
            return Err(ProviderError::ResourceExhausted("native startup private parser window"));
        }
        if original_cut.is_expired() {
            return Err(ProviderError::Correlation(
                "native startup pre-parser expired",
            ));
        }
        Ok(Self {
            creator: std::process::id(),
            thread: std::thread::current().id(),
            preamble,
            private_bootstrap: data.private_bootstrap,
            native_birth: data.native_birth,
            restore_prepare: data.restore_prepare,
            expected_controller_pid: data.controller_pid,
            expected_controller_uid: data.controller_uid,
            maximum_launch_bytes: data.launch_bytes as usize,
            maximum_boot_bytes: data.maximum_boot_bytes as usize,
            original_cut,
            native_issued: false,
            failed: false,
        })
    }

    // Edition routing comes from the actual retained, already authenticated
    // inherited prefix. It never chooses original versus restoration purpose.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn has_invocation_prefix(
        &self,
    ) -> Result<bool, ProviderError> {
        self.ensure_original()?;
        if self.preamble.get(..8) == Some(&b"CNPNS15\0"[..]) {
            decode_original_native_invocation_preamble_data(&self.preamble)?;
            Ok(true)
        } else {
            self.data()?;
            Ok(false)
        }
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn invocation_data(
        &self,
    ) -> Result<PacketNativeInvocationPreambleData, ProviderError> {
        self.ensure_original()?;
        decode_original_native_invocation_preamble_data(&self.preamble)
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn claim_invocation_birth_data(
        &mut self,
        input: super::super::super::boot::OriginalNativeBootClaimInputs<'_>,
        purpose: &PacketNativeInvocationPurposeData,
    ) -> Result<super::super::super::boot::native_startup::OriginalNativeStartupBoot, ProviderError>
    {
        let super::super::super::boot::OriginalNativeBootClaimInputs {
            launch,
            launch_body,
            source,
            registration,
            private_launch,
            key,
            birth_id,
        } = input;

        self.ensure_original()?;
        if std::mem::replace(&mut self.native_issued, true) {
            return Err(ProviderError::Conflict(
                "native invocation birth already claimed",
            ));
        }
        self.failed = true;
        let expected = decode_original_native_invocation_preamble_data(&self.preamble)?;
        authenticate_original_native_invocation_preamble_data(&self.preamble, key)?;
        if birth_id != expected.birth_id
            || launch_body.len() != self.maximum_launch_bytes
            || blake3::hash(launch_body).as_bytes() != &expected.launch_digest
            || blake3::hash(private_launch.as_str().as_bytes()).as_bytes()
                != &expected.private_launch_digest
            || launch.controller_pid.get() != self.expected_controller_pid
            || launch.controller_uid.get() != self.expected_controller_uid
        {
            return Err(ProviderError::Correlation(
                "native invocation original bodies differ",
            ));
        }
        purpose.authenticate_target_data(launch)?;
        let fields = source
            .as_object()
            .ok_or(ProviderError::Correlation("invocation source object"))?;
        if fields.len() != 19
            || fields.get("schema").and_then(serde_json::Value::as_str)
                != Some(PACKET_NATIVE_INVOCATION_SOURCE_BINDING_SCHEMA)
            || PacketNativeInvocationPurposeData::from_original_value_data(
                fields
                    .get("invocation")
                    .ok_or(ProviderError::Correlation("invocation source purpose"))?,
            )? != *purpose
        {
            return Err(ProviderError::Correlation(
                "native invocation Source target differs",
            ));
        }
        let source_body = crucible_node_format::canonical::canonical_json(source)?;
        let host_body = crucible_node_format::canonical::canonical_json(registration)?;
        if blake3::hash(&source_body).as_bytes() != &expected.source_digest
            || blake3::hash(&host_body).as_bytes() != &expected.registration_digest
        {
            return Err(ProviderError::Correlation(
                "native invocation bound child differs",
            ));
        }
        let scratch = crate::reference_packet::service::native_startup::original_native_birth_startup_counter_scratch_data()
            .checked_add(original_native_invocation_counter_scratch_data())
            .ok_or(ProviderError::ResourceExhausted("invocation counter extent"))?;
        if scratch as u64 > self.native_birth.declared_counter_scratch_bytes.get()
            || scratch as u64 > self.private_bootstrap.declared_counter_scratch_bytes.get()
        {
            return Err(ProviderError::ResourceExhausted(
                "native invocation counter window",
            ));
        }
        let maximum = usize::try_from(
            self.native_birth
                .requested_peak_data()?
                .max(self.private_bootstrap.requested_peak_data()?),
        )
        .map_err(|_| ProviderError::ResourceExhausted("native invocation extent"))?;
        // Borrow the SAME literal's complete nested launch span. No re-encoding,
        // stripped DTO, second bank or caller-provided legacy body is accepted.
        let nested = nested_launch_literal(launch_body)?;
        let actual = original_native_invocation_baseline_storage_data(
            &PacketNativeBirthStartupInputs {
                launch,
                private_launch,
                encoded_launch: nested,
                source_birth: &source_body,
                host_registration: &host_body,
            },
            purpose,
            maximum,
        )?;
        let extra = original_native_invocation_construction_storage_data(
            purpose,
            nested,
            actual.maximum_private_boot_body_bytes(),
            maximum,
        )?;
        if extra.launch_identity_data().raw_digest != expected.launch_digest
            || extra.launch_identity_data().encoded_bytes != launch_body.len()
            || extra.maximum_private_boot_body_bytes() > self.maximum_boot_bytes
        {
            return Err(ProviderError::Correlation(
                "native invocation recounted launch differs",
            ));
        }
        let add = |a: usize, b: usize| {
            a.checked_add(b)
                .filter(|n| *n <= maximum)
                .ok_or(ProviderError::ResourceExhausted(
                    "native invocation requested sum",
                ))
        };
        let row =
            |retained, transient| -> Result<PacketNativeStartupAllocationRow, ProviderError> {
                let number = |n| {
                    u64::try_from(n).map(U64::new).map_err(|_| {
                        ProviderError::ResourceExhausted("native invocation row extent")
                    })
                };
                Ok(PacketNativeStartupAllocationRow {
                    retained_requested_bytes: number(retained)?,
                    maximum_simultaneous_transient_bytes: number(transient)?,
                    declared_counter_scratch_bytes: number(scratch)?,
                })
            };
        self.native_birth.authenticate_actual_data(&row(
            add(
                actual.retained_requested_bytes(),
                extra.native_retained_requested_bytes(),
            )?,
            add(
                actual.maximum_simultaneous_transient_bytes(),
                extra.native_transient_requested_bytes(),
            )?,
        )?)?;
        self.private_bootstrap.authenticate_actual_data(&row(
            add(
                actual.private_bootstrap_retained_requested_bytes(),
                extra.private_retained_requested_bytes(),
            )?,
            add(
                actual.private_bootstrap_maximum_simultaneous_transient_bytes(),
                extra.private_transient_requested_bytes(),
            )?,
        )?)?;
        let allocation = PacketNativeStartupAllocation {
            schema: PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA.into(),
            private_bootstrap: self.private_bootstrap,
            native_birth: self.native_birth,
            restore_prepare: self.restore_prepare,
        };
        allocation.validate_data(launch.complete_restore_selection == Some(
            crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
        ))?;
        if serde_json::to_value(&allocation).map_err(crucible_node_format::ContractError::from)?
            != source["native_startup_allocation"]
        {
            return Err(ProviderError::Correlation(
                "native invocation allocation differs",
            ));
        }
        super::finish_claim(
            &mut self.failed,
            self.creator,
            &self.thread,
            &self.original_cut,
            "native invocation claim expired",
        )?;
        Ok(
            super::super::super::boot::native_startup::OriginalNativeStartupBoot {
                restored_suffix: None,
                allocation,
                source_digest: expected.source_digest,
                launch_digest: expected.launch_digest,
                birth_id: expected.birth_id,
                native_birth_issued: true,
                baseline_complete: false,
                prepare_startup_issued: false,
            },
        )
    }
}

fn nested_launch_literal(raw: &[u8]) -> Result<&[u8], ProviderError> {
    let mut fields = Fields::object(raw)?;
    fields.named("invocation")?;
    let launch = fields.named("launch")?;
    if fields.named("schema_version")? != b"6" {
        return Err(ProviderError::Correlation(
            "native invocation launch version",
        ));
    }
    fields.finish()?;
    Ok(launch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_launch_census_borrows_same_literal_and_refuses_wrong_closed_wrapper() {
        let raw =
            br#"{"invocation":{"kind":"inert"},"launch":{"schema_version":5},"schema_version":6}"#;
        let nested = nested_launch_literal(raw).unwrap();
        assert_eq!(nested, br#"{"schema_version":5}"#);
        let offset = nested.as_ptr() as usize - raw.as_ptr() as usize;
        assert_eq!(&raw[offset..offset + nested.len()], nested);

        for changed in [
            br#"{"schema_version":5}"#.as_slice(),
            br#"{"invocation":null,"launch":{},"schema_version":5}"#,
            br#"{"invocation":null,"launch":{},"schema_version":6,"extra":null}"#,
            br#"{"invocation":null,"launch":{},"launch":{},"schema_version":6}"#,
            br#"{"launch":{},"invocation":null,"schema_version":6}"#,
        ] {
            assert!(nested_launch_literal(changed).is_err());
        }
    }
}
