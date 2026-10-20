//! Owns the versioned inherited-channel pre-parser and original startup origin.
//!
//! Its fixed wire prefix is public process DATA. Only the selected original
//! inherited socket, actual parent credentials and same private Source birth
//! can construct this native owner. A row, Boolean or decoded binding cannot.

use super::*;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;

// This primitive byte contract has no Rust-native layout on the wire. Exact
// offsets are explicitly encoded/decoded by the selected original entry.
use crate::reference_packet::service::native_startup::{
    ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES, PacketNativeStartupPreambleData,
    authenticate_original_native_startup_preamble_data,
    decode_original_native_startup_preamble_data,
};

pub(in crate::reference_packet::service::ack_emitter::native_boot) struct OriginalNativeStartupBootstrap
{
    pub(in crate::reference_packet::service::ack_emitter::native_boot) creator: u32,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) thread:
        std::thread::ThreadId,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) preamble:
        [u8; ORIGINAL_NATIVE_STARTUP_PREAMBLE_BYTES],
    pub(in crate::reference_packet::service::ack_emitter::native_boot) private_bootstrap:
        PacketNativeStartupAllocationRow,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) native_birth:
        PacketNativeStartupAllocationRow,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) restore_prepare:
        Option<PacketNativeStartupAllocationRow>,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) expected_controller_pid: u64,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) expected_controller_uid: u64,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) maximum_launch_bytes: usize,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) maximum_boot_bytes: usize,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) original_cut:
        crate::operational_time::OperationalDeadline,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) native_issued: bool,
    pub(in crate::reference_packet::service::ack_emitter::native_boot) failed: bool,
}

impl OriginalNativeStartupBootstrap {
    // This is reachable only from the distinct selected inherited-channel
    // entry. No decoded row or ordinary service caller can construct a scope.
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn read_original<S: AsFd>(
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
        let data = decode_original_native_startup_preamble_data(&preamble)?;
        authenticate_original_native_startup_preamble_data(&preamble, &preamble[272..304])?;
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
        // Current original14 always uses the selected occurrence gate before
        // either Value. This first check pays the independent raw body bank;
        // the complete two-pass/typed/carry sum follows the actual raw read.
        // Old binaries retain their broad parser floor and refuse lower rows.
        if (data.launch_bytes as usize).max(data.maximum_boot_bytes as usize) as u64
            > data.private_bootstrap.maximum_simultaneous_transient_bytes.get()
            || crate::reference_packet::service::native_startup::original_native_birth_startup_counter_scratch_data() as u64
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

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn ensure_original(
        &self,
    ) -> Result<(), ProviderError> {
        if self.creator != std::process::id()
            || self.thread != std::thread::current().id()
            || self.original_cut.is_expired()
            || self.failed
        {
            return Err(ProviderError::Correlation(
                "native startup original scope unavailable",
            ));
        }
        Ok(())
    }

    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn data(
        &self,
    ) -> Result<PacketNativeStartupPreambleData, ProviderError> {
        self.ensure_original()?;
        decode_original_native_startup_preamble_data(&self.preamble)
    }
}

impl OriginalNativeStartupBootstrap {
    pub(in crate::reference_packet::service::ack_emitter::native_boot) fn claim_birth_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        launch_body: &[u8],
        source: &serde_json::Value,
        registration: &serde_json::Value,
        private_launch: &crucible_node_format::Id,
        key: &[u8],
        birth_id: &[u8],
    ) -> Result<super::super::boot::native_startup::OriginalNativeStartupBoot, ProviderError> {
        use crate::reference_packet::service::native_startup::{
            PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA, PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA,
            PacketNativeBirthStartupInputs, PacketNativeStartupAllocation,
            PacketNativeStartupAllocationRow, original_native_birth_startup_counter_scratch_data,
            original_native_preflight_birth_startup_storage_data,
        };
        use crucible_node_format::U64;

        self.ensure_original()?;
        if std::mem::replace(&mut self.native_issued, true) {
            return Err(ProviderError::Conflict(
                "native startup birth already claimed",
            ));
        }
        // Any subsequent failure permanently spends this actual private scope.
        // The bootstrap holder remains retained by the selected entry.
        self.failed = true;
        let expected = decode_original_native_startup_preamble_data(&self.preamble)?;
        authenticate_original_native_startup_preamble_data(&self.preamble, key)?;
        if birth_id != expected.birth_id
            || launch_body.len() != self.maximum_launch_bytes
            || blake3::hash(launch_body).as_bytes() != &expected.launch_digest
            || blake3::hash(private_launch.as_str().as_bytes()).as_bytes()
                != &expected.private_launch_digest
            || launch.controller_pid.get() != self.expected_controller_pid
            || launch.controller_uid.get() != self.expected_controller_uid
            || source.get("schema").and_then(serde_json::Value::as_str)
                != Some(PACKET_NATIVE_STARTUP_SOURCE_BINDING_SCHEMA)
        {
            return Err(ProviderError::Correlation(
                "native startup original bodies differ",
            ));
        }
        let source_body = crucible_node_format::canonical::canonical_json(source)?;
        let host_body = crucible_node_format::canonical::canonical_json(registration)?;
        if blake3::hash(&source_body).as_bytes() != &expected.source_digest
            || blake3::hash(&host_body).as_bytes() != &expected.registration_digest
        {
            return Err(ProviderError::Correlation(
                "native startup bound child differs",
            ));
        }
        let scratch = original_native_birth_startup_counter_scratch_data();
        if scratch as u64 > self.native_birth.declared_counter_scratch_bytes.get() {
            return Err(ProviderError::ResourceExhausted(
                "native startup counter window",
            ));
        }
        // One DATA producer recounts both independently admitted rows. A
        // smaller native phase must not hide the authenticated private raw
        // parser extent. Each returned row still authenticates every component
        // against its ORIGINAL grant below; this ceiling grants no allocation.
        let maximum = original_requote_maximum(&self.native_birth, &self.private_bootstrap)?;
        let actual = original_native_preflight_birth_startup_storage_data(
            &PacketNativeBirthStartupInputs {
                launch,
                private_launch,
                encoded_launch: launch_body,
                source_birth: &source_body,
                host_registration: &host_body,
            },
            maximum,
        )?;
        let row = |retained: usize,
                   transient: usize,
                   scratch: usize|
         -> Result<PacketNativeStartupAllocationRow, ProviderError> {
            Ok(PacketNativeStartupAllocationRow {
                retained_requested_bytes: U64::new(u64::try_from(retained).map_err(|_| {
                    ProviderError::ResourceExhausted("native startup retained extent")
                })?),
                maximum_simultaneous_transient_bytes: U64::new(u64::try_from(transient).map_err(
                    |_| ProviderError::ResourceExhausted("native startup transient extent"),
                )?),
                declared_counter_scratch_bytes: U64::new(u64::try_from(scratch).map_err(|_| {
                    ProviderError::ResourceExhausted("native startup scratch extent")
                })?),
            })
        };
        self.native_birth.authenticate_actual_data(&row(
            actual.retained_requested_bytes(),
            actual.maximum_simultaneous_transient_bytes(),
            actual.declared_counter_scratch_bytes(),
        )?)?;
        self.private_bootstrap.authenticate_actual_data(&row(
            actual.private_bootstrap_retained_requested_bytes(),
            actual.private_bootstrap_maximum_simultaneous_transient_bytes(),
            scratch,
        )?)?;
        if actual.maximum_private_boot_body_bytes() > self.maximum_boot_bytes {
            return Err(ProviderError::ResourceExhausted(
                "native startup boot shape widened",
            ));
        }
        let allocation = PacketNativeStartupAllocation {
            schema: PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA.into(),
            private_bootstrap: self.private_bootstrap,
            native_birth: self.native_birth,
            restore_prepare: self.restore_prepare,
        };
        allocation.validate_data(launch.complete_restore_selection == Some(
            crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12))?;
        if serde_json::to_value(&allocation).map_err(crucible_node_format::ContractError::from)?
            != source["native_startup_allocation"]
        {
            return Err(ProviderError::Correlation(
                "native startup allocation body differs",
            ));
        }
        self.failed = false;
        Ok(
            super::super::boot::native_startup::OriginalNativeStartupBoot {
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

// The fixed path is borrowed through the streamed executable helper. No
// decimal String, PathBuf or complete executable byte Vec is constructed.
pub(in crate::reference_packet::service::ack_emitter::native_boot) fn measure_original_controller_executable(
    pid: crucible_node_format::U64,
) -> Result<crucible_node_format::ContentRef, ProviderError> {
    use std::os::unix::ffi::OsStrExt;
    let mut path = [0u8; 30];
    let mut digits = [0u8; 20];
    let mut value = pid.get();
    let mut first = digits.len();
    loop {
        first -= 1;
        digits[first] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    path[..6].copy_from_slice(b"/proc/");
    let end = 6 + digits.len() - first;
    path[6..end].copy_from_slice(&digits[first..]);
    path[end..end + 4].copy_from_slice(b"/exe");
    super::super::boot::measure_original_prepare_executable_data(Path::new(
        std::ffi::OsStr::from_bytes(&path[..end + 4]),
    ))
}

fn original_requote_maximum(
    native: &PacketNativeStartupAllocationRow,
    private: &PacketNativeStartupAllocationRow,
) -> Result<usize, ProviderError> {
    usize::try_from(
        native
            .requested_peak_data()?
            .max(private.requested_peak_data()?),
    )
    .map_err(|_| ProviderError::ResourceExhausted("native startup native extent"))
}

#[cfg(test)]
mod requote_tests {
    use super::*;
    use crucible_node_format::U64;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn asymmetric_private_parser_requote_does_not_redistribute_native_or_private_grants()
    -> TestResult {
        // The actual unchanged arbitrary parser constructs this data extent;
        // no permission/boot/preamble or fake successful Source is created.
        let raw = crate::retained_metadata::serialization_storage::original_json_value_storage_extent_data(168899)?;
        let parser = u64::try_from(raw.canonical_pass_requested_bytes()?)?;
        let native = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(4096),
            maximum_simultaneous_transient_bytes: U64::new(8192),
            declared_counter_scratch_bytes: U64::new(1024),
        };
        let private = PacketNativeStartupAllocationRow {
            retained_requested_bytes: U64::new(8192),
            maximum_simultaneous_transient_bytes: U64::new(parser),
            declared_counter_scratch_bytes: U64::new(1024),
        };
        assert!(native.requested_peak_data()? < parser);
        assert_eq!(
            u64::try_from(original_requote_maximum(&native, &private)?)?,
            private.requested_peak_data()?
        );
        native.authenticate_actual_data(&native)?;
        private.authenticate_actual_data(&private)?;
        // A generous DATA scan ceiling does not admit transferring one byte
        // of transient or retained grant from the other original row.
        let mut changed = native;
        changed.maximum_simultaneous_transient_bytes = U64::new(8193);
        assert!(native.authenticate_actual_data(&changed).is_err());
        changed = private;
        changed.retained_requested_bytes = U64::new(8193);
        assert!(private.authenticate_actual_data(&changed).is_err());
        changed.declared_counter_scratch_bytes = U64::new(0);
        assert!(original_requote_maximum(&native, &changed).is_err());
        Ok(())
    }
}

#[path = "bootstrap_invocation.rs"]
mod invocation;
