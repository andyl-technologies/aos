//! Closed canonical response-byte wire facts and original-operation validation.
//!
//! This modeled native Query reply distinguishes binary output facts from an
//! uncertain original-request input echo. Its qualification fields remain false:
//!
//! ```json
//! {"return":{"schema-version":1,"payload-kind":"native-query","components":7,
//!   "kernel-capability":41002,"native-abi-size":4264,"maximum-data-bytes":4096,
//!   "clock-edition":3,"clock-components":159,
//!   "qemu-build-id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
//!   "qemu-source-hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
//!   "record-index":2,"vcpu-index":0,"native-vcpu-id":0,"generation":3,"invocation":4,
//!   "operation-id":0,"expected-sequence":0,"expected-revision":0,"pending-sequence":5,
//!   "consumed-sequence":4,"revision":6,"native-phase":1,"callback-result":0,
//!   "native-errno":0,"reason":6,"address":4096,"data-offset":0,"length":4,
//!   "count":0,"size":0,"direction":1,"data-length":4,"data-base64":"AAEC/w==",
//!   "result-known":true,"uncertain-effects":false,"opaque-effects":false,
//!   "kernel-source-qualified":false,"device-closure":false,"input-custody":false,
//!   "output-custody":false,"profile-qualified":false}}
//! ```

use super::{QmpError, QmpKvmResponseBytesOperation, QmpKvmResponseBytesRequest, malformed};
use serde::{Deserialize, Serialize};

/// Preserves native evidence independently from uncertain original input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QmpKvmResponseBytesPayloadKind {
    /// Contains an authenticated current native Query fragment.
    NativeQuery,
    /// Contains the authenticated original native completion result.
    NativeResult,
    /// Contains the retained original request after an unknown native result.
    OriginalRequest,
}

/// Copies original byte facts without granting execution or preservation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmResponseBytesObservation {
    /// Identifies the independent canonical byte schema, exactly one.
    pub schema_version: u32,
    /// Distinguishes current native facts, native result and original input echo.
    pub payload_kind: QmpKvmResponseBytesPayloadKind,
    /// Identifies the partial producer/input/cache bitmap, exactly seven.
    pub components: u32,
    /// Identifies the required native response-byte capability, 0xa02a.
    pub kernel_capability: u32,
    /// Identifies the exact native packet size, 4264 bytes.
    pub native_abi_size: u32,
    /// Identifies the native private byte capacity, 4096.
    pub maximum_data_bytes: u32,
    /// Identifies the required ARM two or x86 three clock edition.
    pub clock_edition: u32,
    /// Identifies the exact corresponding partial clock component bitmap.
    pub clock_components: u32,
    /// Retains the declared compiled userspace build identity.
    pub qemu_build_id: String,
    /// Retains the declared compiled userspace atomic patch identity.
    pub qemu_source_hash: String,
    /// Identifies the original lifetime RUN-return row.
    pub record_index: u32,
    /// Identifies the original fixed QEMU roster position.
    pub vcpu_index: u32,
    /// Identifies a native result owner; request echoes retain native zero.
    pub native_vcpu_id: u32,
    /// Identifies the original retained closed clock generation.
    pub generation: u64,
    /// Identifies the actual native invocation; zero in an input echo.
    pub invocation: u64,
    /// Identifies the original completion; zero for Query.
    pub operation_id: u64,
    /// Identifies the original admitted fragment; zero for Query.
    pub expected_sequence: u64,
    /// Identifies the original admitted native revision; zero for Query.
    pub expected_revision: u64,
    /// Identifies a native pending fragment; zero in an input echo.
    pub pending_sequence: u64,
    /// Identifies native consumption; zero in an input echo.
    pub consumed_sequence: u64,
    /// Identifies the actual native response revision; zero in an input echo.
    pub revision: u64,
    /// Retains the native phase or explicit unknown classification for input.
    pub native_phase: u32,
    /// Retains the actual signed kernel result; zero in an input echo.
    pub callback_result: i32,
    /// Retains the failed native ioctl errno; zero for authenticated results.
    pub native_errno: i32,
    /// Identifies the canonical original PIO or MMIO exit reason.
    pub reason: u32,
    /// Retains the original canonical port or guest physical address.
    pub address: u64,
    /// Retains the checked original mapped PIO offset, never a pointer.
    pub data_offset: u64,
    /// Retains the canonical MMIO length; zero for PIO.
    pub length: u32,
    /// Retains the canonical PIO repetition count; zero for MMIO.
    pub count: u32,
    /// Retains the canonical PIO element size; zero for MMIO.
    pub size: u32,
    /// Retains the original read zero or write one direction.
    pub direction: u32,
    /// Identifies the actual returned native or echoed input byte count.
    pub data_length: u32,
    /// Retains bounded canonical base64 without whitespace or alternate padding.
    pub data_base64: String,
    /// Distinguishes actual native facts from an uncertain original input echo.
    pub result_known: bool,
    /// Retains native owner or original transport effect uncertainty.
    pub uncertain_effects: bool,
    /// Retains the original owner opacity.
    pub opaque_effects: bool,
    /// Remains false because userspace declarations do not qualify the kernel.
    pub kernel_source_qualified: bool,
    /// Remains false because device and DMA closure is absent.
    pub device_closure: bool,
    /// Remains false because no common input cut is authenticated.
    pub input_custody: bool,
    /// Remains false because common output custody is absent.
    pub output_custody: bool,
    /// Remains false because this partial mechanism cannot qualify a node.
    pub profile_qualified: bool,
}

pub(super) fn validate(
    request: &QmpKvmResponseBytesRequest,
    observed: &QmpKvmResponseBytesObservation,
) -> Result<(), QmpError> {
    let compatible_clock = matches!(
        (observed.clock_edition, observed.clock_components),
        (2, 228) | (3, 159)
    );
    let source_id = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if observed.schema_version != 1
        || observed.components != 7
        || observed.kernel_capability != 0xa02a
        || observed.native_abi_size != 4264
        || observed.maximum_data_bytes != 4096
        || !compatible_clock
        || !source_id(&observed.qemu_build_id)
        || !source_id(&observed.qemu_source_hash)
        || observed.record_index != request.record_index
        || observed.generation != request.generation
        || observed.vcpu_index >= 4096
        || observed.operation_id != request.operation_id
        || observed.expected_sequence != request.expected_sequence
        || observed.native_phase > 5
        || observed.data_length > 4096
        || observed.consumed_sequence > observed.pending_sequence
        || observed.kernel_source_qualified
        || observed.device_closure
        || observed.input_custody
        || observed.output_custody
        || observed.profile_qualified
    {
        return Err(malformed(
            "canonical bytes changed compatibility, original scope or closure",
        ));
    }

    match observed.payload_kind {
        QmpKvmResponseBytesPayloadKind::NativeQuery => {
            if request.operation != QmpKvmResponseBytesOperation::Query
                || !observed.result_known
                || observed.invocation != request.expected_invocation
                || observed.expected_revision != 0
                || observed.native_errno != 0
            {
                return Err(malformed(
                    "canonical Query cannot contain original input or completion facts",
                ));
            }
        }
        QmpKvmResponseBytesPayloadKind::NativeResult => {
            if request.operation != QmpKvmResponseBytesOperation::Complete
                || !observed.result_known
                || observed.invocation != request.expected_invocation
                || observed.native_errno != 0
                || observed.expected_revision == 0
                || observed.expected_revision > u64::MAX - 2
            {
                return Err(malformed(
                    "canonical completion requires its original native result",
                ));
            }
            validate_result(request, observed)?;
        }
        QmpKvmResponseBytesPayloadKind::OriginalRequest => {
            // The source echoes its zero-initialized original input packet.
            // These zero native fields are not assertions about the live owner.
            if request.operation != QmpKvmResponseBytesOperation::Complete
                || observed.result_known
                || !observed.uncertain_effects
                || observed.native_errno <= 0
                || observed.native_phase != 4
                || observed.expected_revision == 0
                || observed.expected_revision > u64::MAX - 2
                || observed.invocation != 0
                || observed.native_vcpu_id != 0
                || observed.pending_sequence != 0
                || observed.consumed_sequence != 0
                || observed.revision != 0
                || observed.callback_result != 0
            {
                return Err(malformed(
                    "unknown original input cannot establish native result facts",
                ));
            }
        }
    }
    Ok(())
}

fn validate_result(
    request: &QmpKvmResponseBytesRequest,
    observed: &QmpKvmResponseBytesObservation,
) -> Result<(), QmpError> {
    if observed.callback_result < 0 {
        if observed.native_phase != 4
            || !observed.uncertain_effects
            || observed.pending_sequence != request.expected_sequence
            || observed.consumed_sequence >= request.expected_sequence
            || observed.revision != observed.expected_revision + 1
        {
            return Err(malformed(
                "negative completion changed original retained uncertainty",
            ));
        }
        return Ok(());
    }

    let completed = match observed.native_phase {
        2 => {
            observed.pending_sequence == request.expected_sequence + 1
                && observed.revision == observed.expected_revision + 2
        }
        3 => {
            observed.pending_sequence == request.expected_sequence
                && observed.revision == observed.expected_revision + 1
        }
        _ => false,
    };
    if !completed || observed.consumed_sequence != request.expected_sequence {
        return Err(malformed(
            "completion changed original sequence or native revision",
        ));
    }
    Ok(())
}
