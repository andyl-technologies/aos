//! Encodes the validated closed ACK18 context without heap-backed JSON owners.
//!
//! Every string is a fixed ASCII schema, algorithm, decimal or base64 digest.
//! The defining field order below is JCS order, including the nested funding
//! object. General JSON escaping and dynamic object sorting are unnecessary.

use super::*;
use base64::Engine;
use std::mem::size_of;

// Nine unpadded base64(32) values, the fixed grammar and three independent
// twenty-digit U64 strings fit this bound. Row validation still rejects a sum
// overflow; the encoded upper does not replace that independent requirement.
const MAXIMUM_CONTEXT_BYTES: usize = 873;

pub(super) struct ContextBytes {
    bytes: [u8; MAXIMUM_CONTEXT_BYTES],
    length: usize,
}

impl ContextBytes {
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), ProviderError> {
        let end = self.length.checked_add(bytes.len()).ok_or_else(invalid)?;
        let destination = self.bytes.get_mut(self.length..end).ok_or_else(invalid)?;
        destination.copy_from_slice(bytes);
        self.length = end;
        Ok(())
    }

    fn digest(&mut self, bytes: &Bytes) -> Result<(), ProviderError> {
        let mut encoded = [0; 43];
        let length = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode_slice(bytes.as_slice(), &mut encoded)
            .map_err(|_| invalid())?;
        if length != encoded.len() {
            return Err(invalid());
        }
        self.append(&encoded)
    }

    fn decimal(&mut self, value: U64) -> Result<(), ProviderError> {
        let mut encoded = [0; 20];
        let mut remaining = value.get();
        let mut start = encoded.len();
        loop {
            start = start.checked_sub(1).ok_or_else(invalid)?;
            encoded[start] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        self.append(&encoded[start..])
    }
}

pub(super) fn context_bytes(
    context: &PacketNativeImport18BootstrapAckContext,
) -> Result<ContextBytes, ProviderError> {
    // Validate the entire context before treating any field as unescaped ASCII.
    context.validate_data()?;
    let PacketNativeImport18BootstrapAckContext {
        schema,
        algorithm,
        source_birth,
        kernel_binding,
        policy_binding,
        host_registration,
        native_registration,
        hello_request,
        hello_response,
        assigned_request,
        recipe_identity,
        initial_funding,
    } = context;
    let PacketNativeStartupAllocationRow {
        retained_requested_bytes,
        maximum_simultaneous_transient_bytes,
        declared_counter_scratch_bytes,
    } = initial_funding;

    let mut output = ContextBytes {
        bytes: [0; MAXIMUM_CONTEXT_BYTES],
        length: 0,
    };
    output.append(b"{\"algorithm\":\"")?;
    output.append(algorithm.as_bytes())?;
    output.append(b"\",\"assigned_request\":\"")?;
    output.digest(assigned_request)?;
    output.append(b"\",\"hello_request\":\"")?;
    output.digest(hello_request)?;
    output.append(b"\",\"hello_response\":\"")?;
    output.digest(hello_response)?;
    output.append(b"\",\"host_registration\":\"")?;
    output.digest(host_registration)?;
    output.append(b"\",\"initial_funding\":{\"declared_counter_scratch_bytes\":\"")?;
    output.decimal(*declared_counter_scratch_bytes)?;
    output.append(b"\",\"maximum_simultaneous_transient_bytes\":\"")?;
    output.decimal(*maximum_simultaneous_transient_bytes)?;
    output.append(b"\",\"retained_requested_bytes\":\"")?;
    output.decimal(*retained_requested_bytes)?;
    output.append(b"\"},\"kernel_binding\":\"")?;
    output.digest(kernel_binding)?;
    output.append(b"\",\"native_registration\":\"")?;
    output.digest(native_registration)?;
    output.append(b"\",\"policy_binding\":\"")?;
    output.digest(policy_binding)?;
    output.append(b"\",\"recipe_identity\":\"")?;
    output.digest(recipe_identity)?;
    output.append(b"\",\"schema\":\"")?;
    output.append(schema.as_bytes())?;
    output.append(b"\",\"source_birth\":\"")?;
    output.digest(source_birth)?;
    output.append(b"\"}")?;
    Ok(output)
}

/// Names the actual fixed output/return windows and every encoder control.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<ContextBytes>() * 2
        + size_of::<Result<ContextBytes, ProviderError>>()
        + size_of::<&ContextBytes>()
        + size_of::<&mut ContextBytes>()
        + size_of::<&PacketNativeImport18BootstrapAckContext>()
        + size_of::<&PacketNativeStartupAllocationRow>()
        + size_of::<&String>() * 2
        + size_of::<&Bytes>() * 9
        + size_of::<&U64>() * 3
        + size_of::<&[u8]>() * 2
        + size_of::<Option<&mut [u8]>>()
        + size_of::<&mut [u8]>()
        + size_of::<[u8; 43]>()
        + size_of::<[u8; 20]>()
        + size_of::<base64::engine::GeneralPurpose>()
        + size_of::<U64>()
        + size_of::<u64>()
        + size_of::<usize>() * 4
        + size_of::<Option<usize>>()
        + size_of::<std::ops::Range<usize>>()
        + size_of::<Result<usize, base64::EncodeSliceError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_fixed_output_boundary_preserves_written_prefix_on_refusal() {
        let mut output = ContextBytes {
            bytes: [0; MAXIMUM_CONTEXT_BYTES],
            length: 0,
        };
        output.append(&[b'x'; MAXIMUM_CONTEXT_BYTES]).unwrap();
        assert!(output.append(b"y").is_err());
        assert_eq!(output.as_slice(), &[b'x'; MAXIMUM_CONTEXT_BYTES]);
        output.append(b"").unwrap();
        assert_eq!(output.length, MAXIMUM_CONTEXT_BYTES);
    }
}
