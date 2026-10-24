//! Streams the closed launch6 wrapper while preserving the original launch bytes.
//!
//! Static object field order is UTF-16 lexicographic. All scalars are strings or
//! exact small integers, so this writer matches JCS without constructing a DOM,
//! sorting keys, allocating a byte bank or re-encoding the nested launch5 body.
//! The caller separately authenticates that original canonical launch bank.

use super::*;
use std::io::Write;

struct CanonicalHash<'a>(&'a HashData);
impl Serialize for CanonicalHash<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut f = serializer.serialize_struct("Hash", 3)?;
        f.serialize_field("algorithm", self.0.algorithm)?;
        f.serialize_field("digest", &self.0.digest)?;
        f.serialize_field("domain", &self.0.domain)?;
        f.end()
    }
}

struct CanonicalReference<'a>(&'a ReferenceData);
impl Serialize for CanonicalReference<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut f = serializer.serialize_struct("Reference", 3)?;
        f.serialize_field("hash", &CanonicalHash(&self.0.hash))?;
        f.serialize_field("length", &self.0.length)?;
        f.serialize_field("media_type", &self.0.media_type)?;
        f.end()
    }
}

struct CanonicalSource<'a>(&'a SourceData);
impl Serialize for CanonicalSource<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut f = serializer.serialize_struct("Source", 3)?;
        f.serialize_field("native_state", &CanonicalReference(&self.0.native_state))?;
        f.serialize_field("owner", &self.0.owner)?;
        f.serialize_field("runtime", &CanonicalReference(&self.0.runtime))?;
        f.end()
    }
}

struct CanonicalTarget<'a>(&'a TargetData);
impl Serialize for CanonicalTarget<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut f = serializer.serialize_struct("Target", 9)?;
        f.serialize_field("admission", &self.0.admission)?;
        f.serialize_field("binding", &CanonicalHash(&self.0.binding))?;
        f.serialize_field("incarnation", &self.0.incarnation)?;
        f.serialize_field("node", &self.0.node)?;
        f.serialize_field("owner", &self.0.owner)?;
        f.serialize_field("owner_generation", &self.0.owner_generation)?;
        f.serialize_field("prepared_token", &self.0.prepared_token)?;
        f.serialize_field("session", &self.0.session)?;
        f.serialize_field("world", &CanonicalHash(&self.0.world))?;
        f.end()
    }
}

pub(super) struct CanonicalPurpose<'a>(pub(super) &'a PacketNativeInvocationPurposeData);
impl Serialize for CanonicalPurpose<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut f = serializer.serialize_struct("Purpose", 4)?;
        match &self.0.purpose {
            None => f.serialize_field("purpose", "original_execution")?,
            Some(_) => f.serialize_field("purpose", "restoration_target")?,
        }
        f.serialize_field("schema", SCHEMA)?;
        match &self.0.purpose {
            None => f.serialize_field("source", &Option::<CanonicalSource<'_>>::None)?,
            Some(source) => f.serialize_field("source", &Some(CanonicalSource(source)))?,
        }
        f.serialize_field("target", &CanonicalTarget(&self.0.target))?;
        f.end()
    }
}

/// Retains the exact streamed length and raw BLAKE3 identity of one launch6 literal.
///
/// These fields are DATA, not a writer owner, Source member or native admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNativeInvocationLaunchIdentityData {
    /// Counts the full wrapper and the unchanged nested original launch bytes.
    pub encoded_bytes: usize,
    /// Hashes the exact original wrapper without a replacement encoding.
    pub raw_digest: [u8; 32],
}

struct Identity {
    bytes: usize,
    hasher: blake3::Hasher,
}

impl Write for Identity {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        self.hasher.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const LAUNCH_SUFFIX: &[u8] = b",\"schema_version\":6}";

fn write_launch_prefix(
    purpose: &PacketNativeInvocationPurposeData,
    output: &mut impl Write,
) -> Result<(), ProviderError> {
    output.write_all(b"{\"invocation\":")?;
    serde_json::to_writer(&mut *output, &CanonicalPurpose(purpose))
        .map_err(crucible_node_format::ContractError::from)?;
    output.write_all(b",\"launch\":")?;
    Ok(())
}

struct Extent(usize);

impl Write for Extent {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::OutOfMemory))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Counts the actual closed wrapper around an independently measured bank extent.
///
/// This executes the same defining prefix serializer as the real-bank writer.
/// The nested extent is DATA from the caller's genuine canonical occurrence
/// calculation; it is not a cap, digest, bank, hash or native admission.
///
/// # Errors
/// Refuses the same prefix serialization failure or checked complete overflow.
pub fn original_native_invocation_launch_extent_data(
    purpose: &PacketNativeInvocationPurposeData,
    canonical_launch5_bytes: usize,
) -> Result<usize, ProviderError> {
    let mut output = Extent(0);
    write_launch_prefix(purpose, &mut output)?;
    output
        .0
        .checked_add(canonical_launch5_bytes)
        .and_then(|bytes| bytes.checked_add(LAUNCH_SUFFIX.len()))
        .ok_or_else(invalid)
}

/// Streams the unchanged canonical invocation purpose without constructing a DOM.
///
/// This borrowed writer creates DATA only; its caller authenticates the actual
/// Source member, input provenance and separately admitted output ownership.
///
/// # Errors
/// Propagates writer or closed fixed-view serialization failure.
pub fn write_original_native_invocation_purpose_data(
    purpose: &PacketNativeInvocationPurposeData,
    output: &mut impl Write,
) -> Result<(), ProviderError> {
    serde_json::to_writer(output, &CanonicalPurpose(purpose))
        .map_err(crucible_node_format::ContractError::from)?;
    Ok(())
}

/// Streams the exact new wrapper around an independently authenticated original bank.
///
/// The caller retains both raw input and partially written output through any
/// error. No parser, cloned launch, native permission or allocator bank is made.
///
/// # Errors
/// Refuses writer failure or a serialization failure in the closed fixed view.
pub fn write_original_native_invocation_launch_data(
    purpose: &PacketNativeInvocationPurposeData,
    canonical_launch5: &[u8],
    output: &mut impl Write,
) -> Result<(), ProviderError> {
    write_launch_prefix(purpose, output)?;
    output.write_all(canonical_launch5)?;
    output.write_all(LAUNCH_SUFFIX)?;
    Ok(())
}

/// Counts and hashes the exact wrapper without a DOM or output bank.
///
/// # Errors
/// Refuses checked extent overflow or a closed serialization failure.
pub fn original_native_invocation_launch_identity_data(
    purpose: &PacketNativeInvocationPurposeData,
    canonical_launch5: &[u8],
) -> Result<PacketNativeInvocationLaunchIdentityData, ProviderError> {
    let mut output = Identity {
        bytes: 0,
        hasher: blake3::Hasher::new(),
    };
    write_original_native_invocation_launch_data(purpose, canonical_launch5, &mut output)?;
    Ok(PacketNativeInvocationLaunchIdentityData {
        encoded_bytes: output.bytes,
        raw_digest: *output.hasher.finalize().as_bytes(),
    })
}

/// Names the actual shared fixed writer and extent-control headers.
///
/// Original input/output banks, recursive frames and caller admission remain
/// independent; these fixed headers do not provide native authority.
pub const fn counter_scratch_data() -> usize {
    std::mem::size_of::<Identity>()
        + std::mem::size_of::<PacketNativeInvocationLaunchIdentityData>()
        + std::mem::size_of::<CanonicalPurpose<'static>>()
        + std::mem::size_of::<CanonicalTarget<'static>>()
        + std::mem::size_of::<CanonicalSource<'static>>()
        + std::mem::size_of::<CanonicalReference<'static>>()
        + std::mem::size_of::<CanonicalHash<'static>>()
        + std::mem::size_of::<Result<(), serde_json::Error>>()
        + std::mem::size_of::<Result<(), crucible_node_format::ContractError>>()
        + std::mem::size_of::<Result<(), ProviderError>>()
        + std::mem::size_of::<Extent>()
        + std::mem::size_of::<Result<usize, ProviderError>>()
        + std::mem::size_of::<Result<(), ProviderError>>() // shared prefix return
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_format::canonical;
    use serde_json::json;

    fn purposes() -> [PacketNativeInvocationPurposeData; 2] {
        let runtime =
            canonical::content_ref(b"runtime", "application/runtime;note=\"quoted\"").unwrap();
        let native = canonical::content_ref(b"native", "application/native;note=\\path").unwrap();
        let target = super::super::tests::target();
        [
            PacketNativeInvocationPurposeData {
                target,
                purpose: None,
            },
            PacketNativeInvocationPurposeData {
                target,
                purpose: Some(SourceData {
                    runtime: ReferenceData::original(&runtime).unwrap(),
                    native_state: ReferenceData::original(&native).unwrap(),
                    owner: target.owner,
                }),
            },
        ]
    }

    #[test]
    fn streamed_wrapper_and_identity_match_authoritative_jcs_with_complete_reference_escaping() {
        // This nested bank is canonical DATA, deliberately not a native launch
        // admission fixture. No reader, ticket or Source permission is created.
        let nested = json!({"schema_version":5,"opaque":[null, {}, "x\n\\\""]});
        let bytes = canonical::canonical_json(&nested).unwrap();
        let mut previous = None;
        for purpose in purposes() {
            let expected = canonical::canonical_json(
                &json!({"schema_version":6,"invocation":purpose,"launch":nested}),
            )
            .unwrap();
            let mut actual = Vec::new();
            write_original_native_invocation_launch_data(&purpose, &bytes, &mut actual).unwrap();
            let identity =
                original_native_invocation_launch_identity_data(&purpose, &bytes).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(identity.encoded_bytes, actual.len());
            assert_eq!(identity.raw_digest, *blake3::hash(&actual).as_bytes());
            if let Some(previous) = previous {
                assert_ne!(identity, previous);
            }
            previous = Some(identity);
        }
    }

    #[test]
    fn refused_writer_retains_the_exact_original_prefix_without_reencoding_or_retry() {
        struct Prefix {
            bytes: Vec<u8>,
            maximum: usize,
        }
        impl Write for Prefix {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let take = bytes.len().min(self.maximum - self.bytes.len());
                self.bytes.extend_from_slice(&bytes[..take]);
                Ok(take)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let purpose = purposes()[1];
        let nested = b"{\"schema_version\":5}";
        let mut full = Vec::new();
        write_original_native_invocation_launch_data(&purpose, nested, &mut full).unwrap();
        for maximum in [0, 1, 14, full.len() - 1] {
            let mut output = Prefix {
                bytes: Vec::new(),
                maximum,
            };
            assert!(
                write_original_native_invocation_launch_data(&purpose, nested, &mut output)
                    .is_err()
            );
            assert_eq!(output.bytes, full[..maximum]);
        }
    }
}

#[cfg(test)]
mod extent_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn real_writer_identity_and_shape_extent_agree_without_placeholder_bytes() -> TestResult {
        let target = super::super::tests::target();
        for purpose in [
            PacketNativeInvocationPurposeData {
                target,
                purpose: None,
            },
            PacketNativeInvocationPurposeData {
                target,
                purpose: Some(SourceData {
                    runtime: ReferenceData::original(
                        &crucible_node_format::canonical::content_ref(
                            b"runtime",
                            "application/runtime;quote=\\\"x\\\"",
                        )?,
                    )?,
                    native_state: ReferenceData::original(
                        &crucible_node_format::canonical::content_ref(
                            b"native",
                            "application/native;path=\\\\x",
                        )?,
                    )?,
                    owner: target.owner,
                }),
            },
        ] {
            for bank in [b"{}".as_slice(), br#"{"opaque":["same",1.0]}"#] {
                let mut actual = Vec::new();
                write_original_native_invocation_launch_data(&purpose, bank, &mut actual)?;
                let identity = original_native_invocation_launch_identity_data(&purpose, bank)?;
                let extent = original_native_invocation_launch_extent_data(&purpose, bank.len())?;
                assert_eq!(extent, actual.len());
                assert_eq!(identity.encoded_bytes, extent);
                assert_eq!(identity.raw_digest, *blake3::hash(&actual).as_bytes());
            }
            assert!(original_native_invocation_launch_extent_data(&purpose, usize::MAX).is_err());
        }
        Ok(())
    }
}
