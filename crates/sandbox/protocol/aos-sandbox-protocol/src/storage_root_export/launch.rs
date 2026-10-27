//! Borrowed framing for an original, signed Host launch root export.
//!
//! This envelope preserves the complete original Host Apply body and all four
//! original authorization artifacts. Framing does not validate their contents,
//! verify signatures, admit a Host request, or lend a Storage operation. The
//! actual receiver must make those checks under its retained native owners
//! before invoking the existing catalog and mount-export engine.
//!
//! ```text
//! AOSRME02 | version:u16be=2 | reserved:u16be=0 | AOSRME01[318]
//!          | body_len:u32be | plan_len:u32be | plan_signature_len:u32be
//!          | lease_len:u32be | lease_signature_len:u32be
//!          | original_apply | plan | plan_signature | lease | lease_signature
//! ```

mod receiving;
pub use receiving::decoding_receiving_bytes_v2;

use sha2::{Digest as _, Sha256};

use super::{
    STORAGE_ROOT_EXPORT_REQUEST_BYTES_V1, StorageRootExportProtocolErrorV1,
    StorageRootExportRequestV1,
};
use crate::MAXIMUM_REQUEST_BYTES;
use crate::session::{
    AuthorizationArtifactBytes, MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES,
    MAXIMUM_BROKER_PLAN_BYTES, MAXIMUM_OWNERSHIP_LEASE_BYTES,
};

const MAGIC: &[u8; 8] = b"AOSRME02";
const VERSION: u16 = 2;
const DOMAIN: &[u8] = b"aos.sandbox.storage.root-launch-export.v2\0";
const REQUEST_END: usize = 12 + STORAGE_ROOT_EXPORT_REQUEST_BYTES_V1;

/// Counts the fixed framing before the five original byte strings.
pub const STORAGE_ROOT_LAUNCH_EXPORT_PREFIX_BYTES_V2: usize = REQUEST_END + 5 * 4;

/// Bounds the original admitted packet bytes plus this fixed forwarding prefix.
///
/// Keeping the fixed overhead separate preserves every original Host request
/// accepted beneath the existing Session packet ceiling.
pub const STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2: usize =
    MAXIMUM_REQUEST_BYTES + STORAGE_ROOT_LAUNCH_EXPORT_PREFIX_BYTES_V2;

/// Borrows the complete original launch inputs without admitting an export.
///
/// The embedded request carries the original launch cutoff. This codec neither
/// derives a new timeout nor extends that cutoff. A successful decode only
/// establishes canonical framing, exact proof grammar, and transport bounds.
#[derive(Clone, Copy, Debug)]
pub struct StorageRootLaunchExportRequestV2<'wire> {
    request: StorageRootExportRequestV1,
    original_apply: &'wire [u8],
    authorization: AuthorizationArtifactBytes<'wire>,
    encoded_bytes: usize,
    request_bytes: [u8; STORAGE_ROOT_EXPORT_REQUEST_BYTES_V1],
    segment_lengths: [u32; 5],
}

impl<'wire> StorageRootLaunchExportRequestV2<'wire> {
    /// Frames the exact original Apply body and its original artifact quartet.
    ///
    /// # Errors
    ///
    /// Rejects invalid proof/nonce/cutoff, empty segments, or existing transport
    /// and artifact bounds being exceeded. Artifact validity and trust remain
    /// obligations of the real admitted sender and independently checked receiver.
    pub fn new(
        request: StorageRootExportRequestV1,
        original_apply: &'wire [u8],
        authorization: AuthorizationArtifactBytes<'wire>,
    ) -> Result<Self, StorageRootExportProtocolErrorV1> {
        let request_bytes = request.encode()?;
        let segments = segments(original_apply, authorization);
        let caps = [
            MAXIMUM_REQUEST_BYTES,
            MAXIMUM_BROKER_PLAN_BYTES,
            MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES,
            MAXIMUM_OWNERSHIP_LEASE_BYTES,
            MAXIMUM_AUTHORIZATION_SIGNATURE_BYTES,
        ];
        let mut encoded_bytes = STORAGE_ROOT_LAUNCH_EXPORT_PREFIX_BYTES_V2;
        let mut segment_lengths = [0; 5];
        for (index, (segment, cap)) in segments.into_iter().zip(caps).enumerate() {
            if segment.is_empty() || segment.len() > cap {
                return Err(StorageRootExportProtocolErrorV1);
            }
            segment_lengths[index] = u32::try_from(segment.len())
                .map_err(|_| StorageRootExportProtocolErrorV1)?;
            encoded_bytes = encoded_bytes.checked_add(segment.len())
                .ok_or(StorageRootExportProtocolErrorV1)?;
        }
        if encoded_bytes > STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2 {
            return Err(StorageRootExportProtocolErrorV1);
        }
        Ok(Self {
            request,
            original_apply,
            authorization,
            encoded_bytes,
            request_bytes,
            segment_lengths,
        })
    }

    /// Decodes bounded framing while borrowing every original segment.
    ///
    /// # Errors
    ///
    /// Rejects truncation, trailing bytes, wrong version or reserved fields,
    /// invalid embedded proof, empty segments, and oversized announced lengths.
    /// No model parser or signature verifier runs during this framing step.
    pub fn decode(bytes: &'wire [u8]) -> Result<Self, StorageRootExportProtocolErrorV1> {
        if bytes.len() < STORAGE_ROOT_LAUNCH_EXPORT_PREFIX_BYTES_V2
            || bytes.len() > STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2
            || &bytes[..8] != MAGIC
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[10..12] != [0; 2]
        {
            return Err(StorageRootExportProtocolErrorV1);
        }
        let request = StorageRootExportRequestV1::decode(&bytes[12..REQUEST_END])?;
        let mut offset = STORAGE_ROOT_LAUNCH_EXPORT_PREFIX_BYTES_V2;
        let mut parts = [&[][..]; 5];
        for (index, part) in parts.iter_mut().enumerate() {
            let length = u32::from_be_bytes(super::read_array(bytes, REQUEST_END + index * 4)?);
            let length = usize::try_from(length).map_err(|_| StorageRootExportProtocolErrorV1)?;
            let end = offset.checked_add(length).ok_or(StorageRootExportProtocolErrorV1)?;
            *part = bytes.get(offset..end).ok_or(StorageRootExportProtocolErrorV1)?;
            offset = end;
        }
        if offset != bytes.len() {
            return Err(StorageRootExportProtocolErrorV1);
        }
        Self::new(request, parts[0], AuthorizationArtifactBytes {
            broker_plan: parts[1],
            broker_plan_signature: parts[2],
            ownership_lease: parts[3],
            ownership_lease_signature: parts[4],
        })
    }

    /// Returns the original nonce, cutoff and exact publication proof DATA.
    #[must_use]
    pub const fn request(&self) -> &StorageRootExportRequestV1 {
        &self.request
    }

    /// Borrows the original canonical Host Apply bytes carried by the sender.
    #[must_use]
    pub const fn original_apply(&self) -> &'wire [u8] {
        self.original_apply
    }

    /// Borrows all four original, still-untrusted authorization artifacts.
    #[must_use]
    pub const fn authorization(&self) -> AuthorizationArtifactBytes<'wire> {
        self.authorization
    }

    /// Returns the complete frame size before the caller allocates its buffer.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        self.encoded_bytes
    }

    /// Encodes the complete bounded frame without changing its original inputs.
    ///
    /// Allocation requires the caller's genuine receiving or sending allowance;
    /// the returned bytes do not establish admission or resource funding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_bytes);
        bytes.extend_from_slice(&self.prefix());
        for segment in segments(self.original_apply, self.authorization) {
            bytes.extend_from_slice(segment);
        }
        bytes
    }

    /// Commits to the complete frame under the distinct launch-export domain.
    ///
    /// The digest permits reuse of the existing descriptor response grammar;
    /// it neither authenticates the sender nor proves a physical mount exists.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.prefix());
        for segment in segments(self.original_apply, self.authorization) {
            hasher.update(segment);
        }
        hasher.finalize().into()
    }

    fn prefix(&self) -> [u8; STORAGE_ROOT_LAUNCH_EXPORT_PREFIX_BYTES_V2] {
        let mut bytes = [0; STORAGE_ROOT_LAUNCH_EXPORT_PREFIX_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
        bytes[12..REQUEST_END].copy_from_slice(&self.request_bytes);
        for (index, length) in self.segment_lengths.into_iter().enumerate() {
            let offset = REQUEST_END + index * 4;
            bytes[offset..offset + 4].copy_from_slice(&length.to_be_bytes());
        }
        bytes
    }
}

fn segments<'wire>(
    original_apply: &'wire [u8],
    authorization: AuthorizationArtifactBytes<'wire>,
) -> [&'wire [u8]; 5] {
    [original_apply, authorization.broker_plan, authorization.broker_plan_signature,
        authorization.ownership_lease, authorization.ownership_lease_signature]
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_guest_protocol::guest_root_publication::GuestRootPublicationProofV1;

    fn request() -> StorageRootExportRequestV1 {
        StorageRootExportRequestV1 {
            nonce: [1; 32],
            deadline_boottime_nanoseconds: 42,
            proof: GuestRootPublicationProofV1 {
                sandbox: [2; 16],
                incarnation: [3; 16],
                assignment_epoch: 4,
                assignment_digest: [5; 32],
                creation_operation: [6; 16],
                workspace_handle: [7; 32],
                dataset_guid: 8,
                root_image_digest: [9; 32],
                package_binding: [10; 32],
                root_tree_digest: [11; 32],
                feature_mask: aos_sandbox_guest_protocol::guest_root_publication::CONCRETE_GUEST_FEATURE_MASK_V1,
            },
        }
    }

    fn authorization<'a>(parts: &'a [&'a [u8]; 4]) -> AuthorizationArtifactBytes<'a> {
        AuthorizationArtifactBytes {
            broker_plan: parts[0],
            broker_plan_signature: parts[1],
            ownership_lease: parts[2],
            ownership_lease_signature: parts[3],
        }
    }

    #[test]
    fn retains_exact_original_bytes_and_distinct_response_digest() {
        // Deliberately opaque bytes test framing only, never signed admission.
        let parts: [&[u8]; 4] = [b"plan", b"plan-signature", b"lease", b"lease-signature"];
        let frame = StorageRootLaunchExportRequestV2::new(request(), b"original-apply",
            authorization(&parts)).unwrap();
        let bytes = frame.encode();
        let decoded = StorageRootLaunchExportRequestV2::decode(&bytes).unwrap();

        assert_eq!(bytes.len(), frame.encoded_len());
        assert_eq!(decoded.request(), &request());
        assert_eq!(decoded.original_apply(), b"original-apply");
        assert_eq!(decoded.authorization().broker_plan, parts[0]);
        assert_eq!(decoded.authorization().broker_plan_signature, parts[1]);
        assert_eq!(decoded.authorization().ownership_lease, parts[2]);
        assert_eq!(decoded.authorization().ownership_lease_signature, parts[3]);
        assert_eq!(decoded.encode(), bytes);
        assert_eq!(decoded.digest(), frame.digest());
        assert_ne!(decoded.digest(), request().digest().unwrap());
        assert!(StorageRootExportRequestV1::decode(&bytes).is_err());

        let mut changed = bytes.clone();
        changed[STORAGE_ROOT_LAUNCH_EXPORT_PREFIX_BYTES_V2] ^= 1;
        assert_ne!(StorageRootLaunchExportRequestV2::decode(&changed).unwrap().digest(), frame.digest());
    }

    #[test]
    fn fixed_forwarding_overhead_does_not_reduce_the_original_packet_ceiling() {
        let parts: [&[u8]; 4] = [b"p", b"s", b"l", b"t"];
        let original_body = vec![1; MAXIMUM_REQUEST_BYTES - 4];
        let frame = StorageRootLaunchExportRequestV2::new(request(), &original_body,
            authorization(&parts)).unwrap();

        assert_eq!(frame.encoded_len(), STORAGE_ROOT_LAUNCH_EXPORT_MAXIMUM_BYTES_V2);
        let oversized_body = vec![1; MAXIMUM_REQUEST_BYTES - 3];
        assert!(StorageRootLaunchExportRequestV2::new(request(), &oversized_body,
            authorization(&parts)).is_err());
    }

    #[test]
    fn refuses_length_smuggling_and_cross_version_framing() {
        let parts: [&[u8]; 4] = [b"p", b"s", b"l", b"t"];
        let frame = StorageRootLaunchExportRequestV2::new(request(), b"a", authorization(&parts)).unwrap();
        let bytes = frame.encode();

        let mut truncated_segment = bytes.clone();
        truncated_segment[REQUEST_END..REQUEST_END + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(StorageRootLaunchExportRequestV2::decode(&truncated_segment).is_err());

        let mut empty_plan = bytes.clone();
        empty_plan[REQUEST_END + 4..REQUEST_END + 8].fill(0);
        assert!(StorageRootLaunchExportRequestV2::decode(&empty_plan).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(StorageRootLaunchExportRequestV2::decode(&trailing).is_err());

        let mut reserved = bytes.clone();
        reserved[10] = 1;
        assert!(StorageRootLaunchExportRequestV2::decode(&reserved).is_err());
        assert!(StorageRootLaunchExportRequestV2::decode(&request().encode().unwrap()).is_err());
    }
}
