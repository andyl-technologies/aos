//! Source-local original native execution-input comparison data.
//!
//! The fixed frame commits Source's selected inputs, not Root's Mount plan,
//! lease or independent observation of Source file custody. A decoder supplies
//! no Session, currentness, signing permission, physical floor or effect grant.
//!
//! ```text
//! AOSNEM01 | version:u16be=1 | profile:u16be=1 | reserved[4]=0 |
//! full-scope[224] | provider[16] | holder[16] | session[32] |
//! attempt[32] | acquisition[32] | effect[16] | normalized-intent[32] |
//! kernel-coupled:u8=0 | reserved[7]=0 | backend[32] |
//! RootPrepared[32] | signed-publication[32] | held-catalog[32] |
//! logical-binding[32] | backend-enrollment[32] | dedicated-enrollment[32]
//! ```

use aos_sandbox_core::ObjectDigest;

use super::codec::{Reader, digest, invalid, nonzero};
use super::{NativeHeldScopeV1, Result};

const MAGIC: &[u8; 8] = b"AOSNEM01";
const PROFILE: u16 = 1;
const DOMAIN: &[u8] = b"aos.sandbox.source-provider.native-selected-execution-input.v1\0";

/// Bounds the complete canonical Source-local selected-input frame.
pub const SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1: usize = 648;

/// Supplies untrusted original-input fields for structural comparison only.
///
/// The actual Source owner must derive these from its resident original pair,
/// Applying plan, selected catalog and protected enrollment files. Passing
/// these fields to the codec does not authenticate their origin.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceSelectedNativeExecutionInputFieldsV1 {
    /// Correlates the exact full original flight, never a recovery Session.
    pub scope: NativeHeldScopeV1,
    /// Names the original plan's provider authority.
    pub provider_id: [u8; 16],
    /// Names the original plan's holder authority.
    pub holder_id: [u8; 16],
    /// Equals the full scope's original Source Session binding.
    pub session_binding: ObjectDigest,
    /// Equals the full scope's original provider attempt.
    pub attempt_digest: ObjectDigest,
    /// Equals the full scope's original provider acquisition.
    pub acquisition_id: ObjectDigest,
    /// Names the original Applying plan's effect identity.
    pub effect_id: [u8; 16],
    /// Commits the complete normalized original acquisition intent.
    pub normalized_intent_digest: ObjectDigest,
    /// Must be false for this closed non-kernel native profile.
    pub kernel_coupled: bool,
    /// Names the original Applying plan's native dispatch backend.
    pub backend_id: [u8; 32],
    /// Uses the existing digest of the original signed RootPrepared control.
    pub root_prepared: ObjectDigest,
    /// Uses SHA-256 of all original canonical signed publication bytes.
    pub publication: ObjectDigest,
    /// Uses the existing domain-separated full AOSPCZ01 catalog digest.
    pub catalog: ObjectDigest,
    /// Selects the unique original logical binding in that complete catalog.
    pub binding: ObjectDigest,
    /// Uses SHA-256 of the exact original 928-byte AOSSPBV1 image.
    pub backend_enrollment: ObjectDigest,
    /// Uses SHA-256 of the exact original 160-byte AOSZHV01 image.
    pub dedicated_enrollment: ObjectDigest,
}

/// Retains one canonical nonauthorizing Source-local selected-input frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceSelectedNativeExecutionInputDataV1 {
    fields: SourceSelectedNativeExecutionInputFieldsV1,
    canonical: [u8; SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1],
}

impl SourceSelectedNativeExecutionInputDataV1 {
    /// Encodes a structurally valid original-input claim without authenticating it.
    ///
    /// # Errors
    ///
    /// Rejects malformed full scope, sentinel identities or commitments,
    /// kernel-coupled input and mismatched plan/scope correlation.
    pub fn new(fields: SourceSelectedNativeExecutionInputFieldsV1) -> Result<Self> {
        validate_fields(&fields)?;
        let mut canonical = [0; SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1];
        canonical[..8].copy_from_slice(MAGIC);
        canonical[8..10].copy_from_slice(&1_u16.to_be_bytes());
        canonical[10..12].copy_from_slice(&PROFILE.to_be_bytes());
        canonical[16..240].copy_from_slice(&fields.scope.to_canonical_bytes());

        canonical[240..256].copy_from_slice(&fields.provider_id);
        canonical[256..272].copy_from_slice(&fields.holder_id);
        canonical[272..304].copy_from_slice(fields.session_binding.as_bytes());
        canonical[304..336].copy_from_slice(fields.attempt_digest.as_bytes());
        canonical[336..368].copy_from_slice(fields.acquisition_id.as_bytes());
        canonical[368..384].copy_from_slice(&fields.effect_id);
        canonical[384..416].copy_from_slice(fields.normalized_intent_digest.as_bytes());
        // Both the closed-profile flag and every reserved byte stay zero.
        canonical[424..456].copy_from_slice(&fields.backend_id);

        for (index, commitment) in [
            fields.root_prepared,
            fields.publication,
            fields.catalog,
            fields.binding,
            fields.backend_enrollment,
            fields.dedicated_enrollment,
        ]
        .iter()
        .enumerate()
        {
            let offset = 456 + index * 32;
            canonical[offset..offset + 32].copy_from_slice(commitment.as_bytes());
        }

        Ok(Self { fields, canonical })
    }

    /// Decodes exactly one canonical closed-profile input frame.
    ///
    /// # Errors
    ///
    /// Rejects length, magic, version, profile, reserved bytes and every
    /// structural condition checked by [`Self::new`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1 {
            return Err(invalid("selected execution input length"));
        }
        let mut reader = Reader::new(bytes);
        reader.header(MAGIC)?;
        if reader.u16()? != PROFILE {
            return Err(invalid("selected execution input profile"));
        }
        reader.zeros(4)?;
        let scope = NativeHeldScopeV1::decode(&mut reader)?;
        let provider_id = reader.array()?;
        let holder_id = reader.array()?;
        let session_binding = reader.digest()?;
        let attempt_digest = reader.digest()?;
        let acquisition_id = reader.digest()?;
        let effect_id = reader.array()?;
        let normalized_intent_digest = reader.digest()?;
        if reader.u8()? != 0 {
            return Err(invalid("selected execution input kernel profile"));
        }
        reader.zeros(7)?;

        let fields = SourceSelectedNativeExecutionInputFieldsV1 {
            scope,
            provider_id,
            holder_id,
            session_binding,
            attempt_digest,
            acquisition_id,
            effect_id,
            normalized_intent_digest,
            kernel_coupled: false,
            backend_id: reader.array()?,
            root_prepared: reader.digest()?,
            publication: reader.digest()?,
            catalog: reader.digest()?,
            binding: reader.digest()?,
            backend_enrollment: reader.digest()?,
            dedicated_enrollment: reader.digest()?,
        };
        reader.finish()?;
        Self::new(fields)
    }

    /// Borrows the exact canonical bytes without transferring owner authority.
    #[must_use]
    pub const fn as_canonical_bytes(
        &self,
    ) -> &[u8; SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1] {
        &self.canonical
    }

    /// Borrows the untrusted fields, not an authenticated original owner.
    #[must_use]
    pub const fn fields(&self) -> &SourceSelectedNativeExecutionInputFieldsV1 {
        &self.fields
    }

    /// Commits the new domain, big-endian length and exact canonical frame.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        let mut framed = [0; 4 + SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1];
        framed[..4].copy_from_slice(
            &(SOURCE_SELECTED_NATIVE_EXECUTION_INPUT_BYTES_V1 as u32).to_be_bytes(),
        );
        framed[4..].copy_from_slice(&self.canonical);
        digest(DOMAIN, &framed)
    }
}

fn validate_fields(fields: &SourceSelectedNativeExecutionInputFieldsV1) -> Result<()> {
    fields.scope.validate_full()?;
    if fields.provider_id == [0; 16]
        || fields.holder_id == [0; 16]
        || fields.effect_id == [0; 16]
        || fields.backend_id == [0; 32]
        || fields.kernel_coupled
        || fields.session_binding != fields.scope.original_source_session
        || fields.attempt_digest != fields.scope.provider_attempt
        || fields.acquisition_id != fields.scope.provider_acquisition
    {
        return Err(invalid("selected execution input plan/scope"));
    }
    if [
        fields.normalized_intent_digest,
        fields.root_prepared,
        fields.publication,
        fields.catalog,
        fields.binding,
        fields.backend_enrollment,
        fields.dedicated_enrollment,
    ]
    .iter()
    .any(|value| !nonzero(*value))
    {
        return Err(invalid("selected execution input commitment"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! UNRUN canonical DATA vectors, never an authenticated Source owner.

    use super::*;
    use super::super::native_held_flight_digest_v1;
    use sha2::{Digest as _, Sha256};

    fn d(value: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([value; 32])
    }

    fn fields() -> SourceSelectedNativeExecutionInputFieldsV1 {
        let scope = NativeHeldScopeV1 {
            flight: native_held_flight_digest_v1(d(4), d(5), d(6)),
            original_source_session: d(6),
            mount_attempt: d(5),
            provider_attempt: d(7),
            provider_acquisition: d(8),
            original_root_request: d(4),
            original_native_request: d(9),
        };
        SourceSelectedNativeExecutionInputFieldsV1 {
            scope,
            provider_id: [1; 16],
            holder_id: [2; 16],
            session_binding: d(6),
            attempt_digest: d(7),
            acquisition_id: d(8),
            effect_id: [3; 16],
            normalized_intent_digest: d(10),
            kernel_coupled: false,
            backend_id: [11; 32],
            root_prepared: d(12),
            publication: d(13),
            catalog: d(14),
            binding: d(15),
            backend_enrollment: d(16),
            dedicated_enrollment: d(17),
        }
    }

    #[test]
    fn exact_layout_round_trips_all_original_plan_fields() {
        let fields = fields();
        let data = SourceSelectedNativeExecutionInputDataV1::new(fields).unwrap();
        let bytes = data.as_canonical_bytes();

        assert_eq!(bytes.len(), 648);
        assert_eq!(&bytes[..16], b"AOSNEM01\0\x01\0\x01\0\0\0\0");
        assert_eq!(&bytes[16..240], &fields.scope.to_canonical_bytes());
        assert_eq!(&bytes[240..256], &fields.provider_id);
        assert_eq!(&bytes[256..272], &fields.holder_id);
        assert_eq!(&bytes[272..304], fields.session_binding.as_bytes());
        assert_eq!(&bytes[304..336], fields.attempt_digest.as_bytes());
        assert_eq!(&bytes[336..368], fields.acquisition_id.as_bytes());
        assert_eq!(&bytes[368..384], &fields.effect_id);
        assert_eq!(&bytes[384..416], fields.normalized_intent_digest.as_bytes());
        assert_eq!(&bytes[416..424], &[0; 8]);
        assert_eq!(&bytes[424..456], &fields.backend_id);
        assert_eq!(&bytes[616..648], fields.dedicated_enrollment.as_bytes());
        assert_eq!(
            SourceSelectedNativeExecutionInputDataV1::from_canonical_bytes(bytes).unwrap(),
            data,
        );
    }

    #[test]
    fn digest_uses_one_nul_length_and_complete_new_frame() {
        let data = SourceSelectedNativeExecutionInputDataV1::new(fields()).unwrap();
        let expected: [u8; 32] = Sha256::new()
            .chain_update(b"aos.sandbox.source-provider.native-selected-execution-input.v1\0")
            .chain_update(648_u32.to_be_bytes())
            .chain_update(data.as_canonical_bytes())
            .finalize()
            .into();

        assert_eq!(data.digest().as_bytes(), &expected);
        assert_ne!(data.digest(), d(14));
        assert_ne!(
            data.digest().as_bytes(),
            Sha256::digest(data.as_canonical_bytes()).as_slice(),
        );
    }

    #[test]
    fn closed_header_padding_length_and_kernel_profile_refuse() {
        let data = SourceSelectedNativeExecutionInputDataV1::new(fields()).unwrap();
        for offset in [0, 8, 10, 12, 15, 416, 417, 423] {
            let mut changed = *data.as_canonical_bytes();
            changed[offset] ^= 1;
            assert!(
                SourceSelectedNativeExecutionInputDataV1::from_canonical_bytes(&changed).is_err()
            );
        }
        for length in [0, 16, 239, 456, 647] {
            assert!(
                SourceSelectedNativeExecutionInputDataV1::from_canonical_bytes(
                    &data.as_canonical_bytes()[..length],
                )
                .is_err()
            );
        }
        let mut trailing = data.as_canonical_bytes().to_vec();
        trailing.push(0);
        assert!(SourceSelectedNativeExecutionInputDataV1::from_canonical_bytes(&trailing).is_err());
    }

    #[test]
    fn mismatched_original_scope_and_every_sentinel_refuse() {
        let data = SourceSelectedNativeExecutionInputDataV1::new(fields()).unwrap();
        for (start, end) in [
            (240, 256),
            (256, 272),
            (272, 304),
            (304, 336),
            (336, 368),
            (368, 384),
            (384, 416),
            (424, 456),
            (456, 488),
            (488, 520),
            (520, 552),
            (552, 584),
            (584, 616),
            (616, 648),
        ] {
            let mut changed = *data.as_canonical_bytes();
            changed[start..end].fill(0);
            assert!(
                SourceSelectedNativeExecutionInputDataV1::from_canonical_bytes(&changed).is_err()
            );
        }
        for offset in [16, 272, 304, 336] {
            let mut changed = *data.as_canonical_bytes();
            changed[offset] ^= 1;
            assert!(
                SourceSelectedNativeExecutionInputDataV1::from_canonical_bytes(&changed).is_err()
            );
        }
        let mut coupled = fields();
        coupled.kernel_coupled = true;
        assert!(SourceSelectedNativeExecutionInputDataV1::new(coupled).is_err());
    }

    #[test]
    fn every_unlinked_plan_or_commitment_byte_changes_the_digest() {
        let data = SourceSelectedNativeExecutionInputDataV1::new(fields()).unwrap();
        for offset in [240, 256, 368, 384, 424, 456, 488, 520, 552, 584, 616] {
            let mut changed = *data.as_canonical_bytes();
            changed[offset] ^= 1;
            let changed = SourceSelectedNativeExecutionInputDataV1::from_canonical_bytes(&changed)
                .unwrap();
            assert_ne!(changed.digest(), data.digest());
        }
    }
}
