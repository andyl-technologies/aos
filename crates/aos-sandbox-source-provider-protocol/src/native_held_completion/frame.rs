//! Closed native control sections, prepared signer bytes, and untrusted archives.
//!
//! ```text
//! prepared = header[24] | common[272] | increasing_unique_sections | existing_signer
//! signed = prepared | signature[64]
//! signature_input = domain | fixed_audience:u8 | exact_prepared
//! ```
//!
//! Parsing or checking a signature grants no owner/currentness authority. Every
//! nested original/current role must be independently verified by the actual
//! receiving owner, under the retained original or separately eligible recovery
//! trust. This module contains no signing method or production authority factory.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::crypto::{decode_signer, encode_signer};
use crate::{
    SourceProviderKeyUsageV1, SourceProviderSigningKeyV1, StorageNativeAcquireReplyV3,
    StorageZfsHoldSignerV1,
};

use super::assertion::{
    NativeHeldDispositionV1, NativeHeldSettlementV1, ProviderNativeSettlementAssertionV1,
    RootNativeDispositionAssertionV1, RootNativeObservationV1, StorageNativeSettlementAssertionV1,
};
use super::codec::{Reader, digest, invalid, nonzero, put_length};
use super::recovery::{
    NativeHeldRecoveryChildStatusV1, NativeHeldRecoveryModeV1, NativeHeldRecoveryQueryV1,
    NativeHeldRecoveryRowClassV1, ProviderNativeRecoveryStateV1, RootNativeRecoveryAssertionV1,
    StorageNativeRecoveryStateV1,
};
use super::witness::NativeHeldOwnerWitnessV1;
use super::{
    MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1, NativeHeldCompletionErrorV1,
    NativeHeldControlKindV1 as Kind, NativeHeldOwnerV1 as Owner, NativeHeldScopeV1,
    NativeHeldSectionTagV1 as Tag, Result,
};

const MAGIC: &[u8; 8] = b"AOSNHC01";
const SIGNATURE_DOMAIN: &[u8] = b"aos.sandbox.native-held-completion.signature.v1\0";
const FRAME_DOMAIN: &[u8] = b"aos.sandbox.native-held-completion.frame.v1\0";
const PREPARED_DOMAIN: &[u8] = b"aos.sandbox.native-held-completion.prepared-frame.v1\0";
const MAXIMUM_NESTING: usize = 4;

/// Retains an existing role-specific signer reference as an untrusted claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeHeldSignerV1 {
    /// Reuses the canonical 120-byte RootMountRecord or ProviderOutcome reference.
    SourceProvider(SourceProviderSigningKeyV1),
    /// Reuses the canonical 88-byte separately pinned dedicated Storage reference.
    Storage(StorageZfsHoldSignerV1),
}

impl NativeHeldSignerV1 {
    fn encode_for(&self, owner: Owner, bytes: &mut Vec<u8>) -> Result<()> {
        match (owner, self) {
            (Owner::Root | Owner::Provider, Self::SourceProvider(signer)) => {
                let usage = if owner == Owner::Root {
                    SourceProviderKeyUsageV1::RootMountRecord
                } else {
                    SourceProviderKeyUsageV1::ProviderOutcome
                };
                if signer.usage() != usage {
                    return Err(invalid("control signer usage"));
                }
                encode_signer(bytes, signer);
            }
            (Owner::Storage, Self::Storage(signer)) => bytes.extend_from_slice(&signer.encode()),
            _ => return Err(invalid("control signer role")),
        }
        Ok(())
    }

    fn decode(owner: Owner, reader: &mut Reader<'_>) -> Result<Self> {
        let value = match owner {
            Owner::Root | Owner::Provider => Self::SourceProvider(
                decode_signer(reader.bytes(120)?).map_err(|_| invalid("Source control signer"))?,
            ),
            Owner::Storage => Self::Storage(
                StorageZfsHoldSignerV1::decode(reader.bytes(88)?)
                    .map_err(|_| invalid("Storage control signer"))?,
            ),
        };
        let mut encoded = Vec::new();
        value.encode_for(owner, &mut encoded)?;
        Ok(value)
    }
}

/// Carries one assigned section; only an enclosing closed kind validates its use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHeldSectionV1 {
    tag: Tag,
    bytes: Vec<u8>,
}

impl NativeHeldSectionV1 {
    /// Collects bounded untrusted section bytes without authorizing their claims.
    ///
    /// # Errors
    ///
    /// Rejects an empty or over-8KiB section; the enclosing frame checks semantics.
    pub fn new(tag: Tag, bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1 {
            return Err(invalid("section length"));
        }
        Ok(Self { tag, bytes })
    }

    /// Returns the assigned tag, never an extensible unknown section identifier.
    #[must_use]
    pub const fn tag(&self) -> Tag {
        self.tag
    }

    /// Returns the exact section bytes for the concrete owner's further joins.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Retains exact canonical control and fixed signer bytes before its signature.
///
/// The type validates only format. It is not a durable prepared owner or signing
/// permit; the actual owner must commit/read back these exact bytes where required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedNativeHeldControlV1 {
    kind: Kind,
    scope: NativeHeldScopeV1,
    predecessor: ObjectDigest,
    sections: Vec<NativeHeldSectionV1>,
    signer: NativeHeldSignerV1,
    canonical: Vec<u8>,
}

impl PreparedNativeHeldControlV1 {
    /// Validates the exact closed control shape and unchanged nested predecessors.
    ///
    /// # Errors
    ///
    /// Rejects scope, signer, ordering, section-set, nested join or size violations.
    pub fn new(
        kind: Kind,
        scope: NativeHeldScopeV1,
        predecessor: ObjectDigest,
        sections: Vec<NativeHeldSectionV1>,
        signer: NativeHeldSignerV1,
    ) -> Result<Self> {
        let mut value = Self {
            kind,
            scope,
            predecessor,
            sections,
            signer,
            canonical: Vec::new(),
        };
        value.validate_at_depth(0)?;
        value.canonical = value.encode()?;
        Ok(value)
    }

    /// Decodes only an exact bounded unsigned control including its signer reference.
    ///
    /// # Errors
    ///
    /// Rejects canonical framing, closed section graph, signer or allocation bounds.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode_at_depth(bytes, 0)
    }

    /// Returns the exact canonical prepared bytes; no signature is synthesized.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.canonical.clone()
    }

    /// Returns the fixed original kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// Returns the original correlation scope, not a live owner cut.
    #[must_use]
    pub const fn scope(&self) -> &NativeHeldScopeV1 {
        &self.scope
    }

    /// Returns the exact preceding frame digest retained by this control.
    #[must_use]
    pub const fn predecessor(&self) -> ObjectDigest {
        self.predecessor
    }

    /// Returns the existing role signer reference bound into prepared bytes.
    #[must_use]
    pub const fn signer(&self) -> &NativeHeldSignerV1 {
        &self.signer
    }

    /// Returns the assigned sections in increasing canonical order.
    #[must_use]
    pub fn sections(&self) -> &[NativeHeldSectionV1] {
        &self.sections
    }

    /// Returns exact bytes for one assigned section, if this kind has it.
    #[must_use]
    pub fn section(&self, tag: Tag) -> Option<&[u8]> {
        self.sections
            .iter()
            .find(|section| section.tag == tag)
            .map(|section| section.bytes.as_slice())
    }

    /// Computes the prepared-byte commitment; this is not durable readback evidence.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        digest(PREPARED_DOMAIN, &self.canonical)
    }

    /// Returns the domain-separated signature input without performing signing.
    #[must_use]
    pub fn signature_message(&self) -> Vec<u8> {
        let mut bytes = SIGNATURE_DOMAIN.to_vec();
        bytes.push(self.kind.audience() as u8);
        bytes.extend_from_slice(&self.canonical);
        bytes
    }

    /// Collects an untrusted signature claim without verifying or creating custody.
    #[must_use]
    pub fn with_signature(self, signature: [u8; 64]) -> SignedNativeHeldControlV1 {
        SignedNativeHeldControlV1 {
            prepared: self,
            signature,
        }
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut payload = self.scope.to_canonical_bytes().to_vec();
        payload.extend_from_slice(self.predecessor.as_bytes());
        payload.extend_from_slice(&self.kind.step().to_be_bytes());
        payload.extend_from_slice(&(self.sections.len() as u16).to_be_bytes());
        payload.extend_from_slice(&[0; 6]);
        for section in &self.sections {
            payload.extend_from_slice(&(section.tag as u16).to_be_bytes());
            payload.extend_from_slice(&[0; 2]);
            put_length(&mut payload, &section.bytes)?;
            payload.extend_from_slice(&section.bytes);
        }
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[self.kind as u8, self.kind.sender() as u8]);
        put_length(&mut bytes, &payload)?;
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&payload);
        self.signer.encode_for(self.kind.sender(), &mut bytes)?;
        if bytes
            .len()
            .checked_add(64)
            .is_none_or(|length| length > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1)
        {
            return Err(NativeHeldCompletionErrorV1::LimitExceeded(
                "complete control",
            ));
        }
        Ok(bytes)
    }

    fn decode_at_depth(bytes: &[u8], depth: usize) -> Result<Self> {
        if bytes
            .len()
            .checked_add(64)
            .is_none_or(|length| length > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1)
        {
            return Err(NativeHeldCompletionErrorV1::LimitExceeded(
                "complete control",
            ));
        }
        if depth > MAXIMUM_NESTING {
            return Err(NativeHeldCompletionErrorV1::LimitExceeded(
                "control nesting",
            ));
        }
        let mut reader = Reader::new(bytes);
        reader.header(MAGIC)?;
        let kind = Kind::from_byte(reader.u8()?)?;
        if reader.u8()? != kind.sender() as u8 {
            return Err(invalid("fixed control sender"));
        }
        let payload_length = reader.u32()? as usize;
        reader.zeros(8)?;
        let mut payload = Reader::new(reader.bytes(payload_length)?);
        let scope = NativeHeldScopeV1::decode(&mut payload)?;
        let predecessor = payload.digest()?;
        if payload.u64()? != kind.step() {
            return Err(invalid("fixed control step"));
        }
        let count = usize::from(payload.u16()?);
        if !(2..=3).contains(&count) && !(kind == Kind::RootPrepared && count == 1) {
            return Err(invalid("closed section count"));
        }
        payload.zeros(6)?;
        let mut sections = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = Tag::from_u16(payload.u16()?)?;
            payload.zeros(2)?;
            let length = payload.u32()? as usize;
            if length == 0 || length > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1 {
                return Err(invalid("section length"));
            }
            sections.push(NativeHeldSectionV1 {
                tag,
                bytes: payload.bytes(length)?.to_vec(),
            });
        }
        payload.finish()?;
        let signer = NativeHeldSignerV1::decode(kind.sender(), &mut reader)?;
        reader.finish()?;
        let value = Self {
            kind,
            scope,
            predecessor,
            sections,
            signer,
            canonical: bytes.to_vec(),
        };
        value.validate_at_depth(depth)?;
        if value.encode()? != bytes {
            return Err(invalid("control canonical bytes"));
        }
        Ok(value)
    }

    fn validate_at_depth(&self, depth: usize) -> Result<()> {
        if depth > MAXIMUM_NESTING {
            return Err(NativeHeldCompletionErrorV1::LimitExceeded(
                "control nesting",
            ));
        }
        let mut signer = Vec::new();
        self.signer.encode_for(self.kind.sender(), &mut signer)?;
        if self
            .sections
            .windows(2)
            .any(|pair| pair[0].tag >= pair[1].tag)
        {
            return Err(invalid("section order or duplicate"));
        }
        if (self.kind == Kind::RootPrepared || self.kind == Kind::RootRecoveryQuery)
            != !nonzero(self.predecessor)
        {
            return Err(invalid("predecessor presence"));
        }
        let tags = self
            .sections
            .iter()
            .map(|section| section.tag)
            .collect::<Vec<_>>();
        let required: &[Tag] = match self.kind {
            Kind::RootPrepared => &[Tag::Witness],
            Kind::StorageHeld => &[Tag::Witness, Tag::RootPrepared, Tag::NativeReply],
            Kind::ProviderHeld => &[Tag::Witness, Tag::StorageHeld, Tag::SourceArtifact],
            Kind::RootAccepted => &[
                Tag::Witness,
                Tag::SourceArtifact,
                Tag::RootDispositionAssertion,
            ],
            Kind::RootClosed if self.scope.is_root_only() => &[
                Tag::Witness,
                Tag::RootPrepared,
                Tag::RootDispositionAssertion,
            ],
            Kind::RootClosed => &[
                Tag::Witness,
                Tag::SourceArtifact,
                Tag::RootDispositionAssertion,
            ],
            Kind::ProviderRelay => &[Tag::Witness, Tag::RootDispositionControl],
            Kind::StorageSettled | Kind::ProviderSettled | Kind::RootTerminalRecorded => {
                &[Tag::Witness, Tag::Settlement]
            }
            Kind::RootRecoveryQuery => &[Tag::RecoveryQuery, Tag::RootRecoveryAssertion],
            Kind::ProviderRecoveryState => &[Tag::RecoveryQuery, Tag::ProviderRecoveryState],
            Kind::ProviderStorageRecoveryQuery => &[Tag::RecoveryQuery, Tag::RootRecoveryControl],
            Kind::StorageRecoveryState => &[Tag::RecoveryQuery, Tag::StorageRecoveryState],
        };
        if tags != required {
            return Err(invalid("required/forbidden section set"));
        }
        if !self.kind.is_recovery() {
            self.validate_hot(depth)?;
        } else {
            self.validate_recovery(depth)?;
        }
        Ok(())
    }

    fn required(&self, tag: Tag) -> Result<&[u8]> {
        self.section(tag)
            .ok_or_else(|| invalid("missing required section"))
    }

    fn nested(&self, tag: Tag, kind: Kind, depth: usize) -> Result<SignedNativeHeldControlV1> {
        let value = SignedNativeHeldControlV1::decode_at_depth(self.required(tag)?, depth + 1)?;
        if value.kind() != kind {
            return Err(invalid("closed nested kind"));
        }
        Ok(value)
    }

    fn source_artifact(&self) -> Result<ObjectDigest> {
        let bytes: [u8; 32] = self
            .required(Tag::SourceArtifact)?
            .try_into()
            .map_err(|_| invalid("Source artifact width"))?;
        let value = ObjectDigest::from_bytes(bytes);
        if !nonzero(value) {
            return Err(invalid("Source artifact sentinel"));
        }
        Ok(value)
    }

    fn validate_hot(&self, depth: usize) -> Result<()> {
        let witness = NativeHeldOwnerWitnessV1::from_canonical_bytes(
            self.kind.sender(),
            self.required(Tag::Witness)?,
        )?;
        match self.kind {
            Kind::RootPrepared => self.scope.validate_root_only()?,
            Kind::StorageHeld => {
                self.scope.validate_full()?;
                let original = self.nested(Tag::RootPrepared, Kind::RootPrepared, depth)?;
                self.scope.require_root_prefix(original.scope())?;
                if original.digest() != self.predecessor {
                    return Err(invalid("StorageHeld predecessor"));
                }
                let reply = StorageNativeAcquireReplyV3::from_canonical_bytes(
                    self.required(Tag::NativeReply)?,
                )
                .map_err(|_| invalid("original native reply"))?;
                if reply.acceptance().acceptance().request_digest()
                    != self.scope.original_native_request
                {
                    return Err(invalid("original native reply request"));
                }
                if self.signer != NativeHeldSignerV1::Storage(reply.acceptance().signer())
                    || reply.receipt().signer() != reply.acceptance().signer()
                {
                    return Err(invalid("original dedicated Storage signer"));
                }
                if let NativeHeldOwnerWitnessV1::Storage(value) = &witness {
                    if !nonzero(value.issuance.digest()) {
                        return Err(invalid("actual Storage issuance witness"));
                    }
                }
            }
            Kind::ProviderHeld => {
                self.scope.validate_full()?;
                let held = self.nested(Tag::StorageHeld, Kind::StorageHeld, depth)?;
                if held.scope() != &self.scope || held.digest() != self.predecessor {
                    return Err(invalid("ProviderHeld original join"));
                }
                self.source_artifact()?;
                if let NativeHeldOwnerWitnessV1::Provider(value) = &witness {
                    if value.records.iter().any(|record| !nonzero(record.digest())) {
                        return Err(invalid("positive six-row/challenge witnesses"));
                    }
                }
            }
            Kind::RootAccepted | Kind::RootClosed => {
                let assertion = RootNativeDispositionAssertionV1::from_canonical_bytes(
                    self.required(Tag::RootDispositionAssertion)?,
                )?;
                let expected = if self.kind == Kind::RootAccepted {
                    NativeHeldDispositionV1::Accepted
                } else {
                    NativeHeldDispositionV1::Closed
                };
                if assertion.scope != self.scope || assertion.disposition != expected {
                    return Err(invalid("hot Root assertion class/scope"));
                }
                if let NativeHeldOwnerWitnessV1::Root(value) = &witness {
                    if value.records != assertion.records {
                        return Err(invalid("Root control/assertion witnesses"));
                    }
                }
                match assertion.observation {
                    RootNativeObservationV1::PreparedOnly => {
                        let original = self.nested(Tag::RootPrepared, Kind::RootPrepared, depth)?;
                        if original.scope() != &self.scope || original.digest() != self.predecessor
                        {
                            return Err(invalid("PreparedOnly Closed predecessor"));
                        }
                    }
                    RootNativeObservationV1::ProviderHeldObserved => {
                        if self.source_artifact()? != assertion.source_artifact {
                            return Err(invalid("observed Root artifact"));
                        }
                    }
                }
            }
            Kind::ProviderRelay => {
                self.scope.validate_full()?;
                let root = SignedNativeHeldControlV1::decode_at_depth(
                    self.required(Tag::RootDispositionControl)?,
                    depth + 1,
                )?;
                if !matches!(root.kind(), Kind::RootAccepted | Kind::RootClosed)
                    || root.digest() != self.predecessor
                {
                    return Err(invalid("relay original Root disposition"));
                }
                require_scope_join(&self.scope, root.scope())?;
            }
            Kind::StorageSettled | Kind::ProviderSettled | Kind::RootTerminalRecorded => {
                self.scope.validate_full()?;
                NativeHeldSettlementV1::from_canonical_bytes(self.required(Tag::Settlement)?)?
                    .validate_for_kind(self.kind)?;
                if let NativeHeldOwnerWitnessV1::Storage(value) = &witness {
                    if !nonzero(value.issuance.digest()) {
                        return Err(invalid("settled actual interest witness"));
                    }
                }
            }
            _ => return Err(invalid("hot control kind")),
        }
        Ok(())
    }

    fn validate_recovery(&self, depth: usize) -> Result<()> {
        let query =
            NativeHeldRecoveryQueryV1::from_canonical_bytes(self.required(Tag::RecoveryQuery)?)?;
        query.validate_for_kind(self.kind)?;
        match self.kind {
            Kind::RootRecoveryQuery => {
                self.scope.validate_root_only()?;
                let state = RootNativeRecoveryAssertionV1::decode_at_depth(
                    self.required(Tag::RootRecoveryAssertion)?,
                    depth,
                )?;
                if let Some(disposition) = &state.disposition {
                    require_scope_join(&disposition.scope, &self.scope)?;
                }
                if !nonzero(query.original_prepared) && !matches!(state.phase, 0 | 10) {
                    return Err(invalid("missing original signed RootPrepared"));
                }
                match query.mode {
                    NativeHeldRecoveryModeV1::Observe => {}
                    NativeHeldRecoveryModeV1::SettleRecordedDisposition
                        if state.disposition.is_some() => {}
                    NativeHeldRecoveryModeV1::RecordRootTerminal if state.settlement.is_some() => {}
                    _ => return Err(invalid("Root recovery mode/phase")),
                }
            }
            Kind::ProviderStorageRecoveryQuery => {
                self.scope.validate_full()?;
                let root = self.nested(Tag::RootRecoveryControl, Kind::RootRecoveryQuery, depth)?;
                self.scope.require_root_prefix(root.scope())?;
                let original_query = NativeHeldRecoveryQueryV1::from_canonical_bytes(
                    root.required(Tag::RecoveryQuery)?,
                )?;
                if root.digest() != self.predecessor
                    || query.parent_root_query != root.digest()
                    || query.recovery_session != original_query.recovery_session
                    || query.mode != original_query.mode
                    || query.original_prepared != original_query.original_prepared
                {
                    return Err(invalid("recovery child original Root query"));
                }
            }
            Kind::ProviderRecoveryState => {
                let state = ProviderNativeRecoveryStateV1::decode_at_depth(
                    self.required(Tag::ProviderRecoveryState)?,
                    depth,
                )?;
                if state.fields.row_class == NativeHeldRecoveryRowClassV1::Native {
                    self.scope.validate_full()?;
                    if !nonzero(query.original_prepared) {
                        return Err(invalid("Requested missing signed RootPrepared"));
                    }
                    validate_row_scope(&self.scope, &state.fields, Owner::Provider)?;
                } else {
                    self.scope.validate_root_only()?;
                }
                if query.mode == NativeHeldRecoveryModeV1::RecordRootTerminal
                    && state.fields.child_status != NativeHeldRecoveryChildStatusV1::NotQueried
                {
                    return Err(invalid("terminal ACK Storage child"));
                }
                if let Some(child) = &state.fields.child {
                    let child = SignedNativeHeldControlV1::decode_at_depth(child, depth + 1)?;
                    let child_query = NativeHeldRecoveryQueryV1::from_canonical_bytes(
                        child.required(Tag::RecoveryQuery)?,
                    )?;
                    if child.scope() != &self.scope
                        || child_query.parent_root_query != self.predecessor
                        || child_query.recovery_session != query.recovery_session
                        || child_query.mode != query.mode
                        || child_query.original_prepared != query.original_prepared
                    {
                        return Err(invalid("exact current Storage child correlation"));
                    }
                }
            }
            Kind::StorageRecoveryState => {
                self.scope.validate_full()?;
                let state = StorageNativeRecoveryStateV1::decode_at_depth(
                    self.required(Tag::StorageRecoveryState)?,
                    depth,
                )?;
                if state.fields.row_class == NativeHeldRecoveryRowClassV1::Native {
                    validate_row_scope(&self.scope, &state.fields, Owner::Storage)?;
                }
            }
            _ => return Err(invalid("recovery control kind")),
        }
        Ok(())
    }
}

/// Retains an untrusted exact signature archive separately from stable assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedNativeHeldControlV1 {
    prepared: PreparedNativeHeldControlV1,
    signature: [u8; 64],
}

impl SignedNativeHeldControlV1 {
    /// Decodes one bounded control; decoding neither verifies trust nor currentness.
    ///
    /// # Errors
    ///
    /// Rejects all malformed, unknown, unbounded or inconsistent closed control graphs.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        Self::decode_at_depth(bytes, 0)
    }

    /// Encodes the exact original archive without re-signing or recapturing inputs.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.prepared.to_canonical_bytes();
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Returns the fixed native control kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.prepared.kind
    }

    /// Returns the exact original correlation scope.
    #[must_use]
    pub const fn scope(&self) -> &NativeHeldScopeV1 {
        &self.prepared.scope
    }

    /// Returns the exact preceding frame digest, not a stable disposition ID.
    #[must_use]
    pub const fn predecessor(&self) -> ObjectDigest {
        self.prepared.predecessor
    }

    /// Returns the exact already-bound prepared bytes and role reference.
    #[must_use]
    pub const fn prepared(&self) -> &PreparedNativeHeldControlV1 {
        &self.prepared
    }

    /// Returns exact bytes for one assigned section, if present.
    #[must_use]
    pub fn section(&self, tag: Tag) -> Option<&[u8]> {
        self.prepared.section(tag)
    }

    /// Computes the archive identity, never the stable unsigned Root disposition ID.
    #[must_use]
    pub fn digest(&self) -> ObjectDigest {
        digest(FRAME_DOMAIN, &self.to_canonical_bytes())
    }

    /// Checks only cryptographic equality against an independently supplied role pin.
    ///
    /// The caller must obtain `expected` and `public_key` from its real owned
    /// trust, not the decoded control or an ambient UID. Nested controls and
    /// current/retained generation eligibility need independent owner checks.
    ///
    /// # Errors
    ///
    /// Rejects a different signer, key fingerprint, weak key or invalid signature.
    pub fn verify_signature_claim(
        &self,
        expected: &NativeHeldSignerV1,
        public_key: &[u8; 32],
    ) -> Result<()> {
        if &self.prepared.signer != expected {
            return Err(NativeHeldCompletionErrorV1::Signature);
        }
        if let NativeHeldSignerV1::SourceProvider(signer) = expected {
            let fingerprint = ObjectDigest::from_bytes(Sha256::digest(public_key).into());
            if signer.public_key_digest() != fingerprint {
                return Err(NativeHeldCompletionErrorV1::Signature);
            }
        }
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| NativeHeldCompletionErrorV1::Signature)?;
        if key.is_weak() {
            return Err(NativeHeldCompletionErrorV1::Signature);
        }
        key.verify_strict(
            &self.prepared.signature_message(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| NativeHeldCompletionErrorV1::Signature)
    }

    pub(super) fn decode_at_depth(bytes: &[u8], depth: usize) -> Result<Self> {
        if bytes.len() > MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1 {
            return Err(NativeHeldCompletionErrorV1::LimitExceeded(
                "complete control",
            ));
        }
        let signature_start = bytes
            .len()
            .checked_sub(64)
            .ok_or_else(|| invalid("control signature width"))?;
        let prepared = PreparedNativeHeldControlV1::decode_at_depth(
            bytes
                .get(..signature_start)
                .ok_or_else(|| invalid("prepared width"))?,
            depth,
        )?;
        let signature = bytes
            .get(signature_start..)
            .ok_or_else(|| invalid("control signature"))?
            .try_into()
            .map_err(|_| invalid("control signature width"))?;
        Ok(Self {
            prepared,
            signature,
        })
    }

    fn required(&self, tag: Tag) -> Result<&[u8]> {
        self.prepared.required(tag)
    }
}

fn require_scope_join(
    full_or_root: &NativeHeldScopeV1,
    original: &NativeHeldScopeV1,
) -> Result<()> {
    if full_or_root == original {
        if full_or_root.is_root_only() {
            full_or_root.validate_root_only()
        } else {
            full_or_root.validate_full()
        }
    } else if original.is_root_only() {
        full_or_root.require_root_prefix(original)
    } else {
        Err(invalid("exact original scope join"))
    }
}

fn validate_row_scope(
    scope: &NativeHeldScopeV1,
    fields: &super::recovery::NativeHeldRecoveryFieldsV1,
    owner: Owner,
) -> Result<()> {
    if fields.native_request != scope.original_native_request {
        return Err(invalid("recovery original native request"));
    }
    if let Some(disposition) = &fields.disposition {
        require_scope_join(scope, &disposition.scope)?;
    }
    if !fields.own_assertion.is_empty() {
        let own_scope = match owner {
            Owner::Provider => {
                ProviderNativeSettlementAssertionV1::from_canonical_bytes(&fields.own_assertion)?
                    .scope
            }
            Owner::Storage => {
                StorageNativeSettlementAssertionV1::from_canonical_bytes(&fields.own_assertion)?
                    .scope
            }
            _ => return Err(invalid("recovery assertion owner")),
        };
        if &own_scope != scope {
            return Err(invalid("recovery own assertion scope"));
        }
    }
    if let Some(archive) = &fields.hot_terminal {
        let archive = SignedNativeHeldControlV1::from_canonical_bytes(archive)?;
        if archive.scope() != scope {
            return Err(invalid("recovery hot terminal original scope"));
        }
    }
    Ok(())
}
