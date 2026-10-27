//! Receives private GetBundle metadata until the actual stream ends.
//!
//! Objects undergo canonical CBOR and identity checks before retention.
//! Completion applies the configured metadata schema validator to every object.
//! No objects are exposed until completion; rejection releases all retained data.
//! This layer establishes neither root reachability nor complete dependencies,
//! signatures, Original authority, current permission or backend admission.
//! Optional access profiles remain opaque untrusted bytes for their owning
//! registered decoder. Transport bindings independently bound frame decoding.
//!
//! ```text
//! metadata* -> optional requested access profile -> actual EOF -> private result
//! any refusal -> terminal rejection and release of retained bytes
//! ```

use std::{collections::BTreeSet, fmt};

use terrane_format::identity::Digest;

use super::v1::{self, bundle_frame::Frame};
use crate::{
    pack::{BundleObject, EntryKind, PackError},
    store::{ContentValidator, MetaUpload, StoreFailure},
};

/// Bounds retained metadata bodies, object counts and a trailing access profile.
#[derive(Clone, Copy, Debug)]
pub struct BundleLimits {
    objects: usize,
    object_bytes: usize,
    total_bytes: usize,
    profile_bytes: usize,
}

impl BundleLimits {
    /// Requires explicit positive finite bounds within the bundle format limits.
    ///
    /// The total covers object and access-profile bytes together. Protobuf
    /// overhead, frame decoding and stream deadlines belong to the transport.
    ///
    /// # Errors
    /// Rejects zero bounds, object counts or total bytes beyond the format
    /// maximum, and individual bounds exceeding the total allowance.
    pub fn new(
        objects: usize,
        object_bytes: usize,
        total_bytes: usize,
        profile_bytes: usize,
    ) -> Result<Self, BundleError> {
        if objects == 0
            || objects > terrane_format::pack_format::MAX_BUNDLE_OBJECTS
            || object_bytes == 0
            || total_bytes == 0
            || total_bytes > terrane_format::pack_format::MAX_BUNDLE_BYTES
            || profile_bytes == 0
            || object_bytes > total_bytes
            || profile_bytes > total_bytes
        {
            return Err(BundleError::Limits);
        }
        Ok(Self {
            objects,
            object_bytes,
            total_bytes,
            profile_bytes,
        })
    }
}

/// Retains canonical, identity-checked objects until genuine stream completion.
///
/// Dropping the receiver cancels its private work without backend effects. A
/// surrounding caller must obtain actual EOF before calling [`Self::finish`].
pub struct BundleReceiver {
    limits: BundleLimits,
    profile_requested: bool,
    objects: Vec<BundleObject>,
    identities: BTreeSet<(EntryKind, Digest)>,
    profile: Option<Vec<u8>>,
    bytes: usize,
    failed: bool,
}

impl BundleReceiver {
    /// Starts an empty private receiver with explicit resources and request policy.
    pub fn new(limits: BundleLimits, profile_requested: bool) -> Self {
        Self {
            limits,
            profile_requested,
            objects: Vec::new(),
            identities: BTreeSet::new(),
            profile: None,
            bytes: 0,
            failed: false,
        }
    }

    /// Returns retained body and access-profile bytes for resource accounting.
    pub fn buffered_bytes(&self) -> usize {
        self.bytes
    }

    /// Checks one frame without publishing or exposing any metadata.
    ///
    /// A requested access profile is optional and, if present, must be last.
    /// Empty streams are valid because the caller may already hold all objects.
    /// Object ordering and complete graph resolution remain the client's work.
    ///
    /// # Errors
    /// Rejects malformed frames, non-metadata kinds, noncanonical bytes, invalid
    /// or mismatching hashes, duplicate objects, resource excess and unrequested
    /// or nonfinal profiles. Every refusal releases retained data and latches
    /// [`BundleError::Terminated`] for subsequent pushes and completion.
    pub fn push(&mut self, frame: v1::BundleFrame) -> Result<(), BundleError> {
        if self.failed {
            return Err(BundleError::Terminated);
        }
        let result = self.push_frame(frame);
        if result.is_err() {
            self.failed = true;
            self.objects = Vec::new();
            self.identities = BTreeSet::new();
            self.profile = None;
            self.bytes = 0;
        }
        result
    }

    fn push_frame(&mut self, frame: v1::BundleFrame) -> Result<(), BundleError> {
        if self.profile.is_some() {
            return Err(BundleError::Order);
        }
        match frame.frame.ok_or(BundleError::Frame)? {
            Frame::Object(object) => {
                let kind = metadata_kind(object.kind)?;
                if self.objects.len() >= self.limits.objects
                    || object.encoded.len() > self.limits.object_bytes
                {
                    return Err(BundleError::Limit);
                }
                let hash: Digest = object
                    .hash
                    .as_option()
                    .ok_or(BundleError::Hash)?
                    .value
                    .as_slice()
                    .try_into()
                    .map_err(|_| BundleError::Hash)?;
                let bytes = self.checked_bytes(object.encoded.len())?;
                let checked =
                    BundleObject::new(kind, object.encoded).map_err(BundleError::Metadata)?;
                if checked.hash() != &hash {
                    return Err(BundleError::Hash);
                }
                if !self.identities.insert((kind, hash)) {
                    return Err(BundleError::Duplicate);
                }
                self.objects
                    .try_reserve(1)
                    .map_err(|_| BundleError::Limit)?;
                self.objects.push(checked);
                self.bytes = bytes;
            }
            Frame::AccessProfile(profile) => {
                if !self.profile_requested {
                    return Err(BundleError::Profile);
                }
                if profile.len() > self.limits.profile_bytes {
                    return Err(BundleError::Limit);
                }
                self.bytes = self.checked_bytes(profile.len())?;
                self.profile = Some(profile);
            }
        }
        Ok(())
    }

    fn checked_bytes(&self, incoming: usize) -> Result<usize, BundleError> {
        self.bytes
            .checked_add(incoming)
            .filter(|bytes| *bytes <= self.limits.total_bytes)
            .ok_or(BundleError::Limit)
    }

    /// Completes private reception after the caller observes actual EOF.
    ///
    /// Completion is not graph completeness, signature verification, current
    /// authorization or store admission. A transport failure or cancellation
    /// must drop the receiver instead of calling this method.
    ///
    /// # Errors
    /// Returns [`BundleError::Terminated`] after any rejected frame, or
    /// [`BundleError::Validation`] when the configured schema validator refuses
    /// any object. A refusal exposes no partial result.
    pub fn finish<V: ContentValidator>(self, validator: &V) -> Result<ReceivedBundle, BundleError> {
        if self.failed {
            return Err(BundleError::Terminated);
        }
        for object in &self.objects {
            let upload = MetaUpload::new(object.kind().identity_kind(), object.bytes())
                .map_err(BundleError::Validation)?;
            validator
                .validate_meta(&upload)
                .map_err(BundleError::Validation)?;
        }
        Ok(ReceivedBundle {
            objects: self.objects,
            profile: self.profile,
        })
    }
}

/// Carries checked object representations and an optional untrusted profile.
///
/// Object identities, canonical encodings and configured schemas are checked,
/// but signatures, reachability, dependency closure and authority have not been
/// established.
pub struct ReceivedBundle {
    objects: Vec<BundleObject>,
    profile: Option<Vec<u8>>,
}

impl ReceivedBundle {
    /// Borrows canonical identity-checked objects in their received order.
    pub fn objects(&self) -> &[BundleObject] {
        &self.objects
    }

    /// Borrows opaque profile bytes requiring separate registered validation.
    pub fn access_profile(&self) -> Option<&[u8]> {
        self.profile.as_deref()
    }
}

/// Reports refused bundle representations without classifying repository state.
#[derive(Debug)]
pub enum BundleError {
    /// Requires positive finite resource bounds within the format limits.
    Limits,
    /// Refuses an exceeded count, body, aggregate or allocation bound.
    Limit,
    /// Requires a populated frame variant.
    Frame,
    /// Allows only node, manifest and commit metadata, never data chunks.
    Kind,
    /// Requires an exact 32-byte hash matching the canonical metadata body.
    Hash,
    /// Preserves canonical format or identity-construction failures.
    Metadata(PackError),
    /// Preserves a configured metadata schema validator refusal.
    Validation(StoreFailure),
    /// Refuses repeated metadata identities even when their bytes agree.
    Duplicate,
    /// Refuses an access profile that the caller did not request.
    Profile,
    /// Refuses every frame following the optional final access profile.
    Order,
    /// Refuses further use after an earlier frame rejection.
    Terminated,
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limits => "invalid finite bundle limits",
            Self::Limit => "bundle exceeds its resource allowance",
            Self::Frame => "missing bundle frame variant",
            Self::Kind => "bundle requires node, manifest or commit metadata",
            Self::Hash => "bundle metadata hash is missing, malformed or inconsistent",
            Self::Metadata(_) => "invalid canonical bundle metadata",
            Self::Validation(_) => "bundle metadata failed configured schema validation",
            Self::Duplicate => "duplicate bundle metadata identity",
            Self::Profile => "unrequested bundle access profile",
            Self::Order => "frame follows final bundle access profile",
            Self::Terminated => "bundle reception was already rejected",
        })
    }
}

impl std::error::Error for BundleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Metadata(error) => Some(error),
            Self::Validation(error) => Some(error),
            _ => None,
        }
    }
}

fn metadata_kind(kind: u32) -> Result<EntryKind, BundleError> {
    let kind = u8::try_from(kind).map_err(|_| BundleError::Kind)?;
    let kind = EntryKind::try_from(kind).map_err(|_| BundleError::Kind)?;
    if !matches!(
        kind,
        EntryKind::Node | EntryKind::Manifest | EntryKind::Commit
    ) {
        return Err(BundleError::Kind);
    }
    Ok(kind)
}
