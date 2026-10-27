//! Encodes the signed original authorization scope of a commit (PROV-4).
//!
//! Context preserves authoring scope across later ref, surface, and locality
//! changes. Its root/domain assertions still require canonical tree witnesses.
//!
//! ```text
//! {1: original_ref, 2: surface, 3: locality,
//!  4: [[absolute_root_path, effective_domain], ...]}
//! ```

use super::{Locality, RecordError, RefName};
use crate::{
    auth::Request,
    cbor::{self, Decoder},
};
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

/// Preserves one affected absolute root and its asserted effective domain.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CommitContextRoot {
    path: Vec<u8>,
    domain: String,
}

impl CommitContextRoot {
    /// Returns the canonical absolute root path bytes.
    pub fn path(&self) -> &[u8] {
        &self.path
    }

    /// Returns the effective disclosure domain asserted by the signer.
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

/// Binds the original authoring request into the signed profile pair.
///
/// This type validates syntax and canonical ordering, not whether the claimed
/// roots and domains correspond to the candidate and previous trees (PROV-4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitContext {
    reference: String,
    surface: String,
    locality: Locality,
    roots: Vec<CommitContextRoot>,
}

impl CommitContext {
    /// Copies a request's scope into canonical signed authoring context.
    ///
    /// Roots are sorted by unsigned path bytes followed by UTF-8 domain bytes.
    /// The request's time and epochs remain in commit provenance and trusted
    /// epoch evidence rather than this context map.
    ///
    /// # Errors
    /// Returns [`RecordError`] for invalid ref, unregistered surface, malformed
    /// absolute paths, an empty root list, or duplicate root/domain pairs.
    pub fn from_request(request: &Request<'_>) -> Result<Self, RecordError> {
        let reference = core::str::from_utf8(request.reference)
            .map_err(|_| RecordError::Schema)?
            .to_string();
        let mut roots: Vec<_> = request
            .roots
            .iter()
            .map(|root| CommitContextRoot {
                path: root.path.to_vec(),
                domain: root.domain.to_string(),
            })
            .collect();
        roots.sort();

        let context = Self {
            reference,
            surface: request.surface.to_string(),
            locality: request.locality.clone(),
            roots,
        };
        context.validate()?;
        Ok(context)
    }

    /// Returns the original canonical ref name.
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Returns the registered producing surface.
    pub fn surface(&self) -> &str {
        &self.surface
    }

    /// Returns the original authoring locality.
    pub const fn locality(&self) -> &Locality {
        &self.locality
    }

    /// Returns the sorted affected root/domain assertions.
    pub fn roots(&self) -> &[CommitContextRoot] {
        &self.roots
    }

    /// Compares canonical authoring scope without authenticating its root claims.
    pub(crate) fn matches_request(&self, request: &Request<'_>) -> bool {
        Self::from_request(request).is_ok_and(|context| context == *self)
    }

    fn validate(&self) -> Result<(), RecordError> {
        RefName::parse(&self.reference).map_err(|_| RecordError::Schema)?;
        if !matches!(
            self.surface.as_str(),
            "sdk"
                | "fuse"
                | "erofs"
                | "block"
                | "virtiofs"
                | "virtio-pmem"
                | "nix-cache"
                | "reapi"
                | "gha-cache"
                | "git"
                | "oci"
                | "browse"
                | "api"
        ) || self.roots.is_empty()
            || self.roots.windows(2).any(|pair| pair[0] >= pair[1])
            || self.roots.iter().any(|root| {
                root.path != b"/"
                    && !root
                        .path
                        .strip_prefix(b"/")
                        .is_some_and(|path| crate::tree_format::validate_key(path).is_ok())
            })
        {
            return Err(RecordError::Schema);
        }
        Ok(())
    }

    /// Appends the canonical signed original-context map.
    ///
    /// # Errors
    /// Rejects invalid refs, surfaces, root paths, empty roots and duplicate pairs.
    pub(super) fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), RecordError> {
        self.validate()?;
        cbor::write_map(output, 4);
        cbor::write_uint(output, 1);
        cbor::write_text(output, &self.reference);
        cbor::write_uint(output, 2);
        cbor::write_text(output, &self.surface);
        cbor::write_uint(output, 3);
        self.locality.encode_into(output);
        cbor::write_uint(output, 4);
        cbor::write_array(output, self.roots.len());
        for root in &self.roots {
            cbor::write_array(output, 2);
            cbor::write_bytes(output, &root.path);
            cbor::write_text(output, &root.domain);
        }
        Ok(())
    }

    /// Decodes canonical original-context claims without supplying tree witnesses.
    ///
    /// # Errors
    /// Rejects malformed or noncanonical fields, unsupported surfaces, invalid
    /// root paths, empty roots, duplicates and noncanonical pair ordering.
    pub(super) fn decode_from(decoder: &mut Decoder<'_>) -> Result<Self, RecordError> {
        if decoder.map(4)? != 4 || decoder.uint()? != 1 {
            return Err(RecordError::Schema);
        }
        let reference = decoder.text(decoder.remaining().len())?.to_string();
        if decoder.uint()? != 2 {
            return Err(RecordError::Schema);
        }
        let surface = decoder.text(decoder.remaining().len())?.to_string();
        if decoder.uint()? != 3 {
            return Err(RecordError::Schema);
        }
        let locality = Locality::decode_from(decoder)?;
        if decoder.uint()? != 4 {
            return Err(RecordError::Schema);
        }
        // The CBOR limit rejects input-sized allocations before collection.
        let count = decoder.array(decoder.remaining().len())?;
        let mut roots = Vec::new();
        for _ in 0..count {
            if decoder.array(2)? != 2 {
                return Err(RecordError::Schema);
            }
            let path = decoder.bytes(4097)?.to_vec();
            let domain = decoder.text(decoder.remaining().len())?.to_string();
            roots.push(CommitContextRoot { path, domain });
        }
        let context = Self {
            reference,
            surface,
            locality,
            roots,
        };
        context.validate()?;
        Ok(context)
    }
}
