//! Records original shared-owner edges without serializing process addresses.
//!
//! The precharged lookup compares borrowed backing addresses only during the
//! exclusive source walk. Encoded rows carry a closed kind and local first-group
//! index. They preserve historical aliases but cannot identify or enroll a live
//! original actor, registrar or policy in another process.
//!
//! ```json
//! [["registrar-epoch",0],["registrar-gate",1],["registrar-epoch",0]]
//! ```

use crate::ProviderError;
use serde::{Serialize, Serializer, ser::SerializeSeq};

/// Identifies a closed shared backing category in the whole-eleven graph.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum MetadataSharedKind {
    /// Names an original protocol-capture actor header.
    ProtocolOwner,
    /// Names the original registrar's epoch counter backing.
    RegistrarEpoch,
    /// Names the original registrar's registration gate backing.
    RegistrarGate,
    /// Names one immutable selected-extension slice backing.
    SelectedExtensions,
    /// Names an immutable codec enum backing.
    Codec,
    /// Names an immutable native policy backing.
    NativePolicy,
    /// Names an original Hello literal bank backing.
    HelloBank,
    /// Names one content Vec backing; content-eight edges separately verify it.
    ContentBytes,
    /// Names an original connection frame-bank backing.
    FrameBank,
    /// Names a retained verified private native boot backing.
    NativeBoot,
    /// Names a successful inherited bootstrap literal-bank backing.
    PrivateBootstrapBank,
    /// Names the actual empty installed native extension registry.
    InstalledRegistry,
    /// Names the actual native failure supervisor backing.
    NativeSupervisor,
    /// Names an actual native blob ledger backing.
    BlobLedger,
    /// Names the actual source-installed host supervisor backing.
    HostSupervisor,
    /// Names one original mutable operational deadline backing.
    OperationalDeadline,
    /// Names the actual prepared archive-mapping identity retained by restore.
    ArchivedMapping,
}

impl MetadataSharedKind {
    fn name(self) -> &'static str {
        match self {
            Self::ProtocolOwner => "protocol-owner",
            Self::RegistrarEpoch => "registrar-epoch",
            Self::RegistrarGate => "registrar-gate",
            Self::SelectedExtensions => "selected-extensions",
            Self::Codec => "codec",
            Self::NativePolicy => "native-policy",
            Self::HelloBank => "hello-bank",
            Self::ContentBytes => "content-bytes",
            Self::FrameBank => "frame-bank",
            Self::NativeBoot => "native-boot",
            Self::PrivateBootstrapBank => "private-bootstrap-bank",
            Self::InstalledRegistry => "installed-registry",
            Self::NativeSupervisor => "native-supervisor",
            Self::BlobLedger => "blob-ledger",
            Self::HostSupervisor => "host-supervisor",
            Self::OperationalDeadline => "operational-deadline",
            Self::ArchivedMapping => "archived-mapping",
        }
    }
}

#[derive(Clone, Copy)]
struct AliasKey {
    kind: MetadataSharedKind,
    address: *const (),
}

#[derive(Clone, Copy)]
struct AliasRow {
    kind: MetadataSharedKind,
    first: usize,
}

/// Reports actual alias row and private temporary lookup allocations separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MetadataAliasAllocationFacts {
    /// States the selected finite shared-view ceiling.
    pub maximum_rows: usize,
    /// Reports actual allocated encoded-row capacity.
    pub row_capacity: usize,
    /// Reports actual allocated private lookup-key capacity.
    pub lookup_capacity: usize,
    /// Counts retained historical shared edges.
    pub retained_rows: usize,
    /// Reports the encoded row vector backing bytes.
    pub row_bytes: usize,
    /// Reports the private walk-only lookup vector backing bytes.
    pub lookup_bytes: usize,
}

/// Owns precharged local alias rows and private walk-only lookup storage.
pub struct MetadataAliasBank {
    rows: Vec<AliasRow>,
    keys: Vec<AliasKey>,
    maximum: usize,
    comparisons: usize,
}

impl MetadataAliasBank {
    /// Reserves both fixed-capacity banks before any source state copies.
    ///
    /// # Errors
    /// Refuses zero or more than131072 rows, overflow or failed reservation.
    pub fn reserve(maximum: usize) -> Result<Self, ProviderError> {
        if maximum == 0 || maximum > 131072 {
            return Err(credit());
        }
        maximum
            .checked_mul(std::mem::size_of::<AliasRow>() + std::mem::size_of::<AliasKey>())
            .ok_or_else(credit)?;
        let mut rows = Vec::new();
        let mut keys = Vec::new();
        rows.try_reserve_exact(maximum).map_err(|_| credit())?;
        keys.try_reserve_exact(maximum).map_err(|_| credit())?;
        Ok(Self {
            rows,
            keys,
            maximum,
            comparisons: 0,
        })
    }

    /// Reports actual requested storage of both precharged vectors.
    pub fn allocated_bytes(&self) -> usize {
        self.rows.capacity() * std::mem::size_of::<AliasRow>()
            + self.keys.capacity() * std::mem::size_of::<AliasKey>()
    }

    /// Counts every recorded shared view, including repeated group edges.
    pub fn retained_rows(&self) -> usize {
        self.rows.len()
    }

    /// Reports actual row and temporary key capacities independently.
    pub fn capacity_rows(&self) -> (usize, usize) {
        (self.rows.capacity(), self.keys.capacity())
    }

    /// Reads the two actual precharged vector capacities without copying rows.
    pub fn allocation_facts(&self) -> MetadataAliasAllocationFacts {
        let (row_capacity, lookup_capacity) = self.capacity_rows();
        MetadataAliasAllocationFacts {
            maximum_rows: self.maximum,
            row_capacity,
            lookup_capacity,
            retained_rows: self.retained_rows(),
            row_bytes: self.rows.capacity() * std::mem::size_of::<AliasRow>(),
            lookup_bytes: self.keys.capacity() * std::mem::size_of::<AliasKey>(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.rows.clear();
        self.keys.clear();
        self.comparisons = 0;
    }

    pub(crate) fn retain<T: ?Sized>(
        &mut self,
        kind: MetadataSharedKind,
        backing: &T,
    ) -> Result<(), ProviderError> {
        if self.rows.len() >= self.maximum || self.rows.len() == self.rows.capacity() {
            return Err(credit());
        }
        // Addresses are comparison keys only. Neither serialization nor callers
        // can obtain them, and no raw pointer is ever dereferenced here.
        let address = std::ptr::from_ref(backing).cast::<()>();
        let mut existing = None;
        for (index, key) in self.keys.iter().enumerate() {
            self.comparisons = self.comparisons.checked_add(1).ok_or_else(credit)?;
            if self.comparisons > 64 * 1024 * 1024 {
                return Err(credit());
            }
            if key.kind == kind && key.address == address {
                existing = Some(index);
                break;
            }
        }
        let first = if let Some(index) = existing {
            index
        } else {
            if self.keys.len() == self.keys.capacity() {
                return Err(credit());
            }
            let index = self.keys.len();
            self.keys.push(AliasKey { kind, address });
            index
        };
        self.rows.push(AliasRow { kind, first });
        Ok(())
    }

    pub(crate) fn finish_lookup(&mut self) {
        // Historical numeric edges remain; transient process addresses do not.
        self.keys.clear();
    }
}

impl Serialize for MetadataAliasBank {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut rows = serializer.serialize_seq(Some(self.rows.len()))?;
        for row in &self.rows {
            rows.serialize_element(&(row.kind.name(), row.first))?;
        }
        rows.end()
    }
}

fn credit() -> ProviderError {
    ProviderError::ResourceExhausted("whole protocol alias roster")
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "alias fixtures preserve original backing identity and spare allocation"
)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn shared_alias_and_equal_distinct_empty_backings_have_different_groups() {
        let first = Rc::new(Vec::<u8>::with_capacity(19));
        let alias = first.clone();
        let distinct = Rc::new(Vec::<u8>::with_capacity(19));
        let mut bank = MetadataAliasBank::reserve(4).unwrap();
        let capacities = bank.capacity_rows();
        bank.retain(MetadataSharedKind::ContentBytes, first.as_ref())
            .unwrap();
        bank.retain(MetadataSharedKind::ContentBytes, alias.as_ref())
            .unwrap();
        bank.retain(MetadataSharedKind::ContentBytes, distinct.as_ref())
            .unwrap();
        bank.finish_lookup();

        assert_eq!(bank.capacity_rows(), capacities);
        assert_eq!(bank.keys.len(), 0);
        assert_eq!(
            serde_json::to_vec(&bank).unwrap(),
            br#"[["content-bytes",0],["content-bytes",0],["content-bytes",1]]"#
        );
        assert_eq!(bank.allocation_facts().retained_rows, 3);
    }

    #[test]
    fn fixed_row_exhaustion_preserves_prior_edges_and_capacities() {
        let first = Rc::new(7u64);
        let second = Rc::new(7u64);
        let mut bank = MetadataAliasBank::reserve(1).unwrap();
        bank.retain(MetadataSharedKind::RegistrarEpoch, first.as_ref())
            .unwrap();
        let before = serde_json::to_vec(&bank).unwrap();
        let allocation = bank.allocation_facts();
        assert!(
            bank.retain(MetadataSharedKind::RegistrarEpoch, second.as_ref())
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&bank).unwrap(), before);
        assert_eq!(bank.allocation_facts(), allocation);
    }
}

/// Reports exact inline layouts of the retained alias row and walk lookup key.
///
/// Allocation headers, alignment and allocator geometry remain separate facts.
pub(crate) const fn original_metadata_alias_layouts() -> (usize, usize) {
    (
        std::mem::size_of::<AliasRow>(),
        std::mem::size_of::<AliasKey>(),
    )
}

impl MetadataAliasBank {
    pub(crate) fn retained_rows_of_kind(&self, kind: MetadataSharedKind) -> usize {
        self.rows.iter().filter(|row| row.kind == kind).count()
    }
}
