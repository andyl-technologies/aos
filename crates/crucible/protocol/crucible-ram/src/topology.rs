//! SPDX-License-Identifier: MIT OR Apache-2.0
//! Validates portable region ownership, scope membership, and logical geometry.
//!
//! ```text
//! Inventory = U32(count) || sorted(S(id) || U8(class) || U8(mask) || U64(length))
//! S(id) = U32(UTF-8 byte length) || exact UTF-8 bytes
//! ```

use crate::digest::tagged;
use crate::{LOGICAL_PAGE_SIZE, RamError, TopologyDigest};
use std::sync::Arc;

/// Receiver-controlled bounds checked before traversal or allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum accepted regions, additionally capped at the edition's 4096.
    pub max_regions: usize,
    /// Maximum aggregate logical byte length across all regions.
    pub max_logical_bytes: u64,
    /// Maximum encoded record bytes accepted by a decoder.
    pub max_record_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_regions: 4096,
            max_logical_bytes: u64::MAX,
            max_record_bytes: 3 * 1024 * 1024,
        }
    }
}

/// A checked region geometry with a fixed logical page size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    length: u64,
    count: u64,
    height: u32,
}

impl Geometry {
    /// Computes canonical page count and padded height for a positive length.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::InvalidLength`] for zero length.
    pub fn new(logical_length: u64) -> Result<Self, RamError> {
        if logical_length == 0 {
            return Err(RamError::InvalidLength);
        }
        let count = 1 + (logical_length - 1) / u64::from(LOGICAL_PAGE_SIZE);
        let width = count
            .checked_next_power_of_two()
            .ok_or(RamError::Overflow)?;
        Ok(Self {
            length: logical_length,
            count,
            height: width.trailing_zeros(),
        })
    }

    /// Returns the exact logical byte length.
    pub const fn logical_length(self) -> u64 {
        self.length
    }

    /// Returns the number of real pages, excluding padding.
    pub const fn page_count(self) -> u64 {
        self.count
    }

    /// Returns the canonical region tree height.
    pub const fn height(self) -> u32 {
        self.height
    }

    /// Returns the padded leaf count as a power of two.
    pub const fn padded_leaf_count(self) -> u64 {
        1_u64 << self.height
    }

    /// Returns the required valid byte length for a real page index.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::OutOfRange`] for a padding or absent page.
    pub fn valid_length(self, page_index: u64) -> Result<u32, RamError> {
        if page_index >= self.count {
            return Err(RamError::OutOfRange);
        }
        let offset = page_index
            .checked_mul(u64::from(LOGICAL_PAGE_SIZE))
            .ok_or(RamError::Overflow)?;
        Ok((self.length - offset).min(u64::from(LOGICAL_PAGE_SIZE)) as u32)
    }
}

/// A closed region classification with fixed scope membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RegionClass {
    /// Ordinary guest-observable mutable RAM; coverage mask 7.
    MutableMain = 1,
    /// Guest-observable mutable device RAM; coverage mask 7.
    MutableDevice = 2,
    /// Admitted immutable launch/image bytes; coverage mask 6.
    ImmutableImage = 3,
    /// Reconstruction RAM represented outside execution RAM identity; mask 6.
    ContinuationPrivate = 4,
}

impl RegionClass {
    /// Returns the fixed execution/exact/lifecycle coverage mask.
    pub const fn coverage_mask(self) -> u8 {
        match self {
            Self::MutableMain | Self::MutableDevice => 7,
            _ => 6,
        }
    }

    pub(crate) fn decode(value: u8) -> Result<Self, RamError> {
        match value {
            1 => Ok(Self::MutableMain),
            2 => Ok(Self::MutableDevice),
            3 => Ok(Self::ImmutableImage),
            4 => Ok(Self::ContinuationPrivate),
            _ => Err(RamError::InvalidEncoding),
        }
    }
}

/// A named scope, distinct even when the selected bytes are identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Guest-observable mutable RAM in an execution fingerprint.
    Execution,
    /// Complete RAM inventory in an exact checkpoint.
    Exact,
    /// Complete RAM inventory in a retained lifecycle source seal.
    Lifecycle,
}

impl Scope {
    /// Returns the exact ASCII string committed by a scoped root.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Execution => "execution",
            Self::Exact => "exact",
            Self::Lifecycle => "lifecycle",
        }
    }

    /// Returns whether the region belongs to this scope.
    pub const fn includes(self, class: RegionClass) -> bool {
        let bit = match self {
            Self::Execution => 1,
            Self::Exact => 2,
            Self::Lifecycle => 4,
        };
        class.coverage_mask() & bit != 0
    }

    pub(crate) fn decode(value: &str) -> Result<Self, RamError> {
        match value {
            "execution" => Ok(Self::Execution),
            "exact" => Ok(Self::Exact),
            "lifecycle" => Ok(Self::Lifecycle),
            _ => Err(RamError::InvalidEncoding),
        }
    }
}

/// A validated portable region descriptor with no native mapping information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionDescriptor {
    id: String,
    class: RegionClass,
    geometry: Geometry,
}

impl RegionDescriptor {
    /// Validates a stable UTF-8 identifier, class, and positive logical length.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::InvalidRegionId`] for an empty, excessive, or control-
    /// containing identifier, or [`RamError::InvalidLength`] for zero length.
    pub fn new(
        id: impl Into<String>,
        class: RegionClass,
        logical_length: u64,
    ) -> Result<Self, RamError> {
        let id = id.into();
        validate_id(&id)?;
        Ok(Self {
            id,
            class,
            geometry: Geometry::new(logical_length)?,
        })
    }

    /// Returns the exact stable identifier, without Unicode normalization.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the region classification.
    pub const fn class(&self) -> RegionClass {
        self.class
    }

    /// Returns the classification's fixed scope mask.
    pub const fn coverage_mask(&self) -> u8 {
        self.class.coverage_mask()
    }

    /// Returns the exact logical byte length.
    pub const fn logical_length(&self) -> u64 {
        self.geometry.logical_length()
    }

    /// Returns the region's checked canonical geometry.
    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    pub(crate) fn encode_into(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&(self.id.len() as u32).to_be_bytes());
        output.extend_from_slice(self.id.as_bytes());
        output.push(self.class as u8);
        output.push(self.coverage_mask());
        output.extend_from_slice(&self.logical_length().to_be_bytes());
    }
}

pub(crate) fn validate_id(id: &str) -> Result<(), RamError> {
    if id.is_empty()
        || id.len() > 255
        || id
            .chars()
            .any(|character| character <= '\u{1f}' || character == '\u{7f}')
    {
        return Err(RamError::InvalidRegionId);
    }
    Ok(())
}

/// An immutable complete inventory sorted by unsigned UTF-8 identifier bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Topology {
    regions: Arc<[RegionDescriptor]>,
    digest: TopologyDigest,
    total_length: u64,
}

impl Topology {
    /// Bounds the retained inventory allocation sizes, including identifier capacity.
    ///
    /// The bound includes the shared region slice and its reference counters.
    /// Allocator bookkeeping and process memory accounting remain external.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::Overflow`] if the retained sizes cannot be composed.
    pub fn metadata_bytes(&self) -> Result<u64, RamError> {
        let descriptors = self
            .regions
            .len()
            .checked_mul(std::mem::size_of::<RegionDescriptor>())
            .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
            .ok_or(RamError::Overflow)?;
        self.regions
            .iter()
            .try_fold(descriptors as u64, |bytes, region| {
                bytes
                    .checked_add(region.id.capacity() as u64)
                    .ok_or(RamError::Overflow)
            })
    }

    /// Constructs a canonical inventory within the supplied admission limits.
    ///
    /// Empty topology is allowed for mathematical vectors. Execution admission
    /// remains responsible for requiring its machine's necessary regions.
    ///
    /// # Errors
    ///
    /// Returns [`RamError::ResourceLimit`] for excessive counts or aggregate
    /// bytes, [`RamError::InvalidOrder`] for duplicates, or overflow errors.
    pub fn new(mut regions: Vec<RegionDescriptor>, limits: Limits) -> Result<Self, RamError> {
        if regions.len() > limits.max_regions.min(4096) {
            return Err(RamError::ResourceLimit);
        }
        regions.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
        let mut total_length = 0_u64;
        let mut previous: Option<&str> = None;
        for region in &regions {
            if previous == Some(region.id()) {
                return Err(RamError::InvalidOrder);
            }
            previous = Some(region.id());
            total_length = total_length
                .checked_add(region.logical_length())
                .ok_or(RamError::Overflow)?;
            if total_length > limits.max_logical_bytes {
                return Err(RamError::ResourceLimit);
            }
        }

        let mut hasher = tagged("topology");
        hasher.update(&LOGICAL_PAGE_SIZE.to_be_bytes());
        hasher.update(&(regions.len() as u32).to_be_bytes());
        for region in &regions {
            let mut descriptor = Vec::with_capacity(269);
            region.encode_into(&mut descriptor);
            hasher.update(&descriptor);
        }
        Ok(Self {
            regions: regions.into(),
            digest: TopologyDigest::from_bytes(*hasher.finalize().as_bytes()),
            total_length,
        })
    }

    /// Returns the complete canonical region inventory.
    pub fn regions(&self) -> &[RegionDescriptor] {
        &self.regions
    }

    /// Returns the complete topology commitment.
    pub const fn digest(&self) -> TopologyDigest {
        self.digest
    }

    /// Returns aggregate logical bytes, validated without wrapping.
    pub const fn total_logical_bytes(&self) -> u64 {
        self.total_length
    }

    /// Looks up a stable region identifier in canonical order.
    pub fn region(&self, id: &str) -> Option<&RegionDescriptor> {
        self.regions
            .binary_search_by(|region| region.id().as_bytes().cmp(id.as_bytes()))
            .ok()
            .map(|index| &self.regions[index])
    }

    /// Encodes the canonical inventory, excluding its domain tag and page size.
    pub fn encode_inventory(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.inventory_encoded_len());
        output.extend_from_slice(&(self.regions.len() as u32).to_be_bytes());
        for region in &*self.regions {
            region.encode_into(&mut output);
        }
        output
    }

    /// Returns the exact bounded inventory encoding length for admission.
    pub fn inventory_encoded_len(&self) -> usize {
        4 + self
            .regions
            .iter()
            .map(|region| 14 + region.id().len())
            .sum::<usize>()
    }
}
