//! Registry-free packed string and path destinations.
//!
//! The finalized lane stores string and path identities in separate fixed-
//! stride record vectors. Both record kinds borrow from one byte pool and one
//! shared context table:
//!
//! ```text
//! string/path record
//!   byte_start:u32 | byte_count:u32 | context:u32         12 bytes
//! context record
//!   element_start:u32 | element_count:u32                  8 bytes
//! context element
//!   path range | output range | kind:u8                    20 bytes
//! byte pool
//!   string/path bytes and context path/output bytes         1 byte each
//! ```
//!
//! [`PackedStringLaneDirectBuilder`] reserves every vector before copying any
//! source data. Finalization exposes only allocation-free borrowed views and
//! retains no source identity, hash table, pointer registry, `Arc`, or `Vec`
//! per object.

use std::mem;

use thiserror::Error;

use crate::string::{ContextKind, NixString, StringContext};

/// A direct fixed-record coordinate for a packed Nix string.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PackedStringRef(u32);

impl PackedStringRef {
    /// Builds a direct coordinate for checked lane resolution.
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the fixed-record index.
    pub(crate) const fn index(self) -> u32 {
        self.0
    }
}

/// A direct fixed-record coordinate for a packed Nix path.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PackedPathRef(u32);

impl PackedPathRef {
    /// Builds a direct coordinate for checked lane resolution.
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the fixed-record index.
    pub(crate) const fn index(self) -> u32 {
        self.0
    }
}

/// A direct coordinate for one canonical packed string context.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PackedStringContextRef(u32);

impl PackedStringContextRef {
    /// Builds a direct coordinate for checked lane resolution.
    pub(crate) const fn from_index(index: u32) -> Self {
        Self(index)
    }

    /// Returns the fixed-record index.
    pub(crate) const fn index(self) -> u32 {
        self.0
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackedStringRecord {
    byte_start: u32,
    byte_count: u32,
    context: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackedContextRecord {
    element_start: u32,
    element_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PackedContextElement {
    path_start: u32,
    path_count: u32,
    output_start: u32,
    output_count: u32,
    kind: u8,
    padding: [u8; 3],
}

const PACKED_CONTEXT_OPAQUE_PATH: u8 = 0;
const PACKED_CONTEXT_SINGLE_OUTPUT: u8 = 1;
const PACKED_CONTEXT_DEEP_DERIVATION: u8 = 2;

impl PackedContextElement {
    fn kind(self) -> Result<ContextKind, PackedStringLaneError> {
        match self.kind {
            PACKED_CONTEXT_OPAQUE_PATH => Ok(ContextKind::OpaquePath),
            PACKED_CONTEXT_SINGLE_OUTPUT => Ok(ContextKind::SingleOutput),
            PACKED_CONTEXT_DEEP_DERIVATION => Ok(ContextKind::DeepDerivation),
            kind => Err(PackedStringLaneError::MalformedContextKind { kind }),
        }
    }
}

/// Exact per-vector bytes owned by a finalized packed string lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedStringLaneBytes {
    /// Bytes occupied by the finalized lane's vector descriptors.
    pub(crate) control: usize,
    /// Bytes occupied by initialized string records.
    pub(crate) strings: usize,
    /// Bytes occupied by initialized path records.
    pub(crate) paths: usize,
    /// Bytes occupied by initialized context records.
    pub(crate) contexts: usize,
    /// Bytes occupied by initialized context elements.
    pub(crate) context_elements: usize,
    /// Bytes occupied by string, path, context-path, and output bytes.
    pub(crate) bytes: usize,
}

impl PackedStringLaneBytes {
    /// Returns the checked sum of every reported component.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError::ByteAccountingOverflow`] when the
    /// component byte counts cannot be summed in `usize`.
    pub(crate) fn total(self) -> Result<usize, PackedStringLaneError> {
        [
            self.control,
            self.strings,
            self.paths,
            self.contexts,
            self.context_elements,
            self.bytes,
        ]
        .into_iter()
        .try_fold(0usize, |total, bytes| {
            total
                .checked_add(bytes)
                .ok_or(PackedStringLaneError::ByteAccountingOverflow)
        })
    }
}

/// Exact logical element counts admitted for one direct packed build.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PackedStringLaneCapacities {
    /// Packed Nix string records.
    pub(crate) strings: usize,
    /// Packed Nix path records.
    pub(crate) paths: usize,
    /// Canonical string-context records.
    pub(crate) contexts: usize,
    /// Context elements across every distinct admitted context.
    pub(crate) context_elements: usize,
    /// All string, path, context-path, and output bytes.
    pub(crate) bytes: usize,
}

/// A finalized packed string/path destination with no object registry.
#[derive(Debug, Default)]
pub(crate) struct PackedStringLane {
    strings: Vec<PackedStringRecord>,
    paths: Vec<PackedStringRecord>,
    contexts: Vec<PackedContextRecord>,
    context_elements: Vec<PackedContextElement>,
    bytes: Vec<u8>,
}

impl PackedStringLane {
    /// Returns the number of packed string records.
    pub(crate) fn string_count(&self) -> usize {
        self.strings.len()
    }

    /// Returns the number of packed path records.
    pub(crate) fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Returns the number of distinct packed context records.
    pub(crate) fn context_count(&self) -> usize {
        self.contexts.len()
    }

    /// Returns the number of packed context elements.
    pub(crate) fn context_element_count(&self) -> usize {
        self.context_elements.len()
    }

    /// Returns the number of initialized bytes in the shared byte pool.
    pub(crate) fn byte_count(&self) -> usize {
        self.bytes.len()
    }

    /// Returns exact initialized bytes, including vector descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError::ByteAccountingOverflow`] when a vector
    /// length cannot be represented as a byte count.
    pub(crate) fn initialized_bytes(&self) -> Result<PackedStringLaneBytes, PackedStringLaneError> {
        self.bytes_with(
            self.strings.len(),
            self.paths.len(),
            self.contexts.len(),
            self.context_elements.len(),
            self.bytes.len(),
        )
    }

    /// Returns allocator-granted capacity bytes, including vector descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError::ByteAccountingOverflow`] when a vector
    /// capacity cannot be represented as a byte count.
    pub(crate) fn capacity_bytes(&self) -> Result<PackedStringLaneBytes, PackedStringLaneError> {
        self.bytes_with(
            self.strings.capacity(),
            self.paths.capacity(),
            self.contexts.capacity(),
            self.context_elements.capacity(),
            self.bytes.capacity(),
        )
    }

    fn bytes_with(
        &self,
        strings: usize,
        paths: usize,
        contexts: usize,
        context_elements: usize,
        bytes: usize,
    ) -> Result<PackedStringLaneBytes, PackedStringLaneError> {
        Ok(PackedStringLaneBytes {
            control: mem::size_of::<Self>(),
            strings: checked_bytes::<PackedStringRecord>(strings)?,
            paths: checked_bytes::<PackedStringRecord>(paths)?,
            contexts: checked_bytes::<PackedContextRecord>(contexts)?,
            context_elements: checked_bytes::<PackedContextElement>(context_elements)?,
            bytes,
        })
    }

    /// Returns an allocation-free view of one packed Nix string.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError`] when the coordinate or any stored
    /// string/context range is malformed.
    pub(crate) fn string(
        &self,
        reference: PackedStringRef,
    ) -> Result<PackedNixStringView<'_>, PackedStringLaneError> {
        let record = self
            .strings
            .get(reference.0 as usize)
            .copied()
            .ok_or(PackedStringLaneError::UnknownString { index: reference.0 })?;
        self.view(record, "string", reference.0)
    }

    /// Returns an allocation-free view of one packed Nix path.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError`] when the coordinate or any stored
    /// path/context range is malformed.
    pub(crate) fn path(
        &self,
        reference: PackedPathRef,
    ) -> Result<PackedNixStringView<'_>, PackedStringLaneError> {
        let record = self
            .paths
            .get(reference.0 as usize)
            .copied()
            .ok_or(PackedStringLaneError::UnknownPath { index: reference.0 })?;
        self.view(record, "path", reference.0)
    }

    /// Returns an allocation-free view of one canonical string context.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError`] when the coordinate, element range,
    /// element kind, path range, or output range is malformed.
    pub(crate) fn context(
        &self,
        reference: PackedStringContextRef,
    ) -> Result<PackedStringContextView<'_>, PackedStringLaneError> {
        let record = self
            .contexts
            .get(reference.0 as usize)
            .copied()
            .ok_or(PackedStringLaneError::UnknownContext { index: reference.0 })?;
        let elements = checked_slice(
            &self.context_elements,
            record.element_start,
            record.element_count,
            "context-element",
            reference.0,
        )?;
        for element in elements {
            element.kind()?;
            checked_slice(
                &self.bytes,
                element.path_start,
                element.path_count,
                "context-path",
                reference.0,
            )?;
            if element.kind == PACKED_CONTEXT_SINGLE_OUTPUT {
                checked_slice(
                    &self.bytes,
                    element.output_start,
                    element.output_count,
                    "context-output",
                    reference.0,
                )?;
            } else if element.output_start != 0 || element.output_count != 0 {
                return Err(PackedStringLaneError::MalformedUnexpectedOutput {
                    context: reference.0,
                });
            }
        }
        Ok(PackedStringContextView {
            elements,
            bytes: &self.bytes,
        })
    }

    fn view(
        &self,
        record: PackedStringRecord,
        object: &'static str,
        index: u32,
    ) -> Result<PackedNixStringView<'_>, PackedStringLaneError> {
        let bytes = checked_slice(
            &self.bytes,
            record.byte_start,
            record.byte_count,
            object,
            index,
        )?;
        let context = self.context(PackedStringContextRef(record.context))?;
        Ok(PackedNixStringView { bytes, context })
    }
}

/// An allocation-free borrowed view of a packed Nix string or path.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PackedNixStringView<'a> {
    bytes: &'a [u8],
    context: PackedStringContextView<'a>,
}

impl<'a> PackedNixStringView<'a> {
    /// Returns the exact byte string.
    pub(crate) const fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the exact canonical dependency context.
    pub(crate) const fn context(self) -> PackedStringContextView<'a> {
        self.context
    }
}

/// An allocation-free borrowed view of one canonical packed string context.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PackedStringContextView<'a> {
    elements: &'a [PackedContextElement],
    bytes: &'a [u8],
}

impl<'a> PackedStringContextView<'a> {
    /// Returns the number of canonical context elements.
    pub(crate) const fn len(self) -> usize {
        self.elements.len()
    }

    /// Returns whether this context is empty.
    pub(crate) const fn is_empty(self) -> bool {
        self.elements.is_empty()
    }

    /// Iterates exact context elements in canonical source order.
    pub(crate) fn iter(self) -> PackedStringContextIter<'a> {
        PackedStringContextIter {
            remaining: self.elements,
            bytes: self.bytes,
        }
    }
}

/// An allocation-free iterator over a validated packed string context.
#[derive(Clone, Debug)]
pub(crate) struct PackedStringContextIter<'a> {
    remaining: &'a [PackedContextElement],
    bytes: &'a [u8],
}

impl<'a> Iterator for PackedStringContextIter<'a> {
    type Item = PackedContextElementView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (element, remaining) = self.remaining.split_first()?;
        self.remaining = remaining;
        let path_start = element.path_start as usize;
        let path_end = path_start + element.path_count as usize;
        let kind = match element.kind {
            PACKED_CONTEXT_OPAQUE_PATH => ContextKind::OpaquePath,
            PACKED_CONTEXT_SINGLE_OUTPUT => ContextKind::SingleOutput,
            PACKED_CONTEXT_DEEP_DERIVATION => ContextKind::DeepDerivation,
            _ => return None,
        };
        let output = if kind == ContextKind::SingleOutput {
            let output_start = element.output_start as usize;
            let output_end = output_start + element.output_count as usize;
            Some(&self.bytes[output_start..output_end])
        } else {
            None
        };
        Some(PackedContextElementView {
            kind,
            path: &self.bytes[path_start..path_end],
            output,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining.len(), Some(self.remaining.len()))
    }
}

impl ExactSizeIterator for PackedStringContextIter<'_> {}

/// One exact borrowed context element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedContextElementView<'a> {
    kind: ContextKind,
    path: &'a [u8],
    output: Option<&'a [u8]>,
}

impl<'a> PackedContextElementView<'a> {
    /// Returns the deriving-path kind.
    pub(crate) const fn kind(self) -> ContextKind {
        self.kind
    }

    /// Returns the exact store-path bytes.
    pub(crate) const fn path(self) -> &'a [u8] {
        self.path
    }

    /// Returns the exact output bytes for `SingleOutput`.
    pub(crate) const fn output(self) -> Option<&'a [u8]> {
        self.output
    }
}

/// A pre-reserved, source-map-free packed string/path builder.
#[derive(Debug)]
pub(crate) struct PackedStringLaneDirectBuilder {
    lane: PackedStringLane,
    admitted: PackedStringLaneCapacities,
    admitted_capacity_bytes: PackedStringLaneBytes,
}

impl PackedStringLaneDirectBuilder {
    /// Reserves all record, context, element, and byte storage.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError`] when a capacity exceeds the direct
    /// coordinate width or a vector reservation fails.
    pub(crate) fn try_new(
        admitted: PackedStringLaneCapacities,
    ) -> Result<Self, PackedStringLaneError> {
        checked_range(0, admitted.strings, "string")?;
        checked_range(0, admitted.paths, "path")?;
        checked_range(0, admitted.contexts, "context")?;
        checked_range(0, admitted.context_elements, "context-element")?;
        checked_range(0, admitted.bytes, "byte")?;
        let mut lane = PackedStringLane::default();
        reserve(&mut lane.strings, admitted.strings, "string")?;
        reserve(&mut lane.paths, admitted.paths, "path")?;
        reserve(&mut lane.contexts, admitted.contexts, "context")?;
        reserve(
            &mut lane.context_elements,
            admitted.context_elements,
            "context-element",
        )?;
        reserve(&mut lane.bytes, admitted.bytes, "byte")?;
        let admitted_capacity_bytes = lane.capacity_bytes()?;
        Ok(Self {
            lane,
            admitted,
            admitted_capacity_bytes,
        })
    }

    /// Appends one canonical context and returns its direct coordinate.
    ///
    /// Callers may reuse the returned coordinate for every string or path that
    /// shared the source context. The source collector owns any temporary
    /// identity map; this finalized lane retains none.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError`] before mutation when logical admission
    /// is exhausted, coordinate arithmetic overflows, or a reserved vector's
    /// capacity changed unexpectedly.
    pub(crate) fn append_context(
        &mut self,
        context: &StringContext,
    ) -> Result<PackedStringContextRef, PackedStringLaneError> {
        let attempted_contexts = checked_attempt(self.lane.contexts.len(), 1, "context")?;
        check_admitted(attempted_contexts, self.admitted.contexts, "context")?;
        let attempted_elements = checked_attempt(
            self.lane.context_elements.len(),
            context.len(),
            "context-element",
        )?;
        check_admitted(
            attempted_elements,
            self.admitted.context_elements,
            "context-element",
        )?;
        let added_bytes = context.iter().try_fold(0usize, |total, element| {
            let total = total
                .checked_add(element.path().len())
                .ok_or(PackedStringLaneError::RangeOverflow { lane: "byte" })?;
            total
                .checked_add(element.output().map_or(0, <[u8]>::len))
                .ok_or(PackedStringLaneError::RangeOverflow { lane: "byte" })
        })?;
        let attempted_bytes = checked_attempt(self.lane.bytes.len(), added_bytes, "byte")?;
        check_admitted(attempted_bytes, self.admitted.bytes, "byte")?;
        let context_index = checked_index(self.lane.contexts.len(), "context")?;
        let (element_start, element_count) = checked_range(
            self.lane.context_elements.len(),
            context.len(),
            "context-element",
        )?;
        self.ensure_capacity_unchanged()?;

        for element in context {
            let (path_start, path_count) =
                checked_range(self.lane.bytes.len(), element.path().len(), "byte")?;
            self.lane.bytes.extend_from_slice(element.path());
            let (kind, output_start, output_count) = match element.kind() {
                ContextKind::OpaquePath => (PACKED_CONTEXT_OPAQUE_PATH, 0, 0),
                ContextKind::DeepDerivation => (PACKED_CONTEXT_DEEP_DERIVATION, 0, 0),
                ContextKind::SingleOutput => {
                    let output = element.output().unwrap_or_default();
                    let (start, count) =
                        checked_range(self.lane.bytes.len(), output.len(), "byte")?;
                    self.lane.bytes.extend_from_slice(output);
                    (PACKED_CONTEXT_SINGLE_OUTPUT, start, count)
                }
            };
            self.lane.context_elements.push(PackedContextElement {
                path_start,
                path_count,
                output_start,
                output_count,
                kind,
                padding: [0; 3],
            });
        }
        self.lane.contexts.push(PackedContextRecord {
            element_start,
            element_count,
        });
        Ok(PackedStringContextRef(context_index))
    }

    /// Appends one Nix string using an already-admitted context.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError`] before mutation when the context is
    /// stale, logical admission is exhausted, coordinate arithmetic overflows,
    /// or a reserved vector's capacity changed unexpectedly.
    pub(crate) fn append_string(
        &mut self,
        string: &NixString,
        context: PackedStringContextRef,
    ) -> Result<PackedStringRef, PackedStringLaneError> {
        self.validate_source_context(context, string.context())?;
        let index = self.append_text(string.bytes(), context, false)?;
        Ok(PackedStringRef(index))
    }

    /// Appends one Nix path using an already-admitted context.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError`] before mutation when the context is
    /// stale, logical admission is exhausted, coordinate arithmetic overflows,
    /// or a reserved vector's capacity changed unexpectedly.
    pub(crate) fn append_path(
        &mut self,
        path: &NixString,
        context: PackedStringContextRef,
    ) -> Result<PackedPathRef, PackedStringLaneError> {
        self.validate_source_context(context, path.context())?;
        let index = self.append_text(path.bytes(), context, true)?;
        Ok(PackedPathRef(index))
    }

    fn validate_source_context(
        &self,
        reference: PackedStringContextRef,
        source: &StringContext,
    ) -> Result<(), PackedStringLaneError> {
        let packed = self.lane.context(reference)?;
        let matches = packed.len() == source.len()
            && packed.iter().zip(source).all(|(packed, source)| {
                packed.kind() == source.kind()
                    && packed.path() == source.path()
                    && packed.output() == source.output()
            });
        if !matches {
            return Err(PackedStringLaneError::ContextMismatch {
                context: reference.0,
            });
        }
        Ok(())
    }

    fn append_text(
        &mut self,
        bytes: &[u8],
        context: PackedStringContextRef,
        path: bool,
    ) -> Result<u32, PackedStringLaneError> {
        if (context.0 as usize) >= self.lane.contexts.len() {
            return Err(PackedStringLaneError::UnknownContext { index: context.0 });
        }
        let (initialized, admitted, lane_name) = if path {
            (self.lane.paths.len(), self.admitted.paths, "path")
        } else {
            (self.lane.strings.len(), self.admitted.strings, "string")
        };
        let attempted_records = checked_attempt(initialized, 1, lane_name)?;
        check_admitted(attempted_records, admitted, lane_name)?;
        let attempted_bytes = checked_attempt(self.lane.bytes.len(), bytes.len(), "byte")?;
        check_admitted(attempted_bytes, self.admitted.bytes, "byte")?;
        let index = checked_index(initialized, lane_name)?;
        let (byte_start, byte_count) = checked_range(self.lane.bytes.len(), bytes.len(), "byte")?;
        self.ensure_capacity_unchanged()?;
        self.lane.bytes.extend_from_slice(bytes);
        let record = PackedStringRecord {
            byte_start,
            byte_count,
            context: context.0,
        };
        if path {
            self.lane.paths.push(record);
        } else {
            self.lane.strings.push(record);
        }
        Ok(index)
    }

    /// Finalizes the lane after verifying that no vector grew.
    ///
    /// # Errors
    ///
    /// Returns [`PackedStringLaneError::CapacityChanged`] if allocator capacity
    /// differs from the complete pre-build reservation.
    pub(crate) fn finish(self) -> Result<PackedStringLane, PackedStringLaneError> {
        self.ensure_capacity_unchanged()?;
        Ok(self.lane)
    }

    fn ensure_capacity_unchanged(&self) -> Result<(), PackedStringLaneError> {
        let actual = self.lane.capacity_bytes()?;
        if actual != self.admitted_capacity_bytes {
            return Err(PackedStringLaneError::CapacityChanged {
                admitted: self.admitted_capacity_bytes.total()?,
                actual: actual.total()?,
            });
        }
        Ok(())
    }
}

fn checked_index(index: usize, lane: &'static str) -> Result<u32, PackedStringLaneError> {
    u32::try_from(index).map_err(|_| PackedStringLaneError::IndexOverflow { lane, index })
}

fn checked_range(
    start: usize,
    count: usize,
    lane: &'static str,
) -> Result<(u32, u32), PackedStringLaneError> {
    let start = checked_index(start, lane)?;
    let count =
        u32::try_from(count).map_err(|_| PackedStringLaneError::CountOverflow { lane, count })?;
    start
        .checked_add(count)
        .ok_or(PackedStringLaneError::RangeOverflow { lane })?;
    Ok((start, count))
}

fn checked_attempt(
    initialized: usize,
    additional: usize,
    lane: &'static str,
) -> Result<usize, PackedStringLaneError> {
    initialized
        .checked_add(additional)
        .ok_or(PackedStringLaneError::RangeOverflow { lane })
}

fn check_admitted(
    attempted: usize,
    admitted: usize,
    lane: &'static str,
) -> Result<(), PackedStringLaneError> {
    if attempted > admitted {
        return Err(PackedStringLaneError::CapacityExceeded {
            lane,
            admitted,
            attempted,
        });
    }
    Ok(())
}

fn checked_bytes<T>(elements: usize) -> Result<usize, PackedStringLaneError> {
    elements
        .checked_mul(mem::size_of::<T>())
        .ok_or(PackedStringLaneError::ByteAccountingOverflow)
}

fn reserve<T>(
    values: &mut Vec<T>,
    count: usize,
    lane: &'static str,
) -> Result<(), PackedStringLaneError> {
    values
        .try_reserve_exact(count)
        .map_err(|_| PackedStringLaneError::AllocationFailed { lane })
}

fn checked_slice<'a, T>(
    values: &'a [T],
    start: u32,
    count: u32,
    lane: &'static str,
    object: u32,
) -> Result<&'a [T], PackedStringLaneError> {
    let start = start as usize;
    let end = start
        .checked_add(count as usize)
        .ok_or(PackedStringLaneError::MalformedRange {
            lane,
            object,
            start: start as u32,
            count,
        })?;
    values
        .get(start..end)
        .ok_or(PackedStringLaneError::MalformedRange {
            lane,
            object,
            start: start as u32,
            count,
        })
}

/// Packed string/path construction or resolution failed.
#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum PackedStringLaneError {
    /// A direct record coordinate exceeds `u32`.
    #[error("packed {lane} index {index} exceeds u32")]
    IndexOverflow {
        /// Affected packed lane.
        lane: &'static str,
        /// Rejected index.
        index: usize,
    },
    /// A direct range count exceeds `u32`.
    #[error("packed {lane} count {count} exceeds u32")]
    CountOverflow {
        /// Affected packed lane.
        lane: &'static str,
        /// Rejected count.
        count: usize,
    },
    /// A direct range exceeds the `u32` coordinate space.
    #[error("packed {lane} range exceeds u32")]
    RangeOverflow {
        /// Affected packed lane.
        lane: &'static str,
    },
    /// A logical append exceeds its pre-admitted capacity.
    #[error("packed {lane} capacity exceeded: admitted {admitted}, attempted {attempted}")]
    CapacityExceeded {
        /// Affected packed lane.
        lane: &'static str,
        /// Pre-admitted logical capacity.
        admitted: usize,
        /// Attempted initialized count.
        attempted: usize,
    },
    /// A complete vector reservation failed.
    #[error("failed to reserve packed {lane} lane")]
    AllocationFailed {
        /// Affected packed lane.
        lane: &'static str,
    },
    /// A reserved vector changed allocator capacity.
    #[error("packed string capacity changed from {admitted} bytes to {actual} bytes")]
    CapacityChanged {
        /// Capacity bytes immediately after reservation.
        admitted: usize,
        /// Capacity bytes observed later.
        actual: usize,
    },
    /// Exact byte accounting overflowed `usize`.
    #[error("packed string byte accounting overflow")]
    ByteAccountingOverflow,
    /// A string coordinate is stale or out of range.
    #[error("unknown packed string coordinate {index}")]
    UnknownString {
        /// Rejected coordinate.
        index: u32,
    },
    /// A path coordinate is stale or out of range.
    #[error("unknown packed path coordinate {index}")]
    UnknownPath {
        /// Rejected coordinate.
        index: u32,
    },
    /// A context coordinate is stale or out of range.
    #[error("unknown packed string-context coordinate {index}")]
    UnknownContext {
        /// Rejected coordinate.
        index: u32,
    },
    /// A string/path was paired with a different packed context.
    #[error("packed string context {context} does not match the source string context")]
    ContextMismatch {
        /// Packed context that failed source parity.
        context: u32,
    },
    /// A finalized record contains an invalid slice range.
    #[error("packed {lane} object {object} has malformed range start={start} count={count}")]
    MalformedRange {
        /// Affected packed lane.
        lane: &'static str,
        /// Record or context coordinate.
        object: u32,
        /// Stored range start.
        start: u32,
        /// Stored range count.
        count: u32,
    },
    /// A finalized context element carries an unknown kind byte.
    #[error("packed string context has malformed kind byte {kind}")]
    MalformedContextKind {
        /// Rejected kind byte.
        kind: u8,
    },
    /// A non-output context kind unexpectedly carries output bytes.
    #[error("packed string context {context} has output bytes on a non-output element")]
    MalformedUnexpectedOutput {
        /// Context containing the malformed element.
        context: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::string::ContextElement;

    fn opaque(path: &[u8]) -> ContextElement {
        ContextElement::opaque_path(path.to_vec()).unwrap()
    }

    fn output(path: &[u8], output: &[u8]) -> ContextElement {
        ContextElement::single_output(path.to_vec(), output.to_vec()).unwrap()
    }

    fn deep(path: &[u8]) -> ContextElement {
        ContextElement::deep_derivation(path.to_vec()).unwrap()
    }

    fn context_bytes(context: &StringContext) -> usize {
        context
            .iter()
            .map(|element| element.path().len() + element.output().map_or(0, <[u8]>::len))
            .sum()
    }

    #[test]
    fn exact_capacity_build_never_grows_and_accounts_actual_layout() {
        let context = StringContext::new(vec![
            opaque(b"/nix/store/source"),
            output(b"/nix/store/pkg.drv", b"out"),
            deep(b"/nix/store/deep.drv"),
        ]);
        let string = NixString::new(vec![0, 0xff, b'x'], context.clone());
        let path = NixString::new(b"/tmp/non-utf8-\xfe".to_vec(), context.clone());
        let admitted = PackedStringLaneCapacities {
            strings: 1,
            paths: 1,
            contexts: 1,
            context_elements: context.len(),
            bytes: context_bytes(&context) + string.len() + path.len(),
        };
        let mut builder = PackedStringLaneDirectBuilder::try_new(admitted).unwrap();
        let reserved = builder.admitted_capacity_bytes;
        let context_ref = builder.append_context(&context).unwrap();
        builder.append_string(&string, context_ref).unwrap();
        builder.append_path(&path, context_ref).unwrap();
        let lane = builder.finish().unwrap();

        assert_eq!(lane.capacity_bytes().unwrap(), reserved);
        assert_eq!(lane.string_count(), admitted.strings);
        assert_eq!(lane.path_count(), admitted.paths);
        assert_eq!(lane.context_count(), admitted.contexts);
        assert_eq!(lane.context_element_count(), admitted.context_elements);
        assert_eq!(lane.byte_count(), admitted.bytes);
        let initialized = lane.initialized_bytes().unwrap();
        assert_eq!(initialized.strings, mem::size_of::<PackedStringRecord>());
        assert_eq!(initialized.paths, mem::size_of::<PackedStringRecord>());
        assert_eq!(initialized.contexts, mem::size_of::<PackedContextRecord>());
        assert_eq!(
            initialized.context_elements,
            context.len() * mem::size_of::<PackedContextElement>()
        );
        assert_eq!(initialized.bytes, admitted.bytes);
        assert_eq!(
            initialized.total().unwrap(),
            mem::size_of::<PackedStringLane>()
                + 2 * mem::size_of::<PackedStringRecord>()
                + mem::size_of::<PackedContextRecord>()
                + context.len() * mem::size_of::<PackedContextElement>()
                + admitted.bytes
        );
    }

    #[test]
    fn views_preserve_non_utf8_bytes_and_every_context_distinction() {
        let source_context = StringContext::new(vec![
            deep(b"/nix/store/same.drv"),
            output(b"/nix/store/same.drv", b""),
            output(b"/nix/store/same.drv", b"out"),
            opaque(b"/nix/store/same.drv"),
            opaque(b"/nix/store/same.drv"),
        ]);
        let source = NixString::new(vec![0, b'a', 0xff, 0], source_context.clone());
        let admitted = PackedStringLaneCapacities {
            strings: 1,
            contexts: 1,
            context_elements: source_context.len(),
            bytes: source.len() + context_bytes(&source_context),
            ..PackedStringLaneCapacities::default()
        };
        let mut builder = PackedStringLaneDirectBuilder::try_new(admitted).unwrap();
        let context = builder.append_context(&source_context).unwrap();
        let reference = builder.append_string(&source, context).unwrap();
        let lane = builder.finish().unwrap();
        let view = lane.string(reference).unwrap();

        assert_eq!(view.bytes(), source.bytes());
        assert_eq!(view.context().len(), source_context.len());
        assert!(!view.context().is_empty());
        for (packed, original) in view.context().iter().zip(source_context.iter()) {
            assert_eq!(packed.kind(), original.kind());
            assert_eq!(packed.path(), original.path());
            assert_eq!(packed.output(), original.output());
        }
        assert_eq!(
            view.context()
                .iter()
                .filter(|element| element.kind() == ContextKind::SingleOutput)
                .count(),
            2
        );
    }

    #[test]
    fn stale_and_malformed_coordinates_fail_closed() {
        let context = StringContext::empty();
        let string = NixString::from_bytes(b"x".to_vec());
        let mut builder = PackedStringLaneDirectBuilder::try_new(PackedStringLaneCapacities {
            strings: 1,
            contexts: 1,
            bytes: 1,
            ..PackedStringLaneCapacities::default()
        })
        .unwrap();
        let context_ref = builder.append_context(&context).unwrap();
        builder.append_string(&string, context_ref).unwrap();
        let mut lane = builder.finish().unwrap();

        assert_eq!(
            lane.string(PackedStringRef::from_index(7)).unwrap_err(),
            PackedStringLaneError::UnknownString { index: 7 }
        );
        assert_eq!(
            lane.path(PackedPathRef::from_index(7)).unwrap_err(),
            PackedStringLaneError::UnknownPath { index: 7 }
        );
        assert_eq!(
            lane.context(PackedStringContextRef::from_index(7))
                .unwrap_err(),
            PackedStringLaneError::UnknownContext { index: 7 }
        );

        lane.strings[0].byte_start = u32::MAX;
        assert!(matches!(
            lane.string(PackedStringRef::from_index(0)),
            Err(PackedStringLaneError::MalformedRange {
                lane: "string",
                object: 0,
                ..
            })
        ));
    }

    #[test]
    fn over_capacity_append_is_rejected_before_mutation() {
        let empty = StringContext::empty();
        let string = NixString::from_bytes(b"x".to_vec());
        let mut builder = PackedStringLaneDirectBuilder::try_new(PackedStringLaneCapacities {
            strings: 1,
            contexts: 1,
            bytes: 1,
            ..PackedStringLaneCapacities::default()
        })
        .unwrap();
        let context = builder.append_context(&empty).unwrap();
        builder.append_string(&string, context).unwrap();
        let before = (
            builder.lane.string_count(),
            builder.lane.byte_count(),
            builder.lane.capacity_bytes().unwrap(),
        );
        assert_eq!(
            builder.append_string(&string, context).unwrap_err(),
            PackedStringLaneError::CapacityExceeded {
                lane: "string",
                admitted: 1,
                attempted: 2,
            }
        );
        assert_eq!(
            (
                builder.lane.string_count(),
                builder.lane.byte_count(),
                builder.lane.capacity_bytes().unwrap(),
            ),
            before
        );
        builder.finish().unwrap();
    }

    #[test]
    fn source_context_mismatch_is_rejected_before_mutation() {
        let packed_context = StringContext::new(vec![opaque(b"/nix/store/source")]);
        let source_context = StringContext::new(vec![deep(b"/nix/store/source")]);
        let source = NixString::new(b"x".to_vec(), source_context);
        let mut builder = PackedStringLaneDirectBuilder::try_new(PackedStringLaneCapacities {
            strings: 1,
            contexts: 1,
            context_elements: packed_context.len(),
            bytes: context_bytes(&packed_context) + source.len(),
            ..PackedStringLaneCapacities::default()
        })
        .unwrap();
        let context = builder.append_context(&packed_context).unwrap();
        let before = (
            builder.lane.string_count(),
            builder.lane.byte_count(),
            builder.lane.capacity_bytes().unwrap(),
        );

        assert_eq!(
            builder.append_string(&source, context).unwrap_err(),
            PackedStringLaneError::ContextMismatch {
                context: context.index(),
            }
        );
        assert_eq!(
            (
                builder.lane.string_count(),
                builder.lane.byte_count(),
                builder.lane.capacity_bytes().unwrap(),
            ),
            before
        );
    }
}
