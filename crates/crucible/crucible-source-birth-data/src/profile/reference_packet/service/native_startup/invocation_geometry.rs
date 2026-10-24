//! Shares invocation owner geometry without launch identity or native admission.
//!
//! The upper quoter measures the real canonical Launch5 wrapper and supplies its
//! actual compiled typed-root layout. A contained worker uses the same
//! arithmetic only with the matching defining inputs. These public numbers do
//! not authenticate those inputs or construct a native scope, Source or bank.

use crate::ProviderError;
use crate::profile::serialization_storage::{
    OriginalSerializationStorageData, OriginalSerializationStorageProjection as Projection,
    original_json_value_storage_extent_data,
};

fn invalid() -> ProviderError {
    ProviderError::Correlation("native invocation purpose DATA")
}

/// Reports the independently retained and transient invocation additions.
///
/// No digest, retained-overlap seal, member, bank or allocation right is present.
pub struct InvocationConstructionGeometry {
    native_retained: usize,
    native_transient: usize,
    private_retained: usize,
    private_transient: usize,
    source_finalization: usize,
    wire_growth: usize,
    maximum_boot: usize,
}

impl InvocationConstructionGeometry {
    /// Returns the independent persistent native additions.
    pub const fn native_retained_requested_bytes(&self) -> usize {
        self.native_retained
    }

    /// Returns the complete simultaneous native additions.
    pub const fn native_transient_requested_bytes(&self) -> usize {
        self.native_transient
    }

    /// Returns the independent persistent private additions.
    pub const fn private_retained_requested_bytes(&self) -> usize {
        self.private_retained
    }

    /// Returns the complete simultaneous private additions.
    pub const fn private_transient_requested_bytes(&self) -> usize {
        self.private_transient
    }

    /// Returns actual Source finalization and writer work.
    pub const fn source_finalization_requested_bytes(&self) -> usize {
        self.source_finalization
    }

    /// Returns the independent wrapper bank's additional requested capacity.
    pub const fn wire_growth_requested_bytes(&self) -> usize {
        self.wire_growth
    }

    /// Returns the enlarged boot-body extent under the original absolute ceiling.
    pub const fn maximum_private_boot_body_bytes(&self) -> usize {
        self.maximum_boot
    }
}

/// Retains the three real closed serialization shapes before identity work.
///
/// This phase preserves the upper call's failure order: purpose field, wrapper
/// and allocation rows precede actual bank hashing. It owns only numeric reports;
/// original operands and failed writes remain with their real callers.
pub struct InvocationConstructionShape<P> {
    field: OriginalSerializationStorageData,
    wrapper: OriginalSerializationStorageData,
    rows: OriginalSerializationStorageData,
    purpose_type: std::marker::PhantomData<fn() -> P>,
}

impl<P: serde::Serialize> InvocationConstructionShape<P> {
    /// Counts the actual purpose and maximum-width allocation grammar.
    ///
    /// The argument is the defining closed purpose serializer, not a substitute
    /// full launch. This function does not validate its provenance or grammar.
    ///
    /// # Errors
    /// Preserves field, wrapper and allocation-row projection failures in order.
    pub fn new(purpose: &P, maximum: usize) -> Result<Self, ProviderError> {
        let field = field(purpose, maximum)?;
        let wrapper = wrapper(purpose, maximum)?;
        let rows = allocation_rows(maximum)?;
        Ok(Self {
            field,
            wrapper,
            rows,
            purpose_type: std::marker::PhantomData,
        })
    }

    /// Finishes geometry from original measured extents and compiled layout.
    ///
    /// The two launch extents come from the same real nested bank and actual
    /// wrapper writer. The typed wrapper is the defining native root's size,
    /// not a byte cap or a retained allocation. The generic type is the actual
    /// defining purpose type; it contributes its inline layout only.
    ///
    /// An upper owner independently authenticates all these associations. This
    /// public DATA cannot accept a Source, issue admission or hash an imagined
    /// launch.
    ///
    /// # Errors
    /// Preserves checked arithmetic, parser growth and original frame refusals.
    pub fn finish(
        self,
        canonical_launch5_bytes: usize,
        invocation_launch_bytes: usize,
        old_maximum_boot_bytes: usize,
        typed_wrapper: usize,
        maximum: usize,
    ) -> Result<InvocationConstructionGeometry, ProviderError> {
        let Self {
            field,
            wrapper,
            rows,
            purpose_type: _,
        } = self;
        let encoded_growth = invocation_launch_bytes
            .checked_sub(canonical_launch5_bytes)
            .ok_or_else(invalid)?;
        let maximum_boot = total(
            &[
                old_maximum_boot_bytes,
                field.maximum_encoded_bytes,
                rows.maximum_encoded_bytes,
            ],
            maximum,
        )?;
        if maximum_boot > 512 * 1024 || invocation_launch_bytes > 1024 * 1024 {
            return Err(invalid());
        }
        let old_parser = original_json_value_storage_extent_data(
            canonical_launch5_bytes.max(old_maximum_boot_bytes),
        )?;
        let new_parser =
            original_json_value_storage_extent_data(invocation_launch_bytes.max(maximum_boot))?;
        let parser_growth = new_parser
            .canonical_pass_requested_bytes()?
            .checked_sub(old_parser.canonical_pass_requested_bytes()?)
            .ok_or_else(invalid)?;
        let purpose_tree = field.requested_total()?;
        let wrapper_tree = wrapper.requested_total()?;
        let row_tree = rows.requested_total()?;
        let source_tree = total(&[purpose_tree, row_tree], maximum)?;
        let native_retained = total(
            &[
                source_tree,                // bootstrap bootValue.source_birth
                source_tree,                // NativeAckBoot.data.source_birth
                source_tree,                // normalized association.source_binding
                source_tree,                // normalized policy.source_binding
                wrapper_tree,               // original independent launchValue wrapper
                encoded_growth,             // NativeAckBoot retained original launch_body
                rows.maximum_encoded_bytes, // independently retained canonical Source body
                typed_wrapper,              // conservative independent first typed launch6 owner
            ],
            maximum,
        )?;
        let private_retained = total(
            &[
                wrapper_tree,   // retained private launchValue wrapper
                source_tree,    // retained private bootValue Source child
                encoded_growth, // private launch_bytes bank
                typed_wrapper,  // conservative independent first typed launch6 owner
            ],
            maximum,
        )?;
        let native_transient = total(
            &[
                source_tree,   // independently constructed expected Source binding
                wrapper_tree,  // later independent Value launch decode and validation
                typed_wrapper, // second typed decode while the first may remain retained
                std::mem::size_of::<P>(),
            ],
            maximum,
        )?;
        let private_transient = total(
            &[
                parser_growth,
                wrapper_tree,
                source_tree,
                typed_wrapper, // second typed conversion beside the retained first owner
                std::mem::size_of::<P>(),
            ],
            maximum,
        )?;
        let source_finalization = total(
            &[
                purpose_tree,               // new invocation Value moved into the retained full body
                purpose_tree,               // independent invocation addition/encoding work
                row_tree,                   // enlarged NativeAdditions allocation child
                row_tree,                   // independent finalizer parsed Source allocation child
                row_tree,                   // independent wire boot-frame Source allocation clone
                rows.maximum_encoded_bytes, // finalizer replacement raw encoding work
                rows.maximum_encoded_bytes, // independent wire boot-frame raw encoding work
                wrapper_tree, // Source wrapper encoding and closed wire preparation work
                encoded_growth, // separately retained wrapper bank in Source wire holder
            ],
            maximum,
        )?;
        Ok(InvocationConstructionGeometry {
            native_retained,
            native_transient,
            private_retained,
            private_transient,
            source_finalization,
            wire_growth: encoded_growth,
            maximum_boot,
        })
    }
}

fn total(parts: &[usize], maximum: usize) -> Result<usize, ProviderError> {
    parts.iter().try_fold(0usize, |sum, n| {
        sum.checked_add(*n)
            .filter(|n| *n <= maximum)
            .ok_or_else(invalid)
    })
}

fn field(
    purpose: &impl serde::Serialize,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    p.add_object()?;
    p.add_field("invocation")?;
    p.add_value(purpose)?;
    p.finish(maximum)
}

fn wrapper(
    purpose: &impl serde::Serialize,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    p.add_object()?;
    p.add_field("schema_version")?;
    p.add_value(&6u16)?;
    p.add_field("invocation")?;
    p.add_value(purpose)?;
    // Existing full launch5 ownership is charged by the baseline. This extra
    // null charges its new wrapper value slot without replacing that owner.
    p.add_field("launch")?;
    p.add_value(&())?;
    p.finish(maximum)
}

// The old baseline serialized its actual row values. Enlarging those rows can
// increase every quoted decimal, so count the entire replacement field with all
// three rows at their full U64 width. This also dominates the nullable None case
// without borrowing spare credit from an unrelated purpose tree.
fn allocation_rows(maximum: usize) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut p = Projection::new(maximum)?;
    p.add_object()?;
    p.add_field("native_startup_allocation")?;
    p.add_object()?;
    p.add_field("schema")?;
    p.add_string(super::PACKET_NATIVE_STARTUP_ALLOCATION_SCHEMA)?;
    for name in ["private_bootstrap", "native_birth", "restore_prepare"] {
        p.add_field(name)?;
        p.add_object()?;
        for field in [
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ] {
            p.add_field(field)?;
            p.add_unescaped_ascii_extent(20)?;
        }
    }
    p.finish(maximum)
}

/// Names the new adapter's fixed report and return windows.
///
/// Actual purpose/writer frames, original inputs and native layouts remain in
/// their defining suppliers. This is not a complete caller admission contract.
pub const fn adapter_counter_scratch_data<P>() -> usize {
    use std::mem::size_of;
    size_of::<InvocationConstructionShape<P>>()
        + size_of::<InvocationConstructionGeometry>()
        + size_of::<Result<InvocationConstructionShape<P>, ProviderError>>()
        + size_of::<Result<InvocationConstructionGeometry, ProviderError>>()
        + size_of::<&InvocationConstructionShape<P>>()
        + size_of::<[usize; 5]>()
}

#[cfg(test)]
#[path = "invocation_geometry/tests.rs"]
mod tests;
