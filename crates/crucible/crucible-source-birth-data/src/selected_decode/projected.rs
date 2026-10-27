//! Feeds actual canonical occurrence events to the original generic phase tax.
//!
//! This numeric accumulator retains no JSON bytes or values. The actual shared
//! serializer classifies tokens; raw and projected paths use Credit's sole
//! occurrence operations. Required layouts are actual defining upper DATA.

use super::*;
use crate::profile::reference_packet::service::native_startup::issuer_layout::IssuerDecodeLayoutData;

/// Counts generic issuer occurrences without reconstructing unavailable strings.
///
/// Construction and updates are DATA only. Input bytes and the final requested
/// phase sum have distinct original bounds; numeric success grants nothing.
pub struct ProjectedCredit {
    credit: Credit,
    typed_slot: usize,
    typed_node: usize,
    value_node: usize,
    ordered_node: usize,
    encoded: usize,
    maximum: usize,
}

impl ProjectedCredit {
    /// Initializes the original generic issuer widths and canonical minimum.
    ///
    /// # Errors
    /// Refuses the original invalid/zero supplied layouts or checked overflow.
    pub fn new(
        typed_slot: usize,
        layouts: IssuerDecodeLayoutData,
        maximum: usize,
    ) -> Result<Self, ProviderError> {
        let typed_node = map_node(
            layouts.maximum_tree_key_value_bytes,
            layouts.maximum_tree_entry_alignment,
        )?;
        let typed_slot = typed_slot.max(layouts.maximum_typed_slot_bytes);
        if typed_slot == 0 || typed_node == 0 {
            return Err(exhausted());
        }
        let value_node = map_node(
            size_of::<String>() + size_of::<Value>(),
            align_of::<Value>(),
        )?;
        let ordered_node = map_node(
            size_of::<Vec<u16>>() + size_of::<(&str, &Value)>(),
            align_of::<Vec<u16>>().max(align_of::<(&str, &Value)>()),
        )?;
        Ok(Self {
            credit: Credit {
                canonical: growth(0, 8)?,
                ..Credit::default()
            },
            typed_slot,
            typed_node,
            value_node,
            ordered_node,
            encoded: 0,
            maximum,
        })
    }

    /// Accounts actual serializer bytes or an authenticated opaque string extent.
    ///
    /// # Errors
    /// Refuses input extent above maximum or original canonical arithmetic overflow.
    pub fn encoded(&mut self, bytes: usize) -> Result<(), ProviderError> {
        self.encoded = self
            .encoded
            .checked_add(bytes)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(exhausted)?;
        add(&mut self.credit.canonical, mul(bytes, 4)?)
    }

    /// Accounts an actual object or array opener from the shared classifier.
    ///
    /// # Errors
    /// Refuses a non-container delimiter or original checked occurrence overflow.
    pub fn container(&mut self, delimiter: u8) -> Result<(), ProviderError> {
        if delimiter != b'{' && delimiter != b'[' {
            return Err(malformed());
        }
        occurrence!(container, self.credit, delimiter, self.typed_slot);
        Ok(())
    }

    /// Accounts a completed string and its actual key/value position.
    ///
    /// Encoded width excludes quotes and includes literal escape bytes, exactly
    /// as the raw scanner observes them. No placeholder text is serialized.
    ///
    /// # Errors
    /// Refuses original string/tree/typed/canonical occurrence overflow.
    pub fn string(&mut self, encoded: usize, key: bool) -> Result<(), ProviderError> {
        occurrence!(string, self.credit, encoded);
        if key {
            occurrence!(
                key,
                self.credit,
                encoded,
                self.value_node,
                self.typed_node,
                self.ordered_node
            );
        }
        occurrence!(atom, self.credit, self.typed_slot);
        Ok(())
    }

    /// Accounts an actual non-string scalar from the shared classifier.
    ///
    /// # Errors
    /// Refuses original Value/typed occurrence overflow.
    pub fn atom(&mut self) -> Result<(), ProviderError> {
        occurrence!(atom, self.credit, self.typed_slot);
        Ok(())
    }

    /// Finishes the original one-DOM/typed/canonical issuer phase sum.
    ///
    /// Maximum bounds raw input extent; the original generic issuer does not
    /// add a final comparison between this phase sum and that raw bound.
    ///
    /// # Errors
    /// Refuses empty input or original root/phase arithmetic overflow.
    pub fn finish(mut self) -> Result<usize, ProviderError> {
        if self.encoded == 0 {
            return Err(exhausted());
        }
        add(&mut self.credit.typed, self.typed_slot)?;
        self.credit.requested(&Phases {
            dom: 1,
            typed: 1,
            canonical: 1,
        })
    }

    /// Names actual fixed projected state and direct call/control headers.
    ///
    /// Dynamic input, serializer/allocator/compiler work and any native owner
    /// remain excluded. The actual enclosing caller admits its own wrappers.
    pub const fn counter_scratch_data() -> usize {
        super::arithmetic_counter_scratch_data()
            // Constructor initializer, Ok payload, and the actual finish self.
            + 3 * size_of::<Self>()
            // Constructor return and its caller's Try input.
            + 2 * size_of::<Result<Self, ProviderError>>()
            // Constructor's actual layout input and retained copied argument.
            + 2 * size_of::<IssuerDecodeLayoutData>()
            // Constructor typed-slot/maximum inputs and four measured widths.
            + 6 * size_of::<usize>()
            + size_of::<Credit>()
            // encoded/container/string/atom method loans and returns.
            + size_of::<&mut Self>() * 4
            + 4 * size_of::<Result<(), ProviderError>>()
            + 2 * size_of::<usize>()
            + size_of::<u8>()
            + size_of::<bool>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Phases>()
            + size_of::<&Phases>()
    }
}
