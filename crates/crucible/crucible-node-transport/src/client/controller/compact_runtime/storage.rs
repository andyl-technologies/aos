//! Prices future compact journal backing before moving its original controller.
//!
//! The actual original custody supplies the unchanged lifetime request ceiling
//! and irreversibly reduced byte allowance. This component grants no handoff,
//! allocation or Source permission and does not price the complete SDK future.

use super::*;
use std::mem::size_of;

impl CnpController {
    /// Bounds compact suffix journal backing from this original controller.
    ///
    /// The result covers both future namespace maps, keys, identity hashes and
    /// compact request/response banks under the original remaining byte quota.
    /// It uses the same private limits as the later ownership move. Both maps
    /// retain their original lifetime request ceiling; existing originals stay
    /// independently charged and continue to count toward that ceiling.
    ///
    /// This allocation-free DATA query changes no owner, debit or quota. It
    /// remains readable after fencing and authenticates no live registration,
    /// Source action or permission to move the controller. The caller separately
    /// admits the fixed counter before entry. Content, pending received frames,
    /// correlation, bank construction, materialization and the original owner
    /// require independent funding before any runtime handoff or exchange.
    ///
    /// # Errors
    /// Refuses exhausted or inconsistent original byte credit, unsupported
    /// journal limits or tree layouts, arithmetic overflow, or backing above
    /// the independent supplied restriction.
    pub fn original_compact_runtime_journal_retained_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        self.custody
            .compact_runtime_journal_retained_storage_data(maximum)
    }

    /// Names the fixed original-custody, journal and tree quote controls.
    ///
    /// The enclosing Source admits these controls before invoking the DATA
    /// query. Dynamic backing, physical stack use and whole-owner observation
    /// growth remain separate from this component's requested control layouts.
    pub const fn original_compact_runtime_journal_retained_counter_scratch_data() -> usize {
        ClientCustody::compact_runtime_journal_retained_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<usize>()
    }
}
