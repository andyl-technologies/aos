//! Quotes the current inventory boundary before the sealed model moves.
//!
//! Existing model-transfer DATA excludes this separately constructed hash. The
//! original Source must compose both components with target, archive and Hold
//! construction under its complete phase demand. These methods issue no credit.

use super::*;

impl SealedHistoricalRestoredSettledNative17 {
    /// Quotes boundary formatter work before the typed construction traversal.
    ///
    /// The caller first admits the fixed boundary counter and metadata walk,
    /// then admits this formatter window before asking for construction DATA.
    /// The current model remains retained in this same sealed archive.
    ///
    /// # Errors
    /// Refuses an incomplete seal/model, metadata overflow or a short maximum.
    pub fn current_model18_boundary_quote_formatter_data(
        &self,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        self.validated_native_graph_data()?
            .current_model17_data()?
            .installation_boundary18_quote_formatter_data(maximum)
    }

    /// Quotes the current boundary's additional retained, transient and controls.
    ///
    /// The original Source admits the formatter prewalk before this typed
    /// serialization traversal. The returned hash backing belongs to the fresh
    /// physical Hold after installation; existing model/archive backing and
    /// the Hold allocation remain separate. The complete three-axis sum is
    /// restricted by `maximum`. No model, socket or owning field moves here.
    ///
    /// # Errors
    /// Refuses an incomplete seal/model, unsupported serialization, checked
    /// overflow or insufficient independent complete-component credit.
    pub fn current_model18_boundary_construction_data(
        &self,
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        let [retained, transient, _] = self
            .validated_native_graph_data()?
            .current_model17_data()?
            .installation_boundary18_construction_data(maximum)?;
        let counter = Self::current_model18_boundary_construction_counter_scratch_data();
        if retained
            .checked_add(transient)
            .and_then(|bytes| bytes.checked_add(counter))
            .is_none_or(|bytes| bytes > maximum)
        {
            return Err(ProviderError::ResourceExhausted(
                "sealed model18 installation boundary storage",
            ));
        }
        Ok([retained, transient, counter])
    }

    /// Names boundary construction controls and the sealed loan's guard views.
    ///
    /// Dynamic formatter work and native compiler frames remain independent.
    pub fn current_model18_boundary_construction_counter_scratch_data() -> usize {
        PacketSettledModel17Data::installation_boundary18_construction_counter_scratch_data()
            + Self::current_model18_construction_counter_scratch_data()
    }
}
