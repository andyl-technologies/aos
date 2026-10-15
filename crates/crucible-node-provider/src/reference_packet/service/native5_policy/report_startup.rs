//! Joins the actual immutable policy scope to a closed selected report read.

use super::*;

impl Native5Policy {
    pub(crate) fn authenticate_original_report_query_header_data(
        &self,
        purpose: super::super::report_startup::PacketNativeReportStartupPurpose,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        crate::connection::authenticate_original_report_query_header_data(
            &self.selection,
            purpose,
            original,
        )
    }
}
