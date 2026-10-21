//! Prepays the existing Root append representation and independent native post.
//!
//! This finite mechanical recipe uses the actual same R1 writer association or
//! genuine direct credential borrower. It constructs no semantic transaction,
//! protected role loan or mutation permission. Upper real final gates and the
//! complete upper semantic invoice remain required before actual append.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::canonical_journal::CanonicalJournalMechanicalErrorV1;
use crate::receiving::{RootJournalFinancialBorrowV1, RootJournalFinancialOriginalV1};

use super::{RootCoordinatorWriterV1, RootWriterErrorV1, RootWriterPostOriginalV1};

/// Keeps the actual native, financial or checked representation refusal.
///
/// Upper adapters move these existing classes into their actual role error;
/// selected failed native prefixes remain in the same writer's native sink.
#[derive(Debug, thiserror::Error)]
pub enum RootAppendPostAdmissionErrorV1 {
    /// Preserves the full existing mechanical classification and owned cause.
    #[error(transparent)]
    Mechanical(#[from] CanonicalJournalMechanicalErrorV1),
    /// Preserves the actual fixed Root native or invocation refusal.
    #[error(transparent)]
    Native(#[from] RootWriterErrorV1),
    /// Retains the same original financial allocation and its stable cause.
    #[error(transparent)]
    Financial(RootJournalFinancialOriginalV1),
}

impl<P> RootCoordinatorWriterV1<P> {
    /// Prepays and arms the independently owed native post before append work.
    ///
    /// The genuine direct borrower retains its existing upper exclusion and
    /// avoids reacquiring it. Otherwise the same original financial handle
    /// performs the existing cumulative debit. Each verifies this SAME writer.
    /// Financial critical sections end before the original native post arm.
    /// Neither the post nor a successful debit grants a semantic role operation.
    ///
    /// `upper_bytes` must include the actual upper context/error/Arc and other
    /// complete programme terms. This method preserves the existing native
    /// held-prefix/append plus native-post invoices, and separately adds its
    /// actual newly introduced quote/return carriers before the same debit.
    ///
    /// # Errors
    /// Preserves native demand/arm failure, checked representation refusal or
    /// the actual stable same-original financial cause before any post exists.
    pub fn prepay_native_append_post_once_v1(
        &self,
        transaction: &JournalTransaction,
        upper_bytes: usize,
        financial: Option<&RootJournalFinancialOriginalV1>,
        borrowed: Option<&RootJournalFinancialBorrowV1<'_>>,
    ) -> Result<RootWriterPostOriginalV1, RootAppendPostAdmissionErrorV1> {
        let invalid = || CanonicalJournalMechanicalErrorV1::LimitExceeded("Root append interval");
        let extra = std::mem::size_of::<(
            ResourceVector,
            Result<RootWriterPostOriginalV1, RootAppendPostAdmissionErrorV1>,
        )>()
        .checked_mul(3)
        .ok_or_else(invalid)?;
        let upper = upper_bytes
            .checked_add(extra)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let demand = self
            .append_receiving_demand_v1(transaction)?
            .checked_add(self.native_post_demand_v1()?)
            .and_then(|demand| demand.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, upper)))
            .map_err(|_| {
                CanonicalJournalMechanicalErrorV1::LimitExceeded(
                    "Root native append representation",
                )
            })?;
        if let Some(original) = borrowed {
            original.debit_v1(self, demand).map_err(|_| {
                match original.diagnostic_original_v1() {
                    Some(cause) => RootAppendPostAdmissionErrorV1::Financial(cause),
                    None => RootAppendPostAdmissionErrorV1::Mechanical(
                        CanonicalJournalMechanicalErrorV1::ProtectedBoundary,
                    ),
                }
            })?;
        } else {
            let financial =
                financial.ok_or(CanonicalJournalMechanicalErrorV1::ProtectedBoundary)?;
            financial
                .debit_v1(self, demand)
                .map_err(|_| RootAppendPostAdmissionErrorV1::Financial(financial.clone()))?;
        }
        self.arm_native_post_once_v1().map_err(Into::into)
    }
}
