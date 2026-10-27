//! Advises a future Root suffix under the genuine fixed Authority without write eligibility.
//!
//! This private forecast preserves the old RootCapacity position. It borrows
//! the actual Authority and exact passive recipes, rechecks its full original
//! before-state, and cannot be constructed as earned native binding history.

use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use super::{RootAuthorityErrorV1, RootAuthorityOriginalV1, RootAuthorityQ04FlightOriginalV1};
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::journal::RootPolicyJournalV1;

pub(in crate::native) struct AuthorityForecastGateV1<'role> {
    cause: std::cell::RefCell<Option<RootAuthorityErrorV1>>,
    authority: &'role RootAuthorityOriginalV1,
    transactions: &'role [JournalTransaction],
    before: (u64, ProtectedJournalNamesV1, ObjectDigest),
}

impl AuthorityForecastGateV1<'_> {
    pub(in crate::native) fn preflight_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), NativeError> {
        let returned = self.require_original_v1(journal, transactions);
        match returned {
            Ok(()) => Ok(()),
            Err(error) => {
                let mut cause = self.cause.borrow_mut();
                if cause.is_none() {
                    *cause = Some(error);
                }
                Err(NativeError::boundary())
            }
        }
    }

    fn require_original_v1(
        &self,
        journal: &RootPolicyJournalV1,
        transactions: &[JournalTransaction],
    ) -> Result<(), RootAuthorityErrorV1> {
        if !std::ptr::eq(journal, &self.authority.journal)
            || transactions != self.transactions
            || transactions.is_empty()
        {
            return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
        }
        Ok(())
    }

    pub(in crate::native) fn require_q04_transition_v1(
        &self,
        transaction: &JournalTransaction,
        prospective_index: usize,
    ) -> Result<(), NativeError> {
        if self.transactions.get(prospective_index) == Some(transaction) {
            Ok(())
        } else {
            Err(NativeError::boundary())
        }
    }

    pub(in crate::native) fn finish_v1(&self) -> Result<(), RootAuthorityErrorV1> {
        self.authority.recheck()?;
        self.authority.recheck()?;
        if self.authority.journal.q04_before_rows_v1()? != self.before {
            return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
        }
        Ok(())
    }
}

// This inline reservoir is constructed inert with the genuine Flight. The
// passive forecast never becomes binding-history eligibility or a commit gate.
pub(super) struct RootAuthorityQ04ForecastOriginalV1 {
    entered: bool,
    suffix: crate::q04_data::RootQ04SuffixDataV1,
    named: std::sync::OnceLock<super::names::RootAuthorityNamesOriginalV1>,
    receipt_admission: Option<Result<(), NativeError>>,
    outcome: Option<Result<(), RootAuthorityErrorV1>>,
}

impl RootAuthorityQ04ForecastOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            entered: false,
            suffix: crate::q04_data::RootQ04SuffixDataV1::default(),
            named: std::sync::OnceLock::new(),
            receipt_admission: None,
            outcome: None,
        }
    }

    pub(super) fn is_refused_v1(&self) -> bool {
        self.entered && !matches!(self.outcome, Some(Ok(())))
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.named
            .get()
            .and_then(super::names::RootAuthorityNamesOriginalV1::failure)
            .or_else(|| {
                self.receipt_admission
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
                    .or_else(|| {
                        self.outcome
                            .as_ref()
                            .and_then(|result| result.as_ref().err())
                            .map(|cause| cause as _)
                    })
            })
    }
}

fn capture_fixed_authority_names_v1(
    authority: &RootAuthorityOriginalV1,
    destination: &std::sync::OnceLock<super::names::RootAuthorityNamesOriginalV1>,
) -> Result<(), RootAuthorityErrorV1> {
    use super::names::{
        RootAuthorityNameRecipeV1 as Recipe, RootAuthorityNamesOriginalV1 as Original,
    };
    if destination.get().is_some() {
        return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
    }
    let demand = Original::fixed_demand_v1(Recipe::Owner)?
        .checked_add(aos_sandbox_model::ResourceVector::ZERO.with(
            aos_sandbox_model::ResourceDimension::MetadataEntries,
            crate::native::RootPolicyNameObservationOriginalV1::retained_control_cells_v1(),
        ))
        .map_err(|_| NativeError::geometry())?;
    authority.journal.admit_role_observation_v1(demand)?;
    let mut original = Original::new();
    let returned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        original.observe_once(&authority.journal, Recipe::Owner)
    }));
    if matches!(returned, Ok(Ok(()))) {
        original.settle_positive_once_v1();
    }
    if let Err(_still_owned) = destination.set(original) {
        std::process::abort();
    }
    match returned {
        Ok(Ok(())) => Ok(()),
        // The complete actual failed native prefix stays in destination.
        Ok(Err(())) => Err(RootAuthorityErrorV1::Stale),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

pub(super) fn preflight_authority_suffix_v1(
    authority: &RootAuthorityOriginalV1,
    before: (u64, ProtectedJournalNamesV1, ObjectDigest),
    transactions: &[JournalTransaction],
    named: &std::sync::OnceLock<super::names::RootAuthorityNamesOriginalV1>,
) -> Result<(), RootAuthorityErrorV1> {
    // Exact old wrapper: outer recheck, then nonempty short circuit, then
    // q04_before_rows' own recheck and complete native before-state sample.
    authority.recheck()?;
    if transactions.is_empty() {
        return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
    }
    authority.recheck()?;
    if authority.journal.q04_before_rows_v1()? != before
        || authority.journal.all_records().any(|(namespace, key, _)| {
            namespace == RecordNamespace::DesiredState && key.starts_with(b"\0aos-q04-root-")
        })
    {
        return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
    }
    // Old Journal::preflight_root_q04_capacity first required exactly its
    // fixed named writer, then entered the common complete semantic engine.
    capture_fixed_authority_names_v1(authority, named)?;
    let forecast = AuthorityForecastGateV1 {
        cause: std::cell::RefCell::new(None),
        authority,
        transactions,
        before,
    };
    forecast.require_original_v1(&authority.journal, transactions)?;
    let returned = authority
        .journal
        .preflight_authority_forecast_v1(transactions, &forecast);
    if let Err(native) = returned {
        return Err(match forecast.cause.into_inner() {
            Some(original) => original,
            None => native.into(),
        });
    }
    forecast.finish_v1()
}

impl RootAuthorityQ04FlightOriginalV1<'_, '_, '_> {
    // Only actual Work can lend the private prehold compiler/plan receipt. This
    // action prices Root-owned construction before forming its passive suffix;
    // the Target invoice and an eventual committed-history invoice cannot pay it.
    pub(in crate::native) fn forecast_q04_prehold_suffix_v1(
        &mut self,
        work: &mut crate::native::target::RootPolicyPublicationWorkV1<'_>,
        stage: &crate::q04_data::Q04RootStageRecipeV1,
        request_packet: &[u8],
        preview_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<(), ()> {
        if self.forecast.entered {
            return Err(());
        }
        let ready = self.require_ready();
        self.forecast.entered = true;
        if let Err(error) = ready {
            self.forecast.outcome = Some(Err(error));
            return Err(());
        }
        let receipt_bytes =
            crate::native::target::RootPolicyPublicationWorkV1::prehold_history_receipt_bytes_v1()
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<crate::q04_data::Q04PreholdInputDataV1<'_>>()
                            .checked_mul(3)?,
                    )
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<
                            Result<
                                crate::q04_data::Q04PreholdInputDataV1<'_>,
                                crate::q04_data::PolicyQ04DataErrorV1,
                            >,
                        >()
                        .checked_mul(2)?,
                    )
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<crate::q04_data::Q04PreviewV1<'_>>().checked_mul(3)?,
                    )
                })
                .and_then(|bytes| {
                    bytes.checked_add(
                        std::mem::size_of::<
                            Result<
                                crate::q04_data::Q04PreviewV1<'_>,
                                crate::q04_data::PolicyQ04DataErrorV1,
                            >,
                        >()
                        .checked_mul(2)?,
                    )
                })
                .and_then(|bytes| {
                    bytes
                        .checked_add(std::mem::size_of::<Result<(), NativeError>>().checked_mul(3)?)
                })
                .and_then(|bytes| u64::try_from(bytes).ok());
        let Some(receipt_bytes) = receipt_bytes else {
            self.forecast.outcome = Some(Err(NativeError::geometry().into()));
            return Err(());
        };
        self.forecast.receipt_admission = Some(self.authority.journal.admit_role_observation_v1(
            aos_sandbox_model::ResourceVector::ZERO.with(
                aos_sandbox_model::ResourceDimension::MemoryBytes,
                receipt_bytes,
            ),
        ));
        if !matches!(self.forecast.receipt_admission, Some(Ok(()))) {
            return Err(());
        }
        // On failure the actual compiler/Target cause stays in this same Work.
        // The public Work action classifies that owner before independent posts.
        let receipt = work.prehold_history_input_v1()?;
        let returned = (|| {
            self.authority.recheck()?;
            let before = self.authority.journal.q04_before_rows_v1()?;
            if before != receipt.root_before {
                return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
            }
            let request = crate::q04_data::Q04PreholdInputDataV1::decode(request_packet)?;
            let preview =
                crate::q04_data::Q04PreviewV1::decode(preview_packet, receipt.identity.nonce())?;
            let root_metadata = preview.fields()[0];
            if root_metadata[32..40] != before.0.to_be_bytes()
                || root_metadata[40..88] != before.1.to_bytes()
                || root_metadata[88..120] != *before.2.as_bytes()
            {
                return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
            }
            let bytes = crate::q04_data::RootQ04SuffixDataV1::receiving_bytes_v1(
                receipt.claim_length,
                stage,
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<crate::q04_data::RootQ04SuffixInputDataV1<'_>>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|bytes| {
                bytes
                    .checked_add(std::mem::size_of::<AuthorityForecastGateV1<'_>>().checked_mul(2)?)
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(), RootAuthorityErrorV1>>().checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(), crate::q04_data::PolicyQ04DataErrorV1>>()
                        .checked_mul(2)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(NativeError::geometry)?;
            self.authority.journal.admit_role_observation_v1(
                aos_sandbox_model::ResourceVector::ZERO
                    .with(aos_sandbox_model::ResourceDimension::MemoryBytes, bytes),
            )?;
            self.forecast.suffix.form(
                crate::q04_data::RootQ04SuffixInputDataV1 {
                    identity: receipt.identity,
                    binding: receipt.binding,
                    root_before: before.2,
                    root_sequence: before.0,
                    state_sequence: receipt.target_before.0,
                    claim_length: receipt.claim_length,
                    claim: None,
                    held_pairs: None,
                },
                stage,
                &request,
                &preview,
                source_packet,
            )?;
            preflight_authority_suffix_v1(
                self.authority,
                before,
                &self.forecast.suffix.transactions,
                &self.forecast.named,
            )
        })();
        self.forecast.outcome = Some(returned);
        if matches!(self.forecast.outcome, Some(Ok(()))) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub(in crate::native) fn require_positive_prehold_forecast_v1(
        &self,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.require_ready()?;
        if self.forecast.entered && matches!(self.forecast.outcome, Some(Ok(()))) {
            Ok(())
        } else {
            Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into())
        }
    }
}
