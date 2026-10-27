//! Composes an actual ordinary native owner with its private semantic remainder.
//!
//! Only completed opaque held owners enter here. Callers retain their real
//! opening, paid conversion and role-specific currentness through this final
//! assembly; neither a file, supplied index nor authority allocation is adopted.

use std::sync::Arc;

use aos_sandbox_broker::canonical_journal::{
    CanonicalOrdinaryHeldJournalV1, RecoveryReport as NativeRecoveryReport,
};

use super::native_backing::{JournalNativeBackingV1, OrdinaryJournalNativeV1, Selection};
use super::semantic_remainder::DomainSemanticRemainderDataV1;
use super::{Journal, JournalAuthorityInstance, RecoveryReport};

#[cfg(target_os = "linux")]
use super::native_interval::captured::CapturedAppendOwnerV1;

type Held = CanonicalOrdinaryHeldJournalV1<Selection, JournalAuthorityInstance>;
type NativeInput = Option<(Held, NativeRecoveryReport)>;
type SemanticInput = Option<DomainSemanticRemainderDataV1>;
type Materialized = Option<(Journal, RecoveryReport)>;

impl Journal {
    /// Prices this assembly's actual working, returned and borrowed carriers.
    ///
    /// Callers replace their old two-Journal construction term with this whole
    /// term before entry. Their retained opening, semantic backing and marker
    /// allocation remain separately priced by the actual owning suppliers.
    pub(super) fn ordinary_materialization_receiving_bytes_v1() -> Option<usize> {
        #[cfg(target_os = "linux")]
        let captured_argument = std::mem::size_of::<&mut Option<CapturedAppendOwnerV1>>();
        #[cfg(not(target_os = "linux"))]
        let captured_argument = 0;

        std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(captured_argument)?
            .checked_add(std::mem::size_of::<Materialized>())?
            .checked_add(std::mem::size_of::<&mut NativeInput>())?
            .checked_add(std::mem::size_of::<&mut SemanticInput>())?
            .checked_add(std::mem::size_of::<Arc<JournalAuthorityInstance>>())
    }

    /// Moves the paired, still-resident originals without allocating an identity.
    ///
    /// Missing halves remain in their caller's original slots. The outer alias
    /// clones the SAME held marker, preserving its old Journal field/drop position.
    /// Actual native and semantic constructors are the only producers of these
    /// private inputs; this helper cannot assemble native storage from raw DATA.
    pub(super) fn from_actual_ordinary_held_v1(
        native: &mut NativeInput,
        semantic: &mut SemanticInput,
        #[cfg(target_os = "linux")] captured: &mut Option<CapturedAppendOwnerV1>,
    ) -> Materialized {
        let (held, _) = native.as_ref()?;
        semantic.as_ref()?;
        let authority_instance = Arc::clone(held.instance_data_v1()?.comparison_arc_v1());

        let inputs = (native.take(), semantic.take());
        let ((held, report), semantic) = match inputs {
            (Some(native), Some(semantic)) => (native, semantic),
            (original_native, original_semantic) => {
                *native = original_native;
                *semantic = original_semantic;
                return None;
            }
        };

        let journal = Self {
            #[cfg(target_os = "linux")]
            operator_recovery: None,
            #[cfg(target_os = "linux")]
            provisioning: None,
            start_admission: None,
            execution_admission: None,
            native: JournalNativeBackingV1::Ordinary(OrdinaryJournalNativeV1 {
                held,
                #[cfg(target_os = "linux")]
                captured_append: captured.take(),
            }),
            #[cfg(target_os = "linux")]
            root_journal_financial: None,
            #[cfg(target_os = "linux")]
            native_interval: None,
            #[cfg(target_os = "linux")]
            replacement_original: None,
            cache_policy_gate: None,
            authority_instance,
            source_challenge_history: semantic.source_challenge_history,
            source_original_replay: semantic.source_original_replay,
            source_history_compacted: semantic.source_history_compacted,
            #[cfg(target_os = "linux")]
            q04_lower_history_present: semantic.q04_lower_history_present,
        };
        let report = RecoveryReport {
            committed_transactions: report.committed_transactions,
            committed_records: report.committed_records,
            truncated_bytes: report.truncated_bytes,
        };
        Some((journal, report))
    }
}
