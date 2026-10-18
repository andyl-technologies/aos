//! Retains application output refusal independently of both actual trace closes.

use super::runtime_trace::RuntimeTraceSummary;
use super::super::{NativePluginFlightDiagnostic, NativePluginFlightOutput};
use crate::NativeObservationError;
use crucible_store::content_store::StoreError;

/// Borrows both already-owned traces without moving their files or credits.
pub(super) struct TracePair<'a> {
    pub(super) reference: &'a RuntimeTraceSummary,
    pub(super) hostile: &'a RuntimeTraceSummary,
}

impl TracePair<'_> {
    pub(super) fn emit(
        &self,
        output: NativePluginFlightOutput,
        record: NativePluginFlightDiagnostic<'_>,
    ) -> Result<(), NativeObservationError> {
        output(record).map_err(|source| self.close().output_failure(source))
    }

    pub(super) fn finish(&self) -> Result<(), NativeObservationError> {
        self.close().result()
    }

    fn close(&self) -> TraceCloseOutcomes {
        close_pair(|| self.reference.finish(), || self.hostile.finish())
    }
}

struct TraceCloseOutcomes {
    reference: Result<(), StoreError>,
    hostile: Result<(), StoreError>,
}

/// Attempts both original closes before selecting any report disposition.
fn close_pair(
    reference: impl FnOnce() -> Result<(), StoreError>,
    hostile: impl FnOnce() -> Result<(), StoreError>,
) -> TraceCloseOutcomes {
    let reference = reference();
    let hostile = hostile();
    TraceCloseOutcomes { reference, hostile }
}

impl TraceCloseOutcomes {
    fn output_failure(self, source: std::io::Error) -> NativeObservationError {
        NativeObservationError::DiagnosticOutput {
            source,
            reference: self.reference.err().map(Box::new),
            hostile: self.hostile.err().map(Box::new),
        }
    }

    fn result(self) -> Result<(), NativeObservationError> {
        match (self.reference, self.hostile) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(source), hostile) => Err(NativeObservationError::ReferenceTraceFinalization {
                source: Box::new(source),
                hostile: hostile.err().map(Box::new),
            }),
            (Ok(()), Err(source)) => Err(NativeObservationError::HostileTraceFinalization(
                Box::new(source),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Exercises close ordering and original cause custody without native grants.

    use super::*;
    use std::cell::RefCell;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Debug)]
    struct OutputCause(Arc<AtomicUsize>);

    impl std::fmt::Display for OutputCause {
        fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            output.write_str("actual output refusal")
        }
    }

    impl std::error::Error for OutputCause {}

    impl Drop for OutputCause {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn output_refusal_preserves_its_original_cause_and_both_close_failures() {
        let order = RefCell::new(Vec::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let first = std::io::Error::other(OutputCause(Arc::clone(&dropped)));
        let pointer = first.get_ref().unwrap() as *const _;

        let closed = close_pair(
            || {
                order.borrow_mut().push("reference");
                Err(StoreError::StreamIo {
                    operation: "reference close",
                    source: std::io::Error::from_raw_os_error(5),
                })
            },
            || {
                order.borrow_mut().push("hostile");
                Err(StoreError::StreamIo {
                    operation: "hostile close",
                    source: std::io::Error::from_raw_os_error(9),
                })
            },
        );
        let report = closed.output_failure(first);

        assert_eq!(*order.borrow(), ["reference", "hostile"]);
        let NativeObservationError::DiagnosticOutput {
            source,
            reference,
            hostile,
        } = &report
        else {
            panic!("the original output refusal remains selected");
        };
        assert!(std::ptr::eq(source.get_ref().unwrap(), pointer));
        assert!(matches!(reference.as_deref(), Some(StoreError::StreamIo {
            operation: "reference close", source,
        }) if source.raw_os_error() == Some(5)));
        assert!(matches!(hostile.as_deref(), Some(StoreError::StreamIo {
            operation: "hostile close", source,
        }) if source.raw_os_error() == Some(9)));
        assert_eq!(dropped.load(Ordering::SeqCst), 0);

        drop(report);

        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reference_refusal_does_not_skip_the_independent_hostile_close() {
        let order = RefCell::new(Vec::new());
        let result = close_pair(
            || {
                order.borrow_mut().push("reference");
                Err(StoreError::Unauthorized)
            },
            || {
                order.borrow_mut().push("hostile");
                Err(StoreError::Unauthorized)
            },
        )
        .result();

        assert_eq!(*order.borrow(), ["reference", "hostile"]);
        assert!(
            matches!(result, Err(NativeObservationError::ReferenceTraceFinalization {
            source, hostile: Some(hostile),
        }) if matches!(*source, StoreError::Unauthorized) && matches!(*hostile, StoreError::Unauthorized))
        );
    }

    #[test]
    fn hostile_only_refusal_and_complete_pair_remain_distinct() {
        assert!(
            matches!(close_pair(|| Ok(()), || Err(StoreError::Unauthorized)).result(),
            Err(NativeObservationError::HostileTraceFinalization(source)) if matches!(*source, StoreError::Unauthorized))
        );
        assert!(close_pair(|| Ok(()), || Ok(())).result().is_ok());
    }
}
