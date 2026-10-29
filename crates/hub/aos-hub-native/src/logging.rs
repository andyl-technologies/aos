//! Native stderr logging with task-scoped indexing and storage-work context.
//!
//! Events retain the Hub's plain `name=value` format. Active span fields follow
//! each event so concurrent index runs and release walks remain distinguishable
//! in journald without logging plans, credentials, or object contents.

use std::fmt::{self, Write as _};

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

/// Installs the Native logger while preserving an existing global subscriber.
pub(crate) fn init() {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .event_format(HubEventFormat)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

struct HubEventFormat;

impl<S, N> FormatEvent<S, N> for HubEventFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        context: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut fields = EventFields::default();
        event.record(&mut fields);
        write!(writer, "[{}]{}", event.metadata().level(), fields.0)?;

        if let Some(scope) = context.event_scope() {
            for span in scope.from_root() {
                write!(writer, " span={}", span.name())?;
                let extensions = span.extensions();
                if let Some(fields) = extensions.get::<FormattedFields<N>>() {
                    if !fields.is_empty() {
                        write!(writer, " {fields}")?;
                    }
                }
            }
        }
        writeln!(writer)
    }
}

#[derive(Default)]
struct EventFields(String);

impl Visit for EventFields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        let _ = write!(self.0, " {}={value:?}", field.name());
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use tracing::instrument::WithSubscriber as _;
    use tracing::Instrument as _;

    use super::HubEventFormat;

    #[derive(Clone)]
    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl io::Write for CapturedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn concurrent_release_logs_keep_their_own_context() {
        let output = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&output);
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || CapturedWriter(Arc::clone(&captured)))
            .event_format(HubEventFormat)
            .finish();

        async {
            let root = tracing::info_span!("registry_index", index_run = "run-1", registry_id = 7);
            let first = tracing::info_span!(parent: &root, "registry_release", release = "first");
            let second = tracing::info_span!(parent: &root, "registry_release", release = "second");
            let walk = |marker| async move {
                tracing::info!(marker, request_bytes = 41, "hybrid storage boundary");
                tokio::task::yield_now().await;
                tracing::info!(marker, response_bytes = 59, "hybrid storage boundary");
            };
            tokio::join!(
                walk("first").instrument(first),
                walk("second").instrument(second)
            );
            tracing::info!("outside release walk");
        }
        .with_subscriber(subscriber)
        .await;

        let lines = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        for marker in ["first", "second"] {
            let matching: Vec<_> = lines
                .lines()
                .filter(|line| line.contains(&format!("marker=\"{marker}\"")))
                .collect();
            assert_eq!(matching.len(), 2, "{lines}");
            for line in matching {
                assert!(
                    line.starts_with("[INFO] message=hybrid storage boundary"),
                    "{line}"
                );
                assert!(line.contains("index_run=\"run-1\" registry_id=7"), "{line}");
                assert!(line.contains(&format!("release=\"{marker}\"")), "{line}");
                let other = if marker == "first" { "second" } else { "first" };
                assert!(!line.contains(&format!("release=\"{other}\"")), "{line}");
            }
        }
        let outside = lines
            .lines()
            .find(|line| line.contains("outside release walk"))
            .unwrap();
        assert_eq!(outside, "[INFO] message=outside release walk");
    }
}
