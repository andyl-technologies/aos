//! Fixed system-reset request borrowing the caller's original operation.

use super::*;

impl<S: QmpTimeoutStream> QmpClient<S> {
    pub(super) fn reset_under_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<QmpCommandComplete, QmpError> {
        let response = self.exchange_under(QmpCommand::SystemReset, original)?;
        if !response
            .value
            .as_object()
            .is_some_and(|value| value.is_empty())
        {
            // A reset may already have happened. Keep the first shape refusal
            // and prevent another request on this uncertain control stream.
            self.poisoned = true;
            self.stream.get_mut().poison_qmp_stream();
            return Err(QmpError::InvalidBound {
                operation: "managed reset requires an empty QMP acknowledgement",
            });
        }
        Ok(QmpCommandComplete {
            command: response.command,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    struct FixtureStream {
        replies: io::Cursor<Vec<u8>>,
        written: Arc<Mutex<Vec<u8>>>,
        close_on_read: Option<Arc<HostOperationGuard>>,
    }

    impl Read for FixtureStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if let Some(original) = self.close_on_read.take() {
                original.complete().map_err(io::Error::other)?;
            }
            // Do not buffer future replies during the greeting negotiation.
            let count = bytes.len().min(1);
            self.replies.read(&mut bytes[..count])
        }
    }

    impl Write for FixtureStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.written
                .lock()
                .expect("component request log")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl QmpTimeoutStream for FixtureStream {
        fn set_qmp_read_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn set_qmp_write_timeout(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }
    }

    fn original() -> (HostOperationSupervisor, Arc<HostOperationGuard>) {
        let supervisor = HostOperationSupervisor::new(
            crucible_linux_resource::host_supervision::HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .expect("finite component supervisor");
        let guard = Arc::new(
            supervisor
                .begin(HostOperationClass::Preparation)
                .expect("original component operation"),
        );
        (supervisor, guard)
    }

    fn client(replies: &[Value]) -> QmpClient<FixtureStream> {
        let mut lines = vec![
            json!({"QMP":{"version":{},"capabilities":[]}}),
            json!({"return":{}}),
        ];
        lines.extend_from_slice(replies);
        let bytes = lines
            .iter()
            .map(|line| format!("{line}\r\n"))
            .collect::<String>();
        QmpClient::connect(FixtureStream {
            replies: io::Cursor::new(bytes.into_bytes()),
            written: Arc::new(Mutex::new(Vec::new())),
            close_on_read: None,
        })
        .expect("scripted component QMP negotiation")
    }

    fn commands(client: &QmpClient<FixtureStream>) -> Vec<Value> {
        request_log(&client.stream.get_ref().written)
    }

    fn request_log(written: &Arc<Mutex<Vec<u8>>>) -> Vec<Value> {
        String::from_utf8(written.lock().expect("component request log").clone())
            .expect("request UTF8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("actual typed request"))
            .collect()
    }

    #[test]
    fn managed_reset_adapter_uses_same_client_and_borrows_original() {
        use crate::node::QemuQmpMachineControlChannel;

        let (_supervisor, original) = original();
        let client = client(&[json!({"event":"RESET"}), json!({"return":{}})]);
        let written = Arc::clone(&client.stream.get_ref().written);
        let vmstate = crate::QemuQmpVmStateControlChannel::new(client);
        let mut adapter = crate::node_factory::QemuQmpExactSnapshotControlChannel::new(vmstate);

        let result = adapter
            .reset_under_original(&original)
            .expect("typed reset acknowledgement");

        assert_eq!(result.command, QmpCommandKind::SystemReset);
        assert_eq!(request_log(&written)[1], json!({"execute":"system_reset"}));
        assert!(original.wait_slice().is_ok());
        assert_eq!(
            original
                .status()
                .expect("original status")
                .completed_work_units,
            1
        );
    }

    #[test]
    fn managed_reset_closed_original_ignores_unrelated_live_client_supervisor() {
        let (_supervisor, closed) = original();
        closed.complete().expect("close original before request");
        let (ambient, unrelated) = original();
        let mut client = client(&[json!({"return":{}})]);
        client.set_host_operation_supervisor(ambient);
        let before = commands(&client);

        assert!(matches!(
            client.reset_under_original(&closed),
            Err(QmpError::OperationalSupervision { .. })
        ));

        assert_eq!(commands(&client), before);
        assert_eq!(
            unrelated
                .status()
                .expect("ambient status")
                .completed_work_units,
            0
        );
        assert!(unrelated.wait_slice().is_ok());
    }

    #[test]
    fn managed_reset_preserves_typed_command_rejection() {
        let (_supervisor, original) = original();
        let mut client =
            client(&[json!({"error":{"class":"CommandNotFound","desc":"reset unavailable"}})]);

        let error = client
            .reset_under_original(&original)
            .expect_err("command rejection");

        assert!(
            matches!(error, QmpError::Command { command: QmpCommandKind::SystemReset, class, description } if class == "CommandNotFound" && description == "reset unavailable")
        );
        assert!(!client.poisoned);
        assert!(original.wait_slice().is_ok());
    }

    #[test]
    fn managed_reset_rejects_nonempty_or_nonobject_acknowledgements() {
        for value in [json!(null), json!(true), json!([]), json!({"unexpected":1})] {
            let (_supervisor, original) = original();
            let mut client = client(&[json!({"return":value}), json!({"return":{}})]);

            let first = client
                .reset_under_original(&original)
                .expect_err("invalid acknowledgement");
            let after = commands(&client);
            assert!(matches!(
                client.reset_under_original(&original),
                Err(QmpError::ConnectionPoisoned)
            ));

            assert!(matches!(
                first,
                QmpError::InvalidBound {
                    operation: "managed reset requires an empty QMP acknowledgement",
                }
            ));
            assert_eq!(commands(&client), after);
            assert_eq!(after.len(), 2);
            assert!(original.wait_slice().is_ok());
        }
    }

    #[test]
    fn managed_reset_lost_ack_poison_prevents_second_command() {
        let (_supervisor, original) = original();
        let mut client = client(&[]);

        assert!(client.reset_under_original(&original).is_err());
        assert!(client.poisoned);
        let after = commands(&client);
        assert!(client.reset_under_original(&original).is_err());
        assert_eq!(commands(&client), after);
        assert_eq!(after.len(), 2);
    }

    #[test]
    fn managed_reset_original_closure_during_reply_remains_refusal() {
        let (_supervisor, original) = original();
        let mut client = client(&[json!({"return":{}})]);
        client.stream.get_mut().close_on_read = Some(Arc::clone(&original));

        assert!(matches!(
            client.reset_under_original(&original),
            Err(QmpError::OperationalSupervision { .. })
        ));
        assert_eq!(commands(&client)[1], json!({"execute":"system_reset"}));
        assert!(original.wait_slice().is_err());
    }
}
