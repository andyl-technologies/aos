//! Writes the already retained bootstrap proposal on the original guarded stream.
//!
//! The enclosing publication spends its original
//! once occurrence and admits physical effects before entering this helper.

use super::*;

impl Literal {
    /// Publishes the existing proposal while retaining its first actual failure.
    ///
    /// The caller lends the original unbuffered channel inside complete custody
    /// guards. Each successful write advances the original slot immediately.
    ///
    /// # Errors
    /// Refuses an incomplete/changed proposal, prior failure, guard or actual I/O.
    pub(in super::super) fn write_prepared_data(
        &mut self,
        stream: &mut impl Write,
        failure: &mut Option<ProviderError>,
        mut guard: impl FnMut() -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        if failure.is_some() {
            return Err(refused());
        }
        let outcome = self.write_current_prepared_data(stream, &mut guard);
        if let Err(error) = outcome {
            *failure = Some(error);
            return Err(refused());
        }
        Ok(())
    }

    fn write_current_prepared_data(
        &mut self,
        stream: &mut impl Write,
        guard: &mut impl FnMut() -> Result<(), ProviderError>,
    ) -> Result<(), ProviderError> {
        guard()?;
        if !self.encoded_complete || !self.measure_complete {
            return Err(refused());
        }
        let slot = self.slot.ok_or_else(refused)?;
        let journal = self.journal.as_mut().ok_or_else(refused)?;
        let frame = journal.frame(slot).ok_or_else(refused)?;
        if frame.direction != FrameDirection::Outgoing
            || frame.transferred != 0
            || frame.complete
            || self.measured != Some(self.encoded)
            || frame.bytes.len() != self.encoded.checked_add(4).ok_or_else(exhausted)?
        {
            return Err(refused());
        }
        let total = frame.bytes.len();
        let mut transferred = 0;
        while transferred < total {
            guard()?;
            let frame = journal.frame(slot).ok_or_else(refused)?;
            let written = match stream.write(&frame.bytes[transferred..]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if written == 0 || written > total - transferred {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            journal.advance(slot, written)?;
            transferred += written;
        }
        // Completion records physical transfer independently of permission:
        // a later terminal refusal retains the fact that all bytes were sent.
        journal.finish(slot)?;
        guard()
    }

    /// Checks the exact stored proposal and complete original transfer.
    ///
    /// # Errors
    /// Refuses missing preparation, changed extent or incomplete physical I/O.
    pub(in super::super) fn authenticate_written_data(&self) -> Result<(), ProviderError> {
        let frame = self
            .journal
            .as_ref()
            .ok_or_else(refused)?
            .frame(self.slot.ok_or_else(refused)?)
            .ok_or_else(refused)?;
        if !self.encoded_complete
            || self.measured != Some(self.encoded)
            || frame.direction != FrameDirection::Outgoing
            || !frame.complete
            || frame.bytes.len() != self.encoded.checked_add(4).ok_or_else(exhausted)?
            || frame.transferred != frame.bytes.len()
        {
            return Err(refused());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn prepared() -> Literal {
        let id = Id::new("original").unwrap();
        let mut literal = Literal::empty_data();
        literal.reserve_data(128).unwrap();
        literal.value = Some(serde_json::json!({"request_id":id.as_str()}));
        literal.measure_data(128, 64).unwrap();
        literal.encode_data(&id).unwrap();
        literal
    }

    struct PartialWriter {
        bytes: Vec<u8>,
        interrupt: bool,
        fail_after: Option<usize>,
        zero: bool,
    }

    impl Write for PartialWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if std::mem::take(&mut self.interrupt) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self
                .fail_after
                .is_some_and(|limit| self.bytes.len() >= limit)
            {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            if self.zero {
                return Ok(0);
            }
            let count = bytes.len().min(3);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            panic!("unbuffered publication must not flush")
        }
    }

    #[test]
    fn physical_partial_failure_keeps_the_exact_transferred_prefix_and_first_error() {
        let mut literal = prepared();
        let before = literal.retained_backing_data().unwrap();
        let pointer = literal
            .journal
            .as_ref()
            .unwrap()
            .frame(literal.slot.unwrap())
            .unwrap()
            .bytes
            .as_ptr();
        let mut writer = PartialWriter {
            bytes: Vec::new(),
            interrupt: true,
            fail_after: Some(6),
            zero: false,
        };
        let mut failure = None;

        assert!(
            literal
                .write_prepared_data(&mut writer, &mut failure, || Ok(()))
                .is_err()
        );
        let frame = literal
            .journal
            .as_ref()
            .unwrap()
            .frame(literal.slot.unwrap())
            .unwrap();
        assert_eq!(frame.transferred, 6);
        assert_eq!(writer.bytes, &frame.bytes[..6]);
        assert!(!frame.complete);
        assert_eq!(frame.bytes.as_ptr(), pointer);
        assert!(
            matches!(failure, Some(ProviderError::Io(ref error)) if error.kind() == io::ErrorKind::BrokenPipe)
        );
        assert!(literal.authenticate_written_data().is_err());
        assert!(
            literal
                .write_prepared_data(&mut writer, &mut failure, || panic!("retry entered"))
                .is_err()
        );
        assert_eq!(writer.bytes.len(), 6);
        assert_eq!(literal.retained_backing_data().unwrap(), before);
    }

    #[test]
    fn complete_transfer_survives_terminal_refusal_and_cannot_be_written_twice() {
        let mut literal = prepared();
        let mut writer = PartialWriter {
            bytes: Vec::new(),
            interrupt: true,
            fail_after: None,
            zero: false,
        };
        let mut failure = None;
        let calls = Cell::new(0);
        let bytes = literal
            .journal
            .as_ref()
            .unwrap()
            .frame(literal.slot.unwrap())
            .unwrap()
            .bytes
            .len();
        // Initial guard, one interrupted attempt, each successful three-byte
        // write, then the final guard after recording complete physical I/O.
        let terminal = bytes.div_ceil(3) + 3;
        assert!(
            literal
                .write_prepared_data(&mut writer, &mut failure, || {
                    let call = calls.get() + 1;
                    calls.set(call);
                    if call == terminal {
                        return Err(refused());
                    }
                    Ok(())
                })
                .is_err()
        );
        literal.authenticate_written_data().unwrap();
        assert_eq!(writer.bytes.len(), bytes);
        assert!(failure.is_some());
        assert!(
            literal
                .write_prepared_data(&mut writer, &mut failure, || panic!("retry entered"))
                .is_err()
        );
        assert_eq!(writer.bytes.len(), bytes);

        let mut success = prepared();
        let mut discarded = Vec::new();
        let mut failure = None;
        success
            .write_prepared_data(&mut discarded, &mut failure, || Ok(()))
            .unwrap();
        success.authenticate_written_data().unwrap();
        assert!(failure.is_none());
        assert!(
            success
                .write_prepared_data(&mut discarded, &mut failure, || Ok(()))
                .is_err()
        );
        assert_eq!(discarded.len(), bytes);
    }

    #[test]
    fn zero_write_keeps_an_untransferred_proposal_and_actual_io_refusal() {
        let mut literal = prepared();
        let mut writer = PartialWriter {
            bytes: Vec::new(),
            interrupt: false,
            fail_after: None,
            zero: true,
        };
        let mut failure = None;
        assert!(
            literal
                .write_prepared_data(&mut writer, &mut failure, || Ok(()))
                .is_err()
        );
        let frame = literal
            .journal
            .as_ref()
            .unwrap()
            .frame(literal.slot.unwrap())
            .unwrap();
        assert_eq!(frame.transferred, 0);
        assert!(!frame.complete);
        assert!(
            matches!(failure, Some(ProviderError::Io(ref error)) if error.kind() == io::ErrorKind::WriteZero)
        );
    }
}
