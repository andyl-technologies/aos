//! Retains one calling-thread context observation through the shared reader.
//!
//! This fixed-path DATA neither changes a label nor authenticates an owner.
//! Its genuine purpose supplies its compiled expected label and prepays all
//! native prefixes before entry; ordinary callers keep their original drops.

use std::error::Error as StdError;

use super::*;

pub(super) struct ContextReadOriginalV1 {
    open: Option<std::io::Result<()>>,
    reader: Option<std::io::Take<File>>,
    pub(super) bytes: Vec<u8>,
    read: Option<std::io::Result<usize>>,
    length: Option<Result<()>>,
}

impl ContextReadOriginalV1 {
    pub(super) const fn new() -> Self {
        Self {
            open: None,
            reader: None,
            bytes: Vec::new(),
            read: None,
            length: None,
        }
    }

    pub(super) fn read_once(&mut self, path: &str, retained: bool) -> Result<()> {
        match File::open(path) {
            Ok(file) => {
                // No fallible work intervenes between returned ownership and
                // parking the same native File in its bounded read carrier.
                self.reader = Some(file.take((MAXIMUM_CONTEXT_BYTES + 1) as u64));
                self.open = Some(Ok(()));
            }
            Err(error) => self.open = Some(Err(error)),
        }
        if !matches!(self.open, Some(Ok(()))) {
            return Err(native_read_error(&mut self.open, retained));
        }
        let Some(reader) = self.reader.as_mut() else {
            return Err(unavailable());
        };
        self.read = Some(reader.read_to_end(&mut self.bytes));
        if !retained {
            // The original File::open(...).and_then closure released this
            // exact File before mapping the read error or checking the length.
            drop(self.reader.take());
        }
        if !matches!(self.read, Some(Ok(_))) {
            return Err(native_read_error(&mut self.read, retained));
        }
        self.length = Some(if self.bytes.len() > MAXIMUM_CONTEXT_BYTES {
            Err(Error::invalid("Guest context", "context exceeds fixed bound"))
        } else {
            Ok(())
        });
        match self.length.as_ref() {
            Some(Ok(())) => Ok(()),
            _ if retained => Err(unavailable()),
            _ => self.length.take().ok_or_else(unavailable)?,
        }
    }

    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        failure(&self.open)
            .or_else(|| failure(&self.read))
            .or_else(|| failure(&self.length))
    }
}

/// Retains the actual calling-thread context read and exact label comparison.
#[must_use = "retain actual context acquisition and failures with the purpose owner"]
pub struct CurrentThreadSubjectOriginalV1 {
    observation: ContextReadOriginalV1,
    binding: Option<Result<()>>,
    result: Option<Result<()>>,
    file_retired: bool,
    reentry: Option<Error>,
    entered: bool,
}

impl CurrentThreadSubjectOriginalV1 {
    /// Creates inert fixed destinations without reading or changing a label.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            observation: ContextReadOriginalV1::new(),
            binding: None,
            result: None,
            file_retired: false,
            reentry: None,
            entered: false,
        }
    }

    /// Describes the actual owner, bounded byte work, one File, six results, one byte Vec and two controls.
    #[must_use]
    pub fn receiving_demand_v1() -> Option<(usize, usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(3 * (MAXIMUM_CONTEXT_BYTES + 1))?
            .checked_add(1024)?;
        // Original open/read/length, binding/result/reentry, the retained
        // reader namespace, byte Vec and entered/retired controls coexist.
        Some((bytes, 1, 10))
    }

    /// Observes the calling thread once against the purpose's expected context.
    ///
    /// # Errors
    /// Rejects reentry, failed fixed procfs reads, oversized or unequal labels.
    /// No returned comparison authorizes an operation or creates a role owner.
    pub fn observe_once(&mut self, expected: &str) -> Result<()> {
        if self.entered {
            self.reentry.get_or_insert_with(unavailable);
            return Err(unavailable());
        }
        self.entered = true;
        self.result = Some(self.observe_recipe(expected, true));
        match self.result {
            Some(Ok(())) => Ok(()),
            _ => Err(unavailable()),
        }
    }

    pub(super) fn observe_recipe(&mut self, expected: &str, retained: bool) -> Result<()> {
        self.observation.read_once("/proc/thread-self/attr/current", retained)?;
        self.binding = Some(if context_matches(&self.observation.bytes, expected) {
            Ok(())
        } else {
            Err(Error::invalid("Guest subject", "current context differs"))
        });
        match self.binding.as_ref() {
            Some(Ok(())) => Ok(()),
            _ if retained => Err(unavailable()),
            _ => self.binding.take().ok_or_else(unavailable)?,
        }
    }

    /// Drops only this complete positive read's original File once.
    ///
    /// Actual bytes, read/length/binding outcomes and the entered fence stay
    /// resident. No failed prefix is released and no subject or financial
    /// authority follows from descriptor disposal.
    #[must_use]
    pub fn retire_completed_file_once_v1(&mut self) -> bool {
        if self.file_retired
            || !self.is_complete()
            || self.failure().is_some()
            || self.observation.reader.is_none()
        {
            return false;
        }
        drop(self.observation.reader.take());
        self.file_retired = true;
        true
    }

    /// Borrows the first original native read or semantic comparison refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.observation.failure()
            .or_else(|| failure(&self.binding))
            .or_else(|| failure(&self.result))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as &dyn StdError))
    }

    /// Reports a complete comparison without granting subject/role authority.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.result, Some(Ok(()))) && self.reentry.is_none()
    }
}

impl Default for CurrentThreadSubjectOriginalV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn native_read_error<T>(slot: &mut Option<std::io::Result<T>>, retained: bool) -> Error {
    if !retained {
        if let Some(Err(source)) = slot.take() {
            return Error::Syscall {
                operation: "read Guest context",
                source,
            };
        }
    }
    unavailable()
}

fn unavailable() -> Error {
    Error::invalid("Guest subject observation", "retained context observation unavailable")
}

fn failure<T, E: StdError + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .map(|cause| cause as &dyn StdError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_context_refusal_keeps_file_bytes_and_exact_cause_on_reentry() {
        let mut original = CurrentThreadSubjectOriginalV1::new();
        // No role is admitted by this deliberately foreign comparison.
        assert!(original.observe_once("deliberately-foreign-context").is_err());
        let first = original.failure().unwrap();
        if let Some(native) = first.downcast_ref::<std::io::Error>() {
            let pointer = native as *const std::io::Error;
            assert!(original.observe_once("deliberately-foreign-context").is_err());
            assert!(std::ptr::eq(
                original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap(),
                pointer,
            ));
        } else {
            let pointer = first.downcast_ref::<Error>().unwrap() as *const Error;
            assert!(original.observation.reader.is_some());
            assert!(original.observe_once("deliberately-foreign-context").is_err());
            assert!(std::ptr::eq(original.failure().unwrap().downcast_ref::<Error>().unwrap(), pointer));
        }
        assert!(!original.is_complete());
        assert!(!original.retire_completed_file_once_v1());
    }
}
