//! Retains the same at-most-two-entry single-thread process observation.
//!
//! This mechanical proof grants no Source, role, budget or namespace authority.
//! Ordinary verification and prepaid capture share one native directory recipe.

use std::error::Error as StdError;
use std::fs::{DirEntry, ReadDir};
use std::marker::PhantomData;
use std::rc::Rc;

use super::{Error, Result, SingleThreadedProcess};

trait Native {
    fn open(&mut self) -> Result<()>;
    fn next(&mut self, index: usize) -> Result<bool>;
}

fn recipe(native: &mut impl Native) -> Result<SingleThreadedProcess> {
    native.open()?;
    if !native.next(0)? {
        return Err(Error::invalid(
            "namespace worker",
            "process has no visible calling thread",
        ));
    }
    if native.next(1)? {
        return Err(Error::invalid(
            "namespace worker",
            "process has more than one thread",
        ));
    }
    Ok(SingleThreadedProcess {
        not_send_or_sync: PhantomData,
    })
}

struct Local {
    directory: Option<ReadDir>,
}

impl Native for Local {
    fn open(&mut self) -> Result<()> {
        self.directory =
            Some(
                std::fs::read_dir("/proc/self/task").map_err(|source| Error::Syscall {
                    operation: "read /proc/self/task",
                    source,
                })?,
            );
        Ok(())
    }

    fn next(&mut self, _: usize) -> Result<bool> {
        let directory = self.directory.as_mut().ok_or_else(closed)?;
        match directory.next() {
            Some(Ok(_)) => Ok(true),
            Some(Err(source)) => Err(Error::Syscall {
                operation: "read /proc/self/task entry",
                source,
            }),
            None => Ok(false),
        }
    }
}

pub(super) fn verify_local() -> Result<SingleThreadedProcess> {
    recipe(&mut Local { directory: None })
}

#[derive(Clone, Copy)]
enum First {
    Order,
    Open,
    Entry(usize),
    Recipe,
}

/// Retains the actual task DIR, both reached entries and first native refusal.
///
/// The genuine purpose prices this finite observation before capture and keeps
/// the original through all independently owed posts. A completed proof cannot
/// move across threads or be reconstructed from a count or packet.
#[must_use]
pub struct SingleThreadedProcessOriginalV2 {
    entered: bool,
    directory: Option<std::io::Result<ReadDir>>,
    entries: [Option<Option<std::io::Result<DirEntry>>>; 2],
    returned: Option<Result<SingleThreadedProcess>>,
    first: Option<First>,
    closed: Option<Error>,
    taken: bool,
    not_send_or_sync: PhantomData<Rc<()>>,
}

impl SingleThreadedProcessOriginalV2 {
    /// Creates inert destinations without opening procfs or counting tasks.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entered: false,
            directory: None,
            entries: std::array::from_fn(|_| None),
            returned: None,
            first: None,
            closed: None,
            taken: false,
            not_send_or_sync: PhantomData,
        }
    }

    /// Prices the fixed original, two entry reservoirs and actual native DIR.
    ///
    /// This reuses the same qualified libc DIR, Rust Arc, path, two NAME_MAX
    /// reservoirs and stack supplier as the retained process runner. Its
    /// unavailable platform gate stays closed. No allowance or limit is made.
    #[must_use]
    pub fn receiving_obligations_data_v2() -> Option<(usize, usize)> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(crate::process::task_directory_representation_bytes_v3()?)?
            .checked_add(2 * 128)?;
        Some((bytes, 1))
    }

    /// Observes the same current process's task directory once.
    ///
    /// # Errors
    /// Retains unavailable procfs/entry IO, zero or multiple tasks and reentry.
    /// No second entry is observed after the first native failure.
    pub fn capture_once_v2(&mut self) -> Result<()> {
        if self.entered {
            self.first.get_or_insert(First::Order);
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.returned = Some(recipe(self));
        if matches!(self.returned, Some(Ok(_))) {
            Ok(())
        } else {
            self.first.get_or_insert(First::Recipe);
            Err(closed())
        }
    }

    /// Moves the same actual completed single-thread proof once.
    #[must_use]
    pub fn take_completed_once_v2(&mut self) -> Option<SingleThreadedProcess> {
        if self.first.is_some() || self.taken || !matches!(self.returned, Some(Ok(_))) {
            return None;
        }
        self.taken = true;
        match self.returned.take()? {
            Ok(process) => Some(process),
            Err(_) => None,
        }
    }

    /// Borrows the selected actual native or semantic refusal.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        let cause: Option<&(dyn StdError + 'static)> = match self.first? {
            First::Open => self
                .directory
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::Entry(index) => self.entries[index]
                .as_ref()
                .and_then(|entry| entry.as_ref())
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::Recipe => self
                .returned
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as _),
            First::Order => None,
        };
        cause.or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl Native for SingleThreadedProcessOriginalV2 {
    fn open(&mut self) -> Result<()> {
        self.directory = Some(std::fs::read_dir("/proc/self/task"));
        if matches!(self.directory, Some(Ok(_))) {
            Ok(())
        } else {
            self.first.get_or_insert(First::Open);
            Err(closed())
        }
    }

    fn next(&mut self, index: usize) -> Result<bool> {
        let Some(Ok(directory)) = self.directory.as_mut() else {
            return Err(closed());
        };
        self.entries[index] = Some(directory.next());
        match self.entries[index].as_ref() {
            Some(Some(Ok(_))) => Ok(true),
            Some(None) => Ok(false),
            _ => {
                self.first.get_or_insert(First::Entry(index));
                Err(closed())
            }
        }
    }
}

impl Default for SingleThreadedProcessOriginalV2 {
    fn default() -> Self {
        Self::new()
    }
}

fn closed() -> Error {
    Error::invalid(
        "retained single-thread observation",
        "the original native result is retained",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Script {
        fail_open: bool,
        replies: [Option<bool>; 2],
        reads: Vec<usize>,
    }

    impl Native for Script {
        fn open(&mut self) -> Result<()> {
            if self.fail_open {
                Err(closed())
            } else {
                Ok(())
            }
        }

        fn next(&mut self, index: usize) -> Result<bool> {
            self.reads.push(index);
            self.replies[index].ok_or_else(closed)
        }
    }

    #[test]
    fn native_failure_stops_before_later_task_observations() {
        let mut failed_open = Script {
            fail_open: true,
            replies: [Some(true), Some(false)],
            reads: Vec::new(),
        };
        assert!(recipe(&mut failed_open).is_err());
        assert!(failed_open.reads.is_empty());

        let mut failed_first = Script {
            fail_open: false,
            replies: [None, Some(true)],
            reads: Vec::new(),
        };
        assert!(recipe(&mut failed_first).is_err());
        assert_eq!(failed_first.reads, [0]);
    }

    #[test]
    fn exact_one_task_requires_the_completed_second_end_observation() {
        let mut one = Script {
            fail_open: false,
            replies: [Some(true), Some(false)],
            reads: Vec::new(),
        };
        assert!(recipe(&mut one).is_ok());
        assert_eq!(one.reads, [0, 1]);

        let mut none = Script {
            fail_open: false,
            replies: [Some(false), Some(true)],
            reads: Vec::new(),
        };
        assert!(recipe(&mut none).is_err());
        assert_eq!(none.reads, [0]);

        let mut multiple = Script {
            fail_open: false,
            replies: [Some(true), Some(true)],
            reads: Vec::new(),
        };
        assert!(recipe(&mut multiple).is_err());
        assert_eq!(multiple.reads, [0, 1]);
    }
}
