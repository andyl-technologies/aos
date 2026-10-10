//! Retires the existing materializer without a fresh wait or response channel.
//!
//! The same bounded queue receives the terminal command. Backpressure and
//! thread exit use only retained original wait slices. A refusal leaves the
//! real thread and sender inside the existing enclosing executor owner.

use crucible_linux_resource::host_supervision::{HostOperationGuard, HostSupervisionError};
use std::sync::mpsc::TrySendError;

use super::*;

/// Preserves a materializer cause across its independent raw original post.
#[derive(Debug, thiserror::Error)]
pub enum OriginalMaterializerRetirementError {
    /// The saved original refused before further physical retirement.
    #[error("original materializer retirement refused: {0}")]
    Original(#[from] HostSupervisionError),
    /// The same joined materializer returned its actual retained cause.
    #[error("materializer retirement refused: {cause}; original post: {post:?}")]
    Materializer {
        /// The initiating thread or catalog cause.
        #[source]
        cause: PackagedExactPinMaterializerError,
        /// A separately observed raw original refusal.
        post: Option<HostSupervisionError>,
    },
}

impl PackagedExactPinMaterializerOwner {
    /// Stops this existing owner and joins only after its actual thread exits.
    ///
    /// # Errors
    /// Retains the actual thread on original refusal; preserves a joined
    /// materializer's cause before its independently observed original post.
    pub(crate) fn try_retire_original(
        &mut self,
        original: &HostOperationGuard,
    ) -> Result<(), OriginalMaterializerRetirementError> {
        self.retire_with_post_join(original, || {})
    }

    fn retire_with_post_join(
        &mut self,
        original: &HostOperationGuard,
        post_join: impl FnOnce(),
    ) -> Result<(), OriginalMaterializerRetirementError> {
        original.wait_slice()?;
        if self.thread.is_none() {
            return Ok(());
        }
        self.shutdown.store(true, Ordering::Release);

        loop {
            if self.thread.as_ref().is_some_and(JoinHandle::is_finished) {
                break;
            }
            original.wait_slice()?;
            match self.sender.try_send(MaterializerCommand::Shutdown) {
                Ok(()) | Err(TrySendError::Disconnected(_)) => break,
                Err(TrySendError::Full(_)) => thread::park_timeout(original.wait_slice()?),
            }
        }
        while self
            .thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
        {
            thread::park_timeout(original.wait_slice()?);
        }

        let work = self.join_inner();
        post_join();
        let post = original.wait_slice().err();
        match (work, post) {
            (Ok(()), None) => Ok(()),
            (Ok(()), Some(cause)) => Err(cause.into()),
            (Err(cause), post) => {
                Err(OriginalMaterializerRetirementError::Materializer { cause, post })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationClass, HostOperationSupervisor,
    };

    #[test]
    fn actual_materializer_thread_joins_without_a_response_channel()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = sync_channel(1);
        let worker = thread::spawn(move || match receiver.recv() {
            Ok(MaterializerCommand::Shutdown) => Ok(()),
            _ => Err(PackagedExactPinMaterializerError::CatalogInvariant),
        });
        let mut owner = PackagedExactPinMaterializerOwner {
            shutdown: Arc::new(AtomicBool::new(false)),
            sender,
            thread: Some(worker),
        };
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;

        assert!(owner.try_retire_original(&original).is_ok());

        assert!(owner.thread.is_none());
        assert!(owner.shutdown.load(Ordering::Acquire));
        assert!(owner.try_retire_original(&original).is_ok());
        Ok(())
    }

    #[test]
    fn actual_thread_cause_remains_first_when_original_refuses_after_join()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = sync_channel(1);
        let worker = thread::spawn(move || {
            let _ = receiver.recv();
            Err(PackagedExactPinMaterializerError::CatalogInvariant)
        });
        let mut owner = PackagedExactPinMaterializerOwner {
            shutdown: Arc::new(AtomicBool::new(false)),
            sender,
            thread: Some(worker),
        };
        let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None)?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;

        let result = owner.retire_with_post_join(&original, || {
            assert!(supervisor.cancel().is_ok());
        });

        assert!(matches!(
            result,
            Err(OriginalMaterializerRetirementError::Materializer {
                cause: PackagedExactPinMaterializerError::CatalogInvariant,
                post: Some(_),
            })
        ));
        assert!(owner.thread.is_none());
        Ok(())
    }

    #[test]
    fn original_queue_deadline_keeps_actual_thread_and_sender_owned()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sender, receiver) = sync_channel(1);
        assert!(sender.send(MaterializerCommand::Shutdown).is_ok());
        let (release, released) = sync_channel(1);
        let worker = thread::spawn(move || {
            let _ = released.recv();
            let _ = receiver.recv();
            Ok(())
        });
        let mut owner = PackagedExactPinMaterializerOwner {
            shutdown: Arc::new(AtomicBool::new(false)),
            sender,
            thread: Some(worker),
        };
        let supervisor = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_millis(25)),
        )?;
        let original = supervisor.begin(HostOperationClass::Preparation)?;

        assert!(matches!(
            owner.try_retire_original(&original),
            Err(OriginalMaterializerRetirementError::Original(_))
        ));
        assert!(
            owner
                .thread
                .as_ref()
                .is_some_and(|thread| !thread.is_finished())
        );

        assert!(release.send(()).is_ok());
        assert!(owner.join().is_ok());
        Ok(())
    }
}
