//! Backend trait object-safety contract test.

use super::*;

#[test]
fn backend_trait_is_object_safe() {
    struct StubBackend;

    impl Backend for StubBackend {
        fn advance_to_horizon(
            &mut self,
            _horizon: ExecutionHorizon,
        ) -> Result<AdvanceOutcome, BackendError> {
            Ok(AdvanceOutcome::ReachedHorizon)
        }

        fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
            Ok(ExecutionFingerprint {
                hash: ContentHash::default(),
            })
        }

        fn deliver_input(&mut self, _input: BackendInput) -> Result<(), BackendError> {
            Ok(())
        }

        fn snapshot(&mut self) -> Result<Checkpoint, BackendError> {
            Ok(Checkpoint::new(
                ContentHash::default(),
                ContentHash::default(),
                CheckpointKind::Fat,
            ))
        }

        fn restore(&mut self, _checkpoint: &Checkpoint) -> Result<(), BackendError> {
            Ok(())
        }

        fn shutdown(&mut self) -> Result<(), BackendError> {
            Ok(())
        }
    }

    let mut backend = StubBackend;
    let object: &mut dyn Backend = &mut backend;
    let advanced = object.advance_to_horizon(ExecutionHorizon {
        icount: Icount { retired: 10 },
    });

    assert_eq!(advanced, Ok(AdvanceOutcome::ReachedHorizon));
}
