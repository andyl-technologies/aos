//! Actual actor cancellation and unwind preserve the loop's consuming return.

use super::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicUsize;

#[derive(Default)]
struct ReturnedFile {
    retired: AtomicUsize,
    discarded: AtomicUsize,
    body: Mutex<Option<File>>,
}

struct FileLoop {
    file: Option<File>,
    returned: Arc<ReturnedFile>,
    panic_on_drive: bool,
}

impl QuantumLoop for FileLoop {
    fn drive_quantum(&mut self, _: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        assert!(
            self.panic_on_drive,
            "only the panic control drives this loop"
        );
        panic!("the component loop panics after actor entry");
    }

    fn retire_owned(mut self) {
        assert_eq!(self.returned.retired.fetch_add(1, Ordering::SeqCst), 0);
        let mut body = self.returned.body.lock().unwrap();
        assert!(body.is_none());
        *body = self.file.take();
    }
}

impl Drop for FileLoop {
    fn drop(&mut self) {
        if self.file.is_some() {
            self.returned.discarded.fetch_add(1, Ordering::SeqCst);
        }
    }
}

fn retained_file_loop() -> (FileLoop, Arc<ReturnedFile>, i32) {
    static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "crucible-session-return-{}-{}",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed),
    ));
    let mut file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(path).unwrap();
    file.write_all(b"same retained session body").unwrap();
    let descriptor = file.as_raw_fd();
    let returned = Arc::new(ReturnedFile::default());
    (
        FileLoop {
            file: Some(file),
            returned: Arc::clone(&returned),
            panic_on_drive: false,
        },
        returned,
        descriptor,
    )
}

fn engine(quantum_loop: FileLoop) -> Engine<FileLoop> {
    let scenario = generated_scenario(90_601);
    Engine::new(
        Configuration::genesis(scenario.clone()),
        graph_with_baked_genesis(&scenario),
        quantum_loop,
    )
}

fn assert_same_file_returned(returned: &ReturnedFile, descriptor: i32) {
    assert_eq!(returned.retired.load(Ordering::SeqCst), 1);
    assert_eq!(returned.discarded.load(Ordering::SeqCst), 0);
    let mut file = returned.body.lock().unwrap().take().unwrap();
    assert_eq!(file.as_raw_fd(), descriptor);
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "same retained session body");
}

#[test]
fn unpolled_actor_and_unpolled_run_return_the_actual_loop() {
    let _scope = fixture_metadata_scope();
    for poll_run in [false, true] {
        let (quantum_loop, returned, descriptor) = retained_file_loop();
        let (_sender, mailbox) = mpsc::channel(1);
        let actor = SessionActor::new(engine(quantum_loop), mailbox);

        if poll_run {
            drop(actor.run());
        } else {
            drop(actor);
        }

        assert_same_file_returned(&returned, descriptor);
    }
}

#[tokio::test]
async fn normal_actor_return_retires_the_same_loop_once() {
    let (actor, returned, descriptor) = {
        let _scope = fixture_metadata_scope();
        let (quantum_loop, returned, descriptor) = retained_file_loop();
        let mut engine = engine(quantum_loop);
        engine.state = EngineState::Stopped {
            outcome: Outcome::Stopped,
        };
        let (_sender, mailbox) = mpsc::channel(1);
        (SessionActor::new(engine, mailbox), returned, descriptor)
    };

    let report = admitted_fixture(actor.run()).await.unwrap();

    assert!(matches!(
        report.final_snapshot.state,
        EngineState::Stopped { .. }
    ));
    assert_same_file_returned(&returned, descriptor);
}

#[tokio::test]
async fn abort_after_an_actual_mailbox_reply_returns_the_loop() {
    let (actor, sender, returned, descriptor) = {
        let _scope = fixture_metadata_scope();
        let (quantum_loop, returned, descriptor) = retained_file_loop();
        let (sender, mailbox) = mpsc::channel(1);
        (
            SessionActor::new(engine(quantum_loop), mailbox),
            sender,
            returned,
            descriptor,
        )
    };
    let task = tokio::spawn(admitted_fixture(actor.run()));
    let (reply, response) = CommandReply::channel();
    sender
        .send(SessionCommand::Query {
            kind: QueryKind::Snapshot,
            reply,
        })
        .await
        .unwrap();
    assert!(response.await.unwrap().is_ok());
    assert_eq!(returned.retired.load(Ordering::SeqCst), 0);

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    assert_same_file_returned(&returned, descriptor);
}

#[tokio::test]
async fn actor_panic_returns_the_actual_loop_during_unwind() {
    let (actor, _sender, returned, descriptor) = {
        let _scope = fixture_metadata_scope();
        let (mut quantum_loop, returned, descriptor) = retained_file_loop();
        quantum_loop.panic_on_drive = true;
        let mut engine = engine(quantum_loop);
        engine.state = EngineState::Running;
        let (sender, mailbox) = mpsc::channel(1);
        (
            SessionActor::new(engine, mailbox),
            sender,
            returned,
            descriptor,
        )
    };

    let failure = tokio::spawn(admitted_fixture(actor.run()))
        .await
        .unwrap_err();

    assert!(failure.is_panic());
    assert_same_file_returned(&returned, descriptor);
}

#[test]
fn explicit_extraction_disarms_the_same_owner_and_constructor_refusal_retires() {
    let _scope = fixture_metadata_scope();
    let (quantum_loop, returned, descriptor) = retained_file_loop();
    let extracted = engine(quantum_loop).into_quantum_loop().unwrap();
    assert_eq!(returned.retired.load(Ordering::SeqCst), 0);

    extracted.retire_owned();
    assert_same_file_returned(&returned, descriptor);

    let (quantum_loop, returned, descriptor) = retained_file_loop();
    let missing = Configuration::genesis(generated_scenario(90_602)).id();
    let result = Engine::from_recorded_checkpoint(TemporalGraph::empty(), quantum_loop, missing);
    assert!(matches!(
        result,
        Err(SessionError::Engine(
            EngineError::CheckpointNotRecorded { .. }
        ))
    ));
    assert_same_file_returned(&returned, descriptor);
}
