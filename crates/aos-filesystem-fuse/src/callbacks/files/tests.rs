//! Debug-only callback fixtures with a real protected journal and scripted data.
//!
//! Scripted Complete is not a backing or cryptographic qualification. The
//! installed VM fixture independently exercises the real sealed-FD provider.

use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;

use aos_filesystem_view::{
    DataError, DataReadScratch, DurableStateLimits, ExtendedAttributeLimits, MonotonicClock,
    RegistrationLimits, TeardownSummary,
};
use aos_sandbox_core::ObjectDigest;

use super::*;
use crate::fallback::FallbackState;

#[derive(Clone, Copy)]
enum ReaderMode {
    Complete,
    BadDigest,
    BadSize,
    PrefixFailure,
    RetryPastBound,
    CancelDuringRead,
    RenameJournalDuringRead,
}

struct ScriptedReader {
    mode: ReaderMode,
    calls: usize,
    cancellation: c_int,
    journal: std::path::PathBuf,
}

impl VerifiedObjectReader for ScriptedReader {
    fn read_verified(
        &mut self,
        request: ObjectReadRequest<'_>,
        output: &mut [u8],
    ) -> Result<ObjectReadResult, DataError> {
        self.calls += 1;
        output.fill(b'X');
        match self.mode {
            ReaderMode::PrefixFailure => return Err(DataError::IntegrityFailure),
            ReaderMode::RetryPastBound => {
                return Ok(ObjectReadResult::Retryable {
                    retry_after_ns: u64::MAX,
                });
            }
            ReaderMode::CancelDuringRead => {
                // SAFETY: The fixture retains this borrowed socket through the callback.
                assert_eq!(
                    unsafe { libc::shutdown(self.cancellation, libc::SHUT_RDWR) },
                    0
                );
            }
            ReaderMode::RenameJournalDuringRead => {
                std::fs::rename(&self.journal, self.journal.with_extension("retained")).unwrap();
            }
            _ => {}
        }
        Ok(ObjectReadResult::Complete {
            digest: if matches!(self.mode, ReaderMode::BadDigest) {
                ObjectDigest::from_bytes([0; 32])
            } else {
                request.descriptor.digest()
            },
            encoded_size: request.descriptor.encoded_size()
                + u64::from(matches!(self.mode, ReaderMode::BadSize)),
            object_offset: request.object_offset,
            bytes: output.len(),
        })
    }
}

fn with_context(
    mode: ReaderMode,
    action: impl FnOnce(&mut Context<'_, '_, '_, '_, '_>),
) -> (TeardownSummary, usize) {
    with_profile_context(mode, false, action)
}

fn with_profile_context(
    mode: ReaderMode,
    sparse: bool,
    action: impl FnOnce(&mut Context<'_, '_, '_, '_, '_>),
) -> (TeardownSummary, usize) {
    let mut result = None;
    crate::tests::with_fallback_connection(
        sparse,
        |mut connection, data, scratch, connected, cancellation| {
            let limits = crate::tests::limits();
            let budget = crate::tests::budget();
            crate::initialize_metadata(&mut connection, cancellation, limits, budget).unwrap();
            let directory = tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap();
            let mut owner =
                ProtectedFuseRegistrationOwnerV2::open_test_fixture(directory.path()).unwrap();
            let mut reader = ScriptedReader {
                mode,
                calls: 0,
                cancellation: cancellation.as_raw_fd(),
                journal: directory.path().join("registrations.journal"),
            };
            let summary = {
                let mut context = Context::new(
                    connection,
                    scratch,
                    cancellation.as_raw_fd(),
                    limits,
                    budget,
                );
                let durable = DurableStateLimits {
                    maximum_bytes: 4096,
                    maximum_registration_records: 1,
                };
                let adapter = context
                    .prepare_dormant_operations(
                        &mut owner,
                        durable,
                        RegistrationLimits {
                            maximum_registrations: 1,
                            maximum_open_references: 16,
                        },
                        crate::operations::ImmutableOperationLimits {
                            maximum_file_handles: 16,
                            maximum_read_bytes: 4096,
                            extended_attributes: ExtendedAttributeLimits {
                                maximum_name_bytes: 255,
                                maximum_value_bytes: 4096,
                                maximum_list_bytes: 4096,
                                maximum_attributes_per_inode: 1,
                                maximum_scratch_heap_bytes: 4096,
                            },
                        },
                    )
                    .unwrap();
                context.fallback = Some(FallbackState {
                    adapter,
                    data,
                    scratch: DataReadScratch::allocate(4096, 4096).unwrap(),
                    durable,
                    owner: &mut owner,
                    reader: &mut reader,
                });
                action(&mut context);
                // SAFETY: The real table's scoped destroy gets this same unique Context.
                unsafe {
                    (FALLBACK_OPERATIONS_V2.metadata.destroy)(raw(&mut context));
                }
                assert!(context.destroyed);
                context.connection.teardown()
            };
            // SAFETY: F_GETFD observes the still borrowed fixture descriptors.
            assert!(unsafe { libc::fcntl(connected.as_raw_fd(), libc::F_GETFD) } >= 0);
            assert!(unsafe { libc::fcntl(cancellation.as_raw_fd(), libc::F_GETFD) } >= 0);
            result = Some((summary, reader.calls));
        },
    );
    result.unwrap()
}

fn raw(context: &mut Context<'_, '_, '_, '_, '_>) -> *mut c_void {
    (context as *mut Context<'_, '_, '_, '_, '_>).cast()
}

fn deadline(context: &Context<'_, '_, '_, '_, '_>) -> u64 {
    Control::new(context.cancellation, 2).unwrap().now_ns() + 2_000_000_000
}

fn lookup(context: &mut Context<'_, '_, '_, '_, '_>) -> u64 {
    let mut attributes = abi::Attributes::default();
    // SAFETY: This exact table receives valid nonoverlapping fixture outputs.
    assert_eq!(
        unsafe {
            (FALLBACK_OPERATIONS_V2.metadata.lookup)(
                raw(context),
                1,
                b"file".as_ptr(),
                4,
                &mut attributes,
            )
        },
        0
    );
    attributes.node_id
}

struct Publication {
    handle: u64,
    fail: bool,
}

unsafe extern "C" fn publish(responder: *mut c_void, handle: u64) -> c_int {
    // SAFETY: open_file passes this stack Publication for this one callback only.
    let publication = unsafe { &mut *responder.cast::<Publication>() };
    publication.handle = handle;
    if publication.fail { libc::EIO } else { 0 }
}

fn open_file(context: &mut Context<'_, '_, '_, '_, '_>, node: u64, fail: bool) -> (c_int, u64) {
    let mut publication = Publication { handle: 0, fail };
    let deadline = deadline(context);
    // SAFETY: The exact scoped OPEN receives its stack-owned one-shot responder.
    let result = unsafe {
        (FALLBACK_OPERATIONS_V2.open)(
            raw(context),
            node,
            libc::O_RDONLY,
            deadline,
            (&mut publication as *mut Publication).cast(),
            publish,
        )
    };
    (result, publication.handle)
}

fn read_file(
    context: &mut Context<'_, '_, '_, '_, '_>,
    node: u64,
    handle: u64,
    offset: i64,
    size: u32,
    target: &mut [u8],
) -> (c_int, u64) {
    let mut length = 99;
    let deadline = deadline(context);
    // SAFETY: This fixture supplies a live unique target and disjoint length output.
    let result = unsafe {
        (FALLBACK_OPERATIONS_V2.read)(
            raw(context),
            node,
            handle,
            offset,
            size,
            deadline,
            target.as_mut_ptr(),
            target.len() as u64,
            &mut length,
        )
    };
    (result, length)
}

#[test]
fn fallback_exact_open_read_eof_forget_release_and_stale_handle() {
    let (summary, calls) = with_context(ReaderMode::Complete, |context| {
        let node = lookup(context);
        let (result, handle) = open_file(context, node, false);
        assert_eq!(result, 0);
        assert_ne!(handle, 0);
        // The open pin survives the kernel's last lookup reference.
        assert_eq!(
            unsafe { (FALLBACK_OPERATIONS_V2.metadata.forget)(raw(context), node, 1) },
            0
        );
        let mut target = [0xa5; 8];
        assert_eq!(read_file(context, node, handle, 0, 8, &mut target), (0, 1));
        assert_eq!(target[0], b'X');
        assert_eq!(read_file(context, node, handle, 1, 8, &mut target), (0, 0));
        assert_eq!(
            read_file(context, node + 1, handle, 0, 8, &mut target),
            (libc::ESTALE, 0)
        );
        assert_eq!(
            read_file(context, node, handle + 1, 0, 8, &mut target),
            (libc::ESTALE, 0)
        );
        let deadline = deadline(context);
        assert_eq!(
            unsafe {
                (FALLBACK_OPERATIONS_V2.release)(
                    raw(context),
                    node,
                    handle,
                    libc::O_RDONLY,
                    0,
                    0,
                    deadline,
                )
            },
            0
        );
        assert_eq!(
            read_file(context, node, handle, 0, 8, &mut target),
            (libc::ESTALE, 0)
        );
    });
    assert_eq!(calls, 1);
    assert_eq!(summary.file_handles, 0);
}

#[test]
fn fallback_digest_size_and_failed_prefix_never_copy_a_reply() {
    for mode in [
        ReaderMode::BadDigest,
        ReaderMode::BadSize,
        ReaderMode::PrefixFailure,
    ] {
        let (_, calls) = with_context(mode, |context| {
            let node = lookup(context);
            let (result, handle) = open_file(context, node, false);
            assert_eq!(result, 0);
            let mut target = [0xa5; 8];
            assert_eq!(
                read_file(context, node, handle, 0, 8, &mut target),
                (libc::EIO, 0)
            );
            assert_eq!(target, [0xa5; 8]);
        });
        assert_eq!(calls, 1);
    }
}

#[test]
fn fallback_offset_buffer_budget_and_retry_deadline_are_bounded() {
    let (_, calls) = with_context(ReaderMode::Complete, |context| {
        let node = lookup(context);
        let (result, handle) = open_file(context, node, false);
        assert_eq!(result, 0);
        let mut target = [0xa5; 8];
        assert_eq!(
            read_file(context, node, handle, -1, 8, &mut target),
            (libc::EINVAL, 0)
        );
        assert_eq!(
            read_file(context, node, handle, 0, 4097, &mut target),
            (libc::ENOMEM, 0)
        );
        assert_eq!(target, [0xa5; 8]);
    });
    assert_eq!(calls, 0);
    let (_, calls) = with_context(ReaderMode::RetryPastBound, |context| {
        let node = lookup(context);
        let (_, handle) = open_file(context, node, false);
        let mut target = [0xa5; 8];
        assert_eq!(
            read_file(context, node, handle, 0, 8, &mut target),
            (libc::ETIMEDOUT, 0)
        );
        assert_eq!(target, [0xa5; 8]);
    });
    assert_eq!(calls, 1);
}

#[test]
fn fallback_ambiguous_open_retains_pending_pin_until_teardown() {
    let (summary, calls) = with_context(ReaderMode::Complete, |context| {
        let node = lookup(context);
        assert_eq!(open_file(context, node, true).0, FATAL);
        assert!(context.failed());
        assert!(context.connection.is_faulted());
    });
    assert_eq!(calls, 0);
    assert_eq!(summary.pending_file_handles, 1);
}

#[test]
fn fallback_foreign_session_handle_and_handle_budget_are_closed() {
    let mut foreign = 0;
    let (summary, calls) = with_context(ReaderMode::Complete, |context| {
        let node = lookup(context);
        for _ in 0..16 {
            let (result, handle) = open_file(context, node, false);
            assert_eq!(result, 0);
            foreign = handle;
        }
        assert_eq!(open_file(context, node, false).0, libc::EMFILE);
    });
    assert_eq!(summary.file_handles, 16);
    assert_eq!(calls, 0);

    let (_, calls) = with_context(ReaderMode::Complete, |context| {
        let node = lookup(context);
        let (result, local) = open_file(context, node, false);
        assert_eq!(result, 0);
        assert_ne!(local, foreign);
        let mut target = [0xa5; 8];
        assert_eq!(
            read_file(context, node, foreign, 0, 8, &mut target),
            (libc::ESTALE, 0)
        );
        assert_eq!(target, [0xa5; 8]);
    });
    assert_eq!(calls, 0);
}

#[test]
fn fallback_sparse_byte_holes_are_zero_without_advertising_seek_hole() {
    let (_, calls) = with_profile_context(ReaderMode::Complete, true, |context| {
        let node = lookup(context);
        let (result, handle) = open_file(context, node, false);
        assert_eq!(result, 0);
        let mut target = [0xa5; 8];
        assert_eq!(read_file(context, node, handle, 0, 8, &mut target), (0, 6));
        assert_eq!(&target[..6], &[0, 0, b'X', 0, 0, 0]);
        assert_eq!(read_file(context, node, handle, 6, 8, &mut target), (0, 0));
        assert_eq!(read_file(context, node, handle, 3, 2, &mut target), (0, 2));
        assert_eq!(&target[..2], &[0, 0]);
    });
    assert_eq!(calls, 1);
}

#[test]
fn fallback_cancellation_after_provider_work_never_copies_private_bytes() {
    let (_, calls) = with_context(ReaderMode::CancelDuringRead, |context| {
        let node = lookup(context);
        let (result, handle) = open_file(context, node, false);
        assert_eq!(result, 0);
        let mut target = [0xa5; 8];
        assert_eq!(
            read_file(context, node, handle, 0, 8, &mut target),
            (libc::EINTR, 0)
        );
        assert_eq!(target, [0xa5; 8]);
    });
    assert_eq!(calls, 1);
}

#[test]
fn fallback_renamed_protected_journal_after_read_never_copies_private_bytes() {
    let (_, calls) = with_context(ReaderMode::RenameJournalDuringRead, |context| {
        let node = lookup(context);
        let (result, handle) = open_file(context, node, false);
        assert_eq!(result, 0);
        let mut target = [0xa5; 8];
        assert_eq!(
            read_file(context, node, handle, 0, 8, &mut target),
            (FATAL, 0)
        );
        assert_eq!(target, [0xa5; 8]);
        assert!(context.failed());
    });
    assert_eq!(calls, 1);
}

#[test]
fn fallback_expired_original_transport_deadline_never_reanchors() {
    let (summary, calls) = with_context(ReaderMode::Complete, |context| {
        let node = lookup(context);
        let mut publication = Publication {
            handle: 0,
            fail: false,
        };
        let now = Control::new(context.cancellation, 2).unwrap().now_ns();
        assert_eq!(
            unsafe {
                (FALLBACK_OPERATIONS_V2.open)(
                    raw(context),
                    node,
                    libc::O_RDONLY,
                    now,
                    (&mut publication as *mut Publication).cast(),
                    publish,
                )
            },
            FATAL
        );
        assert_eq!(publication.handle, 0);
    });
    assert_eq!(calls, 0);
    assert_eq!(summary.file_handles, 0);
}
