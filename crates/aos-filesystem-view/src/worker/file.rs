//! Read-only regular-file open lifecycle for one metadata connection.
//!
//! A pending open pins its connection-scoped inode before a transport resolves
//! immutable content or constructs a reply. The only content authority exposed
//! here is the authenticated byte layout from the structural index; this module
//! owns no OS descriptor, backing registration, cache entry, or fetch authority.
//!
//! Synchronous transports should keep the reservation pending while publishing
//! its raw handle, then call `commit_open_after_reply` after confirmed success or
//! `abort_open` after confirmed failure. An indeterminate publication result is
//! terminal for the connection and must be reported through
//! `fault_pending_open_reply_ambiguity`. A transport that activates before its
//! reply uses `fault_active_open_reply_ambiguity` for the same terminal case.

use std::mem::size_of;

use crate::{
    IndexContentView, IndexNodeBodyView, InodeError, OpenHandleId, OpenReservation, ValidatedIndex,
};

use super::{
    ConnectionBrandId, MetadataConnection, RequestBudget, RequestCheckpoint, RequestControl,
    WorkerAttributes, WorkerError, check, map_index, map_inode, require_output,
};

const OPEN_REPLY_BYTES: u64 = size_of::<OpenFileReply<'static>>() as u64;

/// Identifies the byte-access mode requested by a transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileAccessMode {
    /// Requests immutable byte reads only.
    ReadOnly,
    /// Requests writes without reads.
    WriteOnly,
    /// Requests both reads and writes.
    ReadWrite,
}

/// Describes transport-normalized regular-file open intent.
///
/// A transport must reject or conservatively classify flags it cannot map to
/// these semantics. Construction does not authorize an open; the worker accepts
/// only [`Self::read_only`] or an exactly equivalent value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileOpenRequest {
    access_mode: FileAccessMode,
    create: bool,
    truncate: bool,
    append: bool,
}

impl FileOpenRequest {
    /// Creates an open request from transport-normalized semantics.
    #[must_use]
    pub const fn new(
        access_mode: FileAccessMode,
        create: bool,
        truncate: bool,
        append: bool,
    ) -> Self {
        Self {
            access_mode,
            create,
            truncate,
            append,
        }
    }

    /// Creates the only open intent accepted by an immutable worker.
    #[must_use]
    pub const fn read_only() -> Self {
        Self::new(FileAccessMode::ReadOnly, false, false, false)
    }

    /// Returns the requested byte-access mode.
    #[must_use]
    pub const fn access_mode(self) -> FileAccessMode {
        self.access_mode
    }

    /// Reports whether the request asks to create a directory entry.
    #[must_use]
    pub const fn creates(self) -> bool {
        self.create
    }

    /// Reports whether the request asks to truncate existing content.
    #[must_use]
    pub const fn truncates(self) -> bool {
        self.truncate
    }

    /// Reports whether the request asks for append semantics.
    #[must_use]
    pub const fn appends(self) -> bool {
        self.append
    }

    const fn is_exactly_read_only(self) -> bool {
        matches!(self.access_mode, FileAccessMode::ReadOnly)
            && !self.create
            && !self.truncate
            && !self.append
    }
}

/// Borrows one file's exact authenticated immutable byte layout.
///
/// This value can identify whole-file or sparse content objects. It grants no
/// authority to discover whether an object is resident, obtain a backing file,
/// fetch bytes, publish content, or access metadata other than logical size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileContentAuthority<'index> {
    content: IndexContentView<'index>,
}

impl<'index> FileContentAuthority<'index> {
    /// Returns the authenticated whole-file or sparse content layout.
    #[must_use]
    pub const fn content(self) -> IndexContentView<'index> {
        self.content
    }

    /// Returns the exact logical size, including sparse holes.
    #[must_use]
    pub const fn logical_size(self) -> u64 {
        match self.content {
            IndexContentView::Whole { content } => content.encoded_size(),
            IndexContentView::Sparse(sparse) => sparse.logical_size(),
        }
    }
}

/// Holds a regular-file open reservation while its reply remains unpublished.
///
/// The raw handle is untrusted protocol identity, not standalone authority. A
/// private instance brand binds the token to the exact worker that created it,
/// independently of the caller-provided inode-table key. A caller must commit,
/// abort, or fault the connection before dropping this token.
#[must_use = "publish, abort, or fault the connection for the pending OPEN reply"]
pub struct PendingFileReply<'index> {
    reservation: OpenReservation,
    connection_brand: ConnectionBrandId,
    node_id: u64,
    attributes: WorkerAttributes,
    content: FileContentAuthority<'index>,
}

impl<'index> PendingFileReply<'index> {
    /// Returns the raw connection-scoped handle for a prospective reply.
    #[must_use]
    pub const fn raw_handle(&self) -> u64 {
        self.reservation.raw_protocol_handle()
    }

    /// Returns the exact connection-scoped inode being opened.
    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Returns the exact projected metadata authorized for the OPEN reply.
    #[must_use]
    pub const fn attributes(&self) -> WorkerAttributes {
        self.attributes
    }

    /// Returns the authenticated immutable byte authority for backing resolution.
    #[must_use]
    pub const fn content(&self) -> FileContentAuthority<'index> {
        self.content
    }
}

/// Identifies one active read-only regular-file open.
///
/// Both the typed handle and a private process-local identity bind this token to
/// its originating worker. This value owns no OS descriptor and carries only
/// immutable byte-content authority.
#[must_use = "state-changing OPEN replies require handling; reconstructed inspection replies may be dropped"]
pub struct OpenFileReply<'index> {
    handle: OpenHandleId,
    connection_brand: ConnectionBrandId,
    node_id: u64,
    attributes: WorkerAttributes,
    content: FileContentAuthority<'index>,
}

impl std::fmt::Debug for OpenFileReply<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenFileReply")
            .field("handle", &self.handle)
            .field("node_id", &self.node_id)
            .field("attributes", &self.attributes)
            .field("content", &self.content)
            .finish()
    }
}

impl PartialEq for OpenFileReply<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
            && self.connection_brand == other.connection_brand
            && self.node_id == other.node_id
            && self.attributes == other.attributes
            && self.content == other.content
    }
}

impl Eq for OpenFileReply<'_> {}

impl<'index> OpenFileReply<'index> {
    /// Returns the raw handle that was or will be published to the transport.
    #[must_use]
    pub const fn raw_handle(&self) -> u64 {
        self.handle.get()
    }

    /// Returns the exact connection-scoped inode associated with the handle.
    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.node_id
    }

    /// Returns the exact projected metadata published for this open.
    #[must_use]
    pub const fn attributes(&self) -> WorkerAttributes {
        self.attributes
    }

    /// Returns the authenticated immutable byte authority for this open.
    #[must_use]
    pub const fn content(&self) -> FileContentAuthority<'index> {
        self.content
    }
}

impl<'prepared, 'index, 'bytes, 'plan> MetadataConnection<'prepared, 'index, 'bytes, 'plan> {
    /// Prepares and pins an exact read-only regular-file open.
    ///
    /// All fallible validation and content decoding precedes the reservation.
    /// The returned token remains pending and unavailable to subsequent handle
    /// resolution until explicitly activated.
    ///
    /// # Errors
    ///
    /// Returns a read-only-filesystem error for any write, create, truncate, or
    /// append intent. Also returns closed initialization, stale-node, wrong-kind,
    /// budget, cancellation, deadline, index-integrity, or handle-admission errors.
    pub fn prepare_open(
        &mut self,
        node_id: u64,
        request: FileOpenRequest,
        budget: RequestBudget,
        control: &impl RequestControl,
    ) -> Result<PendingFileReply<'index>, WorkerError> {
        self.ready_budget(budget)?;
        self.authorize_request(control)?;
        if !request.is_exactly_read_only() {
            return Err(WorkerError::ReadOnlyFilesystem);
        }
        require_output(budget, OPEN_REPLY_BYTES)?;
        check(control, RequestCheckpoint::BeforeWork)?;

        let ordinal = self.projected_ordinal(node_id)?;
        let projected = self
            .projection
            .node(ordinal)
            .ok_or(WorkerError::IntegrityFailure)?;
        if !matches!(
            projected.kind(),
            crate::ProjectedNodeKind::Source {
                kind: crate::IndexNodeKind::File,
                ..
            }
        ) {
            return Err(WorkerError::NotFile);
        }
        let record = self.projected_record(projected)?;
        let attributes = self
            .projected_attribute_template(projected)?
            .with_node(node_id);
        let index: &'index ValidatedIndex<'bytes> = self.index();
        let semantics = index.record_semantics(&record).map_err(map_index)?;
        let IndexNodeBodyView::File(file) = semantics.body() else {
            return Err(WorkerError::IntegrityFailure);
        };
        let content = FileContentAuthority {
            content: file.content(),
        };

        check(control, RequestCheckpoint::AfterReadOnlyWork)?;
        check(control, RequestCheckpoint::BeforeCommit)?;
        let reservation = self.inodes.reserve_open(node_id).map_err(map_inode)?;

        Ok(PendingFileReply {
            reservation,
            connection_brand: self.connection_brand,
            node_id,
            attributes,
            content,
        })
    }

    /// Activates a prepared open immediately before transport publication.
    ///
    /// A transport that can determine publication failure exactly may activate,
    /// attempt publication, and invoke [`Self::rollback_open`] on definite
    /// failure. Synchronous transports should normally retain the pending state
    /// through publication and use [`Self::commit_open_after_reply`] instead.
    ///
    /// # Errors
    ///
    /// Returns a terminal-fault, initialization, foreign, stale, consumed, or
    /// integrity error.
    pub fn publish_open(
        &mut self,
        pending: &mut PendingFileReply<'index>,
    ) -> Result<OpenFileReply<'index>, WorkerError> {
        self.ready()?;
        self.activate_open(pending)
    }

    /// Activates a prepared open after confirmed synchronous reply publication.
    ///
    /// This transition has no cancellation checkpoint because the peer already
    /// owns the raw handle. Any activation error after confirmed publication
    /// faults the connection and preserves its fail-closed inode pin for teardown.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::IntegrityFailure`] and permanently faults the
    /// connection if activation cannot exactly commit the published handle.
    pub fn commit_open_after_reply(
        &mut self,
        pending: &mut PendingFileReply<'index>,
    ) -> Result<OpenFileReply<'index>, WorkerError> {
        if self.ready().is_err() {
            self.faulted = true;
            return Err(WorkerError::IntegrityFailure);
        }

        match self.activate_open(pending) {
            Ok(reply) => Ok(reply),
            Err(_) => {
                self.faulted = true;
                Err(WorkerError::IntegrityFailure)
            }
        }
    }

    /// Aborts a pending open after confirmed reply failure.
    ///
    /// # Errors
    ///
    /// Returns a terminal-fault, initialization, foreign, stale, consumed, or
    /// integrity error.
    pub fn abort_open(
        &mut self,
        pending: &mut PendingFileReply<'index>,
    ) -> Result<(), WorkerError> {
        self.ready()?;
        self.validate_pending_open(pending)?;
        self.inodes
            .abort_open(&mut pending.reservation)
            .map_err(map_inode)
    }

    /// Rolls back an activated open after definite pre-publication failure.
    ///
    /// This operation is unsafe after a reply may have become visible. An
    /// ambiguous result must fault the connection instead so the inode pin is
    /// retained until teardown.
    ///
    /// # Errors
    ///
    /// Returns a terminal-fault, initialization, stale, foreign, or integrity
    /// error.
    pub fn rollback_open(&mut self, reply: OpenFileReply<'index>) -> Result<(), WorkerError> {
        self.ready()?;
        self.validate_active_open(&reply)?;
        self.inodes.release_open(reply.handle).map_err(map_inode)
    }

    /// Faults the connection after indeterminate publication of its pending reply.
    ///
    /// The token is borrowed and validated before the transition. On success,
    /// the reservation is deliberately not aborted and its inode pin remains
    /// charged until [`Self::teardown`] because the peer may possess the raw
    /// handle. Validation failure leaves both the token and receiver unchanged.
    ///
    /// # Errors
    ///
    /// Returns a terminal-fault, initialization, foreign-token, stale-state,
    /// node, content, or index-integrity error without consuming `pending`.
    pub fn fault_pending_open_reply_ambiguity(
        &mut self,
        pending: &PendingFileReply<'index>,
    ) -> Result<(), WorkerError> {
        self.ready()?;
        self.validate_pending_open(pending)?;
        self.faulted = true;
        Ok(())
    }

    /// Faults the connection after indeterminate publication of its active reply.
    ///
    /// The reply is borrowed and validated before the transition. On success,
    /// the handle is deliberately not rolled back and its inode pin remains
    /// charged until [`Self::teardown`] because the peer may possess the raw
    /// handle. Validation failure leaves both the reply and receiver unchanged.
    ///
    /// # Errors
    ///
    /// Returns a terminal-fault, initialization, foreign-handle, stale-state,
    /// node, content, or index-integrity error without changing `reply`.
    pub fn fault_active_open_reply_ambiguity(
        &mut self,
        reply: &OpenFileReply<'index>,
    ) -> Result<(), WorkerError> {
        self.ready()?;
        self.validate_active_open(reply)?;
        self.faulted = true;
        Ok(())
    }

    /// Resolves an active raw handle and exact request inode to byte authority.
    ///
    /// This performs no cache lookup, backing registration, fetch, or read. It
    /// reauthenticates the inode and structural record before returning the same
    /// immutable content layout admitted during open preparation.
    ///
    /// # Errors
    ///
    /// Returns a closed initialization, stale or pending handle, wrong handle
    /// kind, mismatched inode, cancellation, deadline, index, or integrity error.
    pub fn resolve_open_for_node(
        &self,
        node_id: u64,
        raw_handle: u64,
        control: &impl RequestControl,
    ) -> Result<OpenFileReply<'index>, WorkerError> {
        self.ready()?;
        self.authorize_request(control)?;
        check(control, RequestCheckpoint::BeforeWork)?;

        let handle = self
            .inodes
            .resolve_active_handle(raw_handle)
            .map_err(map_inode)?;
        let attributes = self.inodes.active_open(handle).map_err(map_inode)?;
        if attributes.node_id != node_id {
            return Err(WorkerError::Stale);
        }
        let content = self.content_for_node(node_id)?;

        check(control, RequestCheckpoint::AfterReadOnlyWork)?;
        Ok(OpenFileReply {
            handle,
            connection_brand: self.connection_brand,
            node_id,
            attributes: self
                .projected_attribute_template(
                    self.projection
                        .node(self.projected_ordinal(node_id)?)
                        .ok_or(WorkerError::IntegrityFailure)?,
                )?
                .with_node(node_id),
            content,
        })
    }

    /// Resolves an active open solely for identity-checked release cleanup.
    ///
    /// Lease expiry does not block cleanup of authority created while the lease
    /// was live. This method performs no content read or new access admission.
    ///
    /// # Errors
    ///
    /// Returns a closed initialization, stale or pending handle, wrong handle
    /// kind, mismatched inode, index, or integrity error.
    pub fn resolve_open_for_release(
        &self,
        node_id: u64,
        raw_handle: u64,
    ) -> Result<OpenFileReply<'index>, WorkerError> {
        self.ready()?;
        let handle = self
            .inodes
            .resolve_active_handle(raw_handle)
            .map_err(map_inode)?;
        let attributes = self.inodes.active_open(handle).map_err(map_inode)?;
        if attributes.node_id != node_id {
            return Err(WorkerError::Stale);
        }
        let content = self.content_for_node(node_id)?;
        Ok(OpenFileReply {
            handle,
            connection_brand: self.connection_brand,
            node_id,
            attributes: self
                .projected_attribute_template(
                    self.projection
                        .node(self.projected_ordinal(node_id)?)
                        .ok_or(WorkerError::IntegrityFailure)?,
                )?
                .with_node(node_id),
            content,
        })
    }

    /// Releases one active file handle after validating its request inode.
    ///
    /// # Errors
    ///
    /// Returns a closed initialization, stale or pending handle, wrong handle
    /// kind, mismatched inode, cancellation, deadline, or integrity error.
    /// Errors before the final transition preserve the active handle.
    pub fn release_open_for_node(
        &mut self,
        node_id: u64,
        raw_handle: u64,
        control: &impl RequestControl,
    ) -> Result<(), WorkerError> {
        self.ready()?;
        check(control, RequestCheckpoint::BeforeWork)?;

        let handle = self
            .inodes
            .resolve_active_handle(raw_handle)
            .map_err(map_inode)?;
        let attributes = self.inodes.active_open(handle).map_err(map_inode)?;
        if attributes.node_id != node_id {
            return Err(WorkerError::Stale);
        }

        check(control, RequestCheckpoint::AfterReadOnlyWork)?;
        check(control, RequestCheckpoint::BeforeCommit)?;
        self.inodes.release_open(handle).map_err(map_inode)
    }

    /// Releases an identity-checked active handle during transport cleanup.
    ///
    /// This path intentionally does not consult lease time, cancellation, or a
    /// request deadline. Those controls gate new authority and byte access; they
    /// must never strand an already-published handle or backing registration.
    ///
    /// # Errors
    ///
    /// Returns a closed initialization, stale handle, wrong handle kind,
    /// mismatched inode, or integrity error without releasing another handle.
    pub fn release_open_for_cleanup(
        &mut self,
        node_id: u64,
        raw_handle: u64,
    ) -> Result<(), WorkerError> {
        self.ready()?;
        let handle = self
            .inodes
            .resolve_active_handle(raw_handle)
            .map_err(map_inode)?;
        let attributes = self.inodes.active_open(handle).map_err(map_inode)?;
        if attributes.node_id != node_id {
            return Err(WorkerError::Stale);
        }
        self.inodes.release_open(handle).map_err(map_inode)
    }

    fn activate_open(
        &mut self,
        pending: &mut PendingFileReply<'index>,
    ) -> Result<OpenFileReply<'index>, WorkerError> {
        self.validate_pending_open(pending)?;
        let handle = self
            .inodes
            .activate_open(&mut pending.reservation)
            .map_err(map_inode)?;
        Ok(OpenFileReply {
            handle,
            connection_brand: pending.connection_brand,
            node_id: pending.node_id(),
            attributes: pending.attributes,
            content: pending.content,
        })
    }

    fn validate_pending_open(&self, pending: &PendingFileReply<'index>) -> Result<(), WorkerError> {
        if pending.connection_brand != self.connection_brand {
            return Err(WorkerError::Stale);
        }
        match self.inodes.resolve_active_handle(pending.raw_handle()) {
            Err(InodeError::OpenStillPending) => {}
            Err(error) => return Err(map_inode(error)),
            Ok(_) => return Err(WorkerError::Stale),
        }

        let content = self.content_for_node(pending.node_id)?;
        let attributes = self
            .projected_attribute_template(
                self.projection
                    .node(self.projected_ordinal(pending.node_id)?)
                    .ok_or(WorkerError::IntegrityFailure)?,
            )?
            .with_node(pending.node_id);
        if content != pending.content || attributes != pending.attributes {
            return Err(WorkerError::IntegrityFailure);
        }
        Ok(())
    }

    fn validate_active_open(&self, reply: &OpenFileReply<'index>) -> Result<(), WorkerError> {
        if reply.connection_brand != self.connection_brand {
            return Err(WorkerError::Stale);
        }
        let attributes = self.inodes.active_open(reply.handle).map_err(map_inode)?;
        if attributes.node_id != reply.node_id {
            return Err(WorkerError::Stale);
        }

        let content = self.content_for_node(reply.node_id)?;
        let projected_attributes = self
            .projected_attribute_template(
                self.projection
                    .node(self.projected_ordinal(reply.node_id)?)
                    .ok_or(WorkerError::IntegrityFailure)?,
            )?
            .with_node(reply.node_id);
        if content != reply.content || projected_attributes != reply.attributes {
            return Err(WorkerError::IntegrityFailure);
        }
        Ok(())
    }

    fn content_for_node(&self, node_id: u64) -> Result<FileContentAuthority<'index>, WorkerError> {
        let ordinal = self.projected_ordinal(node_id)?;
        let projected = self
            .projection
            .node(ordinal)
            .ok_or(WorkerError::IntegrityFailure)?;
        if !matches!(
            projected.kind(),
            crate::ProjectedNodeKind::Source {
                kind: crate::IndexNodeKind::File,
                ..
            }
        ) {
            return Err(WorkerError::NotFile);
        }
        let record = self.projected_record(projected)?;
        let index: &'index ValidatedIndex<'bytes> = self.index();
        let semantics = index.record_semantics(&record).map_err(map_index)?;
        let IndexNodeBodyView::File(file) = semantics.body() else {
            return Err(WorkerError::IntegrityFailure);
        };

        Ok(FileContentAuthority {
            content: file.content(),
        })
    }
}
