//! Holds complete-source byte owners beside the same actual native endpoint.
//!
//! The owning constructor preserves original Hello and precharges protocol
//! snapshots before the first control frame. It does not issue a native capture;
//! the original ticket, unchanged full cut and complete prefix settlement remain
//! independent prerequisites.

use super::super::service::{PacketNative5CaptureProfile, PacketNative5StorageLimits};
use super::*;
use crate::{
    native_hello::OriginalNativeHelloJournal, protocol_snapshot::ProtocolSnapshotReservation,
};

pub(super) struct CompleteEndpointState {
    pub(super) creator: u32,
    pub(super) thread: std::thread::ThreadId,
    pub(super) storage: PacketNative5StorageLimits,
    pub(super) profile: Option<PacketNative5CaptureProfile>,
    pub(super) hello: OriginalNativeHelloJournal,
    pub(super) before: Option<ProtocolSnapshotReservation>,
    pub(super) after: Option<ProtocolSnapshotReservation>,
    poisoned: bool,
    unwind_payload: Option<Box<dyn std::any::Any + Send>>,
}

impl CompleteEndpointState {
    pub(super) fn ensure_origin(&self) -> Result<(), ProviderError> {
        if self.creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native5 endpoint foreign creator",
            ));
        }
        if self.thread != std::thread::current().id() {
            return Err(ProviderError::Correlation(
                "native5 endpoint foreign thread",
            ));
        }
        Ok(())
    }

    fn preflight_birth(&self, authority: &ConnectionAuthority) -> Result<(), ProviderError> {
        self.ensure_origin()?;
        self.storage.validate(&authority.limits())?;
        let maximum_hello = usize::try_from(self.storage.hello_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("native5 Hello allocation credit"))?;
        if self.hello.allocated_bytes() > maximum_hello {
            return Err(ProviderError::ResourceExhausted(
                "native5 actual Hello allocation",
            ));
        }
        let hello_view_credit = maximum_hello
            .checked_mul(4)
            .and_then(|bytes| bytes.checked_add(8192))
            .ok_or(ProviderError::ResourceExhausted(
                "native5 Hello codec extent",
            ))?;
        serialized_credit(&self.hello.protocol_view(), hello_view_credit)?;
        let before = self.before.as_ref().ok_or(ProviderError::Correlation(
            "native5 initial snapshot slot absent",
        ))?;
        let after = self.after.as_ref().ok_or(ProviderError::Correlation(
            "native5 initial settlement slot absent",
        ))?;
        let profile = self.profile.as_ref().ok_or(ProviderError::Correlation(
            "native5 original endpoint profile absent",
        ))?;
        let before_facts = before.original_allocation_facts()?;
        let after_facts = after.original_allocation_facts()?;
        if before_facts.maximum_encoded_bytes as u64
            != profile.native_before_bytes(&self.storage).get()
            || after_facts.maximum_encoded_bytes as u64
                != profile.native_after_bytes(&self.storage).get()
        {
            return Err(ProviderError::Correlation(
                "native5 original snapshot bank differs from born profile",
            ));
        }
        before
            .allocated_bytes()
            .checked_add(after.allocated_bytes())
            .ok_or(ProviderError::ResourceExhausted(
                "native5 actual snapshot capacity overflow",
            ))?;
        authority.ensure_live()
    }
}

/// Retains every original complete-source owner after constructor refusal.
///
/// The original Hello and both independently prepared snapshot banks remain
/// beside the same connection and native actor. Legacy endpoint refusal owns
/// no complete-state resources and keeps its existing recovery interface.
#[must_use = "retain the complete original owner until authenticated reclamation"]
pub struct PacketCompleteEndpointRefusal<S: ProviderStream> {
    original: PacketCompleteEndpointRecovery<S>,
    error: ProviderError,
}

impl<S: ProviderStream> PacketCompleteEndpointRefusal<S> {
    /// Borrows the retained local refusal without releasing its native owner.
    pub fn error(&self) -> &ProviderError {
        &self.error
    }

    /// Transfers the same original owner and all original prepared banks together.
    pub fn into_original(self) -> PacketCompleteEndpointRecovery<S> {
        self.original
    }

    /// Fences the same original connection while retaining every original object.
    ///
    /// # Errors
    /// Refuses a copied creator process or thread before transport callbacks.
    pub fn contain_original(&mut self) -> Result<(), ProviderError> {
        self.original.state.ensure_origin()?;
        self.original.connection.close();
        Ok(())
    }
}

/// Owns the indivisible original resources needed for a complete endpoint retry.
///
/// Recovery cannot replace its Hello, native actor, connection, installed source
/// policy or supervisor. A supplied storage candidate still requires exact
/// equality with the immutable native birth tuple before any allocation.
#[must_use = "recover or supervise the entire original complete-source owner"]
pub struct PacketCompleteEndpointRecovery<S: ProviderStream> {
    connection: Connection<S>,
    native: PacketControl,
    policy: Rc<dyn PacketEndpointPolicy>,
    supervisor: Rc<dyn BlobSupervisor>,
    state: CompleteEndpointState,
}

impl<S: ProviderStream> PacketCompleteEndpointRecovery<S> {
    /// Borrows the same original literal Hello for independent inert inspection.
    pub fn hello(&self) -> &OriginalNativeHelloJournal {
        &self.state.hello
    }

    /// Returns retained snapshot-bank allocations without releasing either bank.
    pub fn snapshot_allocations(&self) -> (Option<usize>, Option<usize>) {
        (
            self.state
                .before
                .as_ref()
                .map(ProtocolSnapshotReservation::allocated_bytes),
            self.state
                .after
                .as_ref()
                .map(ProtocolSnapshotReservation::allocated_bytes),
        )
    }

    /// Retries the same original endpoint without replacing owners or prepared banks.
    ///
    /// # Errors
    /// Returns this complete owner on changed origin, storage, negotiated limits,
    /// source policy, actual Hello credit or unavailable original allocation.
    pub fn retry(
        self,
        storage: PacketNative5StorageLimits,
    ) -> Result<PacketEndpoint<S>, Box<PacketCompleteEndpointRefusal<S>>> {
        PacketEndpoint::complete_from_original(self, storage)
    }
}

impl<S: ProviderStream> PacketEndpoint<S> {
    /// Takes complete native source owners on the same unused archived connection.
    ///
    /// Actual selected allocations precede control input. Every refusal retains
    /// the same Hello, connection, native actor and all banks already prepared.
    /// The enclosing source factory separately charges whole-world geometry.
    ///
    /// # Errors
    /// Returns complete original custody on foreign origin, changed immutable
    /// storage/limits, invalid credit, unavailable allocation or failed source
    /// authentication. No failure releases a completed Hello or prepared bank.
    pub fn new_complete(
        connection: Connection<S>,
        native: PacketControl,
        policy: Rc<dyn PacketEndpointPolicy>,
        supervisor: Rc<dyn BlobSupervisor>,
        storage: PacketNative5StorageLimits,
        hello: OriginalNativeHelloJournal,
    ) -> Result<Self, Box<PacketCompleteEndpointRefusal<S>>> {
        let original = PacketCompleteEndpointRecovery {
            connection,
            native,
            policy,
            supervisor,
            state: CompleteEndpointState {
                creator: std::process::id(),
                thread: std::thread::current().id(),
                storage: storage.clone(),
                profile: None,
                hello,
                before: None,
                after: None,
                poisoned: false,
                unwind_payload: None,
            },
        };
        Self::complete_from_original(original, storage)
    }

    fn complete_from_original(
        mut original: PacketCompleteEndpointRecovery<S>,
        storage: PacketNative5StorageLimits,
    ) -> Result<Self, Box<PacketCompleteEndpointRefusal<S>>> {
        // Every callback sees borrowed originals inside one unwind boundary.
        // The recovery capsule itself remains owned by this outer frame.
        let preparation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            original.state.ensure_origin()?;
            if original.state.poisoned {
                return Err(ProviderError::Correlation(
                    "native5 original constructor unwound",
                ));
            }
            let authority = original.connection.provider_authority()?.clone();
            storage.validate(&authority.limits())?;
            original
                .native
                .authenticate_complete_storage(&storage, authority.limits())?;
            let actual_profile = original
                .connection
                .original_native5_capture_profile()?
                .clone();
            original
                .native
                .authenticate_complete_capture_profile(&actual_profile)?;
            if original
                .state
                .profile
                .as_ref()
                .is_some_and(|profile| profile != &actual_profile)
            {
                return Err(ProviderError::Correlation(
                    "native5 original endpoint profile changed",
                ));
            }
            let actual_confirmation = original.connection
                .original_native5_confirmation_selection()?;
            original.native.authenticate_complete_confirmation_selection(actual_confirmation)?;
            original.state.profile = Some(actual_profile);

            let history = usize::try_from(storage.frame_bank_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("native5 original history bytes"))?;
            let frames = usize::try_from(storage.frames_per_direction.get())
                .map_err(|_| ProviderError::ResourceExhausted("native5 original history slots"))?;
            let frame_bytes = usize::try_from(authority.limits().frame_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("native5 negotiated frame bytes"))?;
            let descriptors = frames
                .checked_mul(2)
                .ok_or(ProviderError::ResourceExhausted(
                    "native5 original descriptor population",
                ))?;
            let facts = original.connection.original_native5_storage_facts()?;
            if facts.maximum_frame_bytes != frame_bytes
                || facts.maximum_history_bytes != history
                || facts.maximum_frames_per_direction != frames
                || facts.byte_capacity != history
                || facts.descriptor_capacity != descriptors
                || !facts.all_io_complete
            {
                return Err(ProviderError::Correlation(
                    "native5 original bank differs from selected birth storage",
                ));
            }

            // A wrong compatible candidate never changes selected storage or
            // creates a replacement bank. Already prepared original banks stay.
            original.state.storage = storage;
            let profile = original
                .state
                .profile
                .as_ref()
                .ok_or(ProviderError::Correlation(
                    "native5 original endpoint profile absent",
                ))?;
            let before_maximum =
                usize::try_from(profile.native_before_bytes(&original.state.storage).get())
                    .map_err(|_| {
                        ProviderError::ResourceExhausted("native5 before snapshot bytes")
                    })?;
            let after_maximum =
                usize::try_from(profile.native_after_bytes(&original.state.storage).get())
                    .map_err(|_| {
                        ProviderError::ResourceExhausted("native5 after snapshot bytes")
                    })?;
            let history = usize::try_from(original.state.storage.frame_bank_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("native5 frozen history bytes"))?;
            let frames = usize::try_from(original.state.storage.frames_per_direction.get())
                .map_err(|_| ProviderError::ResourceExhausted("native5 frozen history slots"))?;
            if original.state.before.is_none() {
                original.state.before = Some(reserve_original_protocol_bank(
                    profile,
                    before_maximum,
                    history,
                    frames,
                )?);
            }
            if original.state.after.is_none() {
                original.state.after = Some(reserve_original_protocol_bank(
                    profile,
                    after_maximum,
                    history,
                    frames,
                )?);
            }
            original.state.preflight_birth(&authority)?;

            original
                .policy
                .authenticate_source(&authority, original.native.endpoint_scope()?)?;
            let chunk = usize::try_from(authority.limits().blob_chunk_bytes.get())
                .map_err(|_| ProviderError::ResourceExhausted("packet chunk allowance"))?
                .min(4096);
            let uploads = BlobReceiver::new(
                authority.session_id().clone(),
                authority.incarnation_id().clone(),
                BlobLimits {
                    reserved_bytes: STORED_CONTENT,
                    content_bytes: CONTENT,
                    chunk_bytes: chunk,
                    transfers_per_origin: 256,
                    tombstones_per_origin: 256,
                    chunks_per_transfer: 256,
                    operation_pins: EXCHANGES,
                },
                original.supervisor.clone(),
            )?;
            let authority = authority.clone();
            original.connection.bind_native5_blob_receiver(&uploads)?;
            Ok::<_, ProviderError>((authority, uploads))
        }));
        let (authority, uploads) = match preparation {
            Ok(Ok(prepared)) => prepared,
            Ok(Err(error)) => {
                return Err(Box::new(PacketCompleteEndpointRefusal { original, error }));
            }
            Err(payload) => {
                original.state.poisoned = true;
                // An arbitrary panic payload can run code when dropped. Retain
                // it beside original custody until authenticated reclamation.
                original.state.unwind_payload = Some(payload);
                return Err(Box::new(PacketCompleteEndpointRefusal {
                    original,
                    error: ProviderError::Correlation("native5 original constructor unwound"),
                }));
            }
        };
        let PacketCompleteEndpointRecovery {
            connection,
            native,
            policy,
            supervisor: _,
            state,
        } = original;
        Ok(Self {
            transport: Some(Transport::Connected(connection)),
            native,
            authority,
            policy,
            uploads,
            pins: Vec::new(),
            records: Vec::new(),
            next_sequence: 2,
            transport_credit: 0,
            held: false,
            complete: Some(state),
            capture: None,
            pending_capture: None,
            after_confirmation: None,
            canonical_ack_boot: None,
            canonical_ack_admission: None,
        })
    }
}

fn reserve_original_protocol_bank(
    profile: &PacketNative5CaptureProfile,
    maximum: usize,
    history: usize,
    frames: usize,
) -> Result<ProtocolSnapshotReservation, ProviderError> {
    match profile {
        PacketNative5CaptureProfile::OriginalArrays6 => {
            ProtocolSnapshotReservation::reserve_complete(maximum, history, frames)
        }
        PacketNative5CaptureProfile::CompactBytes7 { .. } => {
            ProtocolSnapshotReservation::reserve_complete_compact(maximum, history, frames)
        }
    }
}

