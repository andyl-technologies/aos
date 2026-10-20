//! Counts the closed host constructors and their independent Hello phase.
//!
//! These are host owners, not native publication rows. Fixed body/layout
//! counters run before any cloned installation, parsed registration, Hello
//! object, socket wrapper or controller is constructed. Existing caller roots
//! and the previously admitted known supervisor remain separate observations.

use std::{
    mem::{align_of, size_of},
    rc::Rc,
};

use crucible_node_format::{ContentRef, Id};

use super::{OriginalPacketHostStartup, PacketNativeHostStartupInputs, hello, refused};
use crate::{
    ProviderError,
    handshake::{ExtensionHandshake, Handshake, HelloRequest, HelloResult},
    retained_metadata::{
        MetadataObserver, RetainedProtocolMetadataFacts,
        requested_storage::{
            requested_metadata_backing_storage_data, shared_header_storage_data, tree_storage_data,
        },
        serialization_storage::{
            original_json_value_storage_extent_counter_scratch_data,
            original_json_value_storage_extent_data,
        },
    },
};

/// Reports the requested SDK constructor and Hello allocations without rights.
///
/// The original Source action must conjoin this row with its actual retained
/// holder, Source, guarded process and previously admitted known supervisor.
/// This row ends at an unused controller. Codec installation, Discover,
/// Realize, Admit, report queries and subsequent control operations need their
/// own prospective terms before the controller may leave its retained holder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketNativeHostStartupStorageData {
    retained: usize,
    transient: usize,
    scratch: usize,
    pub(super) content_bytes: usize,
    pub(super) content_objects: usize,
    pub(super) maximum_chunk: usize,
    pub(super) maximum_requests: usize,
}

impl PacketNativeHostStartupStorageData {
    /// Counts all newly retained SDK constructor owners.
    pub fn retained_requested_bytes(&self) -> usize {
        self.retained
    }

    /// Bounds the entire simultaneous constructor or Hello work phase.
    pub fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }

    /// Counts explicit counter, result and borrowed-view headers.
    pub fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }

    /// Sums the independent owning and maximum-phase components as data.
    ///
    /// # Errors
    /// Refuses checked arithmetic overflow.
    pub fn requested_peak_data(&self) -> Result<usize, ProviderError> {
        sum(&[self.retained, self.transient, self.scratch])
    }
}

/// Counts the fixed SDK counter bank before any prospective owner walk.
///
/// Compiler frames, recursive observer stack and allocator physical overhead
/// are separate. No serialization or metadata observer runs in this getter.
pub fn original_packet_host_startup_counter_scratch_data() -> usize {
    4 * size_of::<MetadataObserver<'static>>()
        + 4 * size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<PacketNativeHostStartupStorageData>()
        + size_of::<[usize; 18]>()
        + size_of::<hello::Verifier<'static>>()
        + size_of::<hello::ResponseGuard<'static>>()
        + original_json_value_storage_extent_counter_scratch_data()
        + crate::reference_packet::service::native_startup::data_equality::counter_scratch_data()
        + crate::reference_packet::service::complete_restore::transfer::selected_issuer_decode_counter_scratch_data()
        + crate::reference_packet::service::ack_emitter::original_prepare_executable_measurement_counter_scratch_data()
}

/// Counts one original host SDK birth without constructing its typed owners.
///
/// Counts the actual borrowed content roster and executable reference, the
/// actual registration's raw occurrences, source-selected literal bank and
/// closed Hello grammar. No verifier callback, DOM, encoder, file access or
/// allocator request runs here. The caller credits the fixed counter getter
/// before entering this method. The result supplies no allocation permission.
///
/// # Errors
/// Refuses missing or excessive original data, unsupported nonempty extension
/// registries, unbounded selection or checked requested-storage overflow.
pub fn original_packet_host_startup_storage_data(
    inputs: &PacketNativeHostStartupInputs<'_>,
    hello_id: &Id,
) -> Result<PacketNativeHostStartupStorageData, ProviderError> {
    let launch = inputs.launch;
    if inputs.registration.is_empty()
        || inputs.registration.len() > 16 * 1024
        || inputs.content.is_empty()
        || inputs.content.len() > 8192
        || hello_id.as_str().is_empty()
        || hello_id.as_str().len() > 128
        || launch.selection.realization.bindings.len() != 1
        || launch.selection.realization.descriptors.len() != 1
        || launch.selection.realization.owner_bindings.len() != 1
        || launch.admission_token.as_slice().len() != 32
        || inputs.executable.hash.algorithm != "blake3-256"
        || inputs.executable.hash.domain != "cnp.blob.v1"
        || inputs.executable.media_type != "application/octet-stream"
        || inputs.executable.hash.digest.len() != 64
        || !inputs
            .executable
            .hash
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || inputs.executable.length.get() == 0
        || inputs.executable.length.get() > 256 * 1024 * 1024
    {
        return Err(refused());
    }
    let frame_bytes =
        usize::try_from(launch.storage.frame_bank_bytes.get()).map_err(|_| refused())?;
    let frames =
        usize::try_from(launch.storage.frames_per_direction.get()).map_err(|_| refused())?;
    let maximum_requests =
        usize::try_from(launch.limits.journal_entries.get()).map_err(|_| refused())?;
    let maximum_chunk =
        usize::try_from(launch.limits.blob_chunk_bytes.get()).map_err(|_| refused())?;
    if !(4..=512 * 1024 * 1024).contains(&frame_bytes)
        || !(1..=4096).contains(&frames)
        || !(1..=4096).contains(&maximum_requests)
        || !(1..=4096).contains(&maximum_chunk)
    {
        return Err(refused());
    }

    let registration = crate::reference_packet::service::complete_restore::transfer::selected_issuer_decode_storage_data(
        inputs.registration, size_of::<hello::Registration>(), 16 * 1024,
    )?;
    let mut observer = MetadataObserver::new();
    observer.observe(&launch.selection)?;
    let selection = requested_metadata_backing_storage_data(&observer.finish())?;
    let mut observer = MetadataObserver::new();
    observer.observe(inputs.executable)?;
    let executable = requested_metadata_backing_storage_data(&observer.finish())?;
    let mut observer = MetadataObserver::new();
    observer.observe(&launch.initial_coordinator)?;
    let coordinator = requested_metadata_backing_storage_data(&observer.finish())?;

    let mut content_bytes = 0;
    let mut observer = MetadataObserver::new();
    observer.tree::<String, (ContentRef, Rc<Vec<u8>>)>(inputs.content.len())?;
    for (reference, bytes) in inputs.content {
        if reference.length.get() != u64::try_from(bytes.len()).map_err(|_| refused())? {
            return Err(refused());
        }
        content_bytes = add(content_bytes, bytes.len())?;
        observer.observe(reference)?;
        observer.observe(&reference.hash.digest)?;
        observer.vector::<u8>(bytes.len())?;
    }
    if content_bytes == 0 || content_bytes > 512 * 1024 * 1024 {
        return Err(refused());
    }
    let content = sum(&[
        requested_metadata_backing_storage_data(&observer.finish())?,
        mul(inputs.content.len(), size_of::<Vec<u8>>())?,
        shared_header_storage_data(inputs.content.len(), align_of::<Vec<u8>>())?,
    ])?;
    let protocol_bank = sum(&[
        frame_bytes,
        mul(
            mul(frames, 2)?,
            crate::transport::original_frames::original_frame_slot_layout(),
        )?,
    ])?;
    let hello_bank = sum(&[
        mul(add(hello::MAXIMUM_HELLO_BYTES, 4)?, 2)?,
        mul(
            2,
            crate::transport::original_frames::original_frame_slot_layout(),
        )?,
    ])?;

    // Each row names a distinct constructor owner, including independent
    // authority and correlation copies. A full decoded registration bound
    // conservatively dominates that row's actual feature/ID/map subset.
    let registration_owners = [
        registration, // Original decoded registration.
        registration, // Handshake supported feature roster.
        registration, // Handshake required feature roster and key map.
        registration, // Original Hello request and its typed children.
        registration, // Journal's independent original request.
        registration, // Handshake selected features and current connection.
        registration, // ClientSession's independent authority children.
        registration, // Connection's independent authority children.
        registration, // CorrelationGuard session/incarnation and key set.
    ];
    let retained = sum(&[
        size_of::<OriginalPacketHostStartup>(),
        selection,
        selection,
        coordinator,
        executable,
        content,
        protocol_bank,
        hello_bank,
        hello::MAXIMUM_HELLO_BYTES,
        sum(&registration_owners)?,
        // The route, retained peer reference and one issued Hello ID own
        // independent bounded strings outside their copied rosters.
        executable,
        2 * 128,
        hello_id.allocated_capacity(),
        // The handshake, Session authority and Connection authority expose
        // three independently counted views of the same epoch/gate backing.
        mul(
            3,
            Handshake::original_initial_host_allocation_layout_data()?,
        )?,
        // The one original Hello ID also lives in Handshake's replay set.
        tree_storage_data(1, 1, size_of::<Id>(), align_of::<Id>())?,
        hello_id.allocated_capacity(),
        // Root, Session and stream share the same deadline. Conservative data
        // walks retain each verified edge; the temporary reader adds no owner.
        mul(
            3,
            crate::client::ExchangeDeadline::original_host_startup_allocation_layout_data()?,
        )?,
        ExtensionHandshake::original_empty_registry_allocation_layout_data()?,
        // Connection and Controller each create their own protocol owner.
        mul(
            2,
            add(
                size_of::<crate::protocol_snapshot::ProtocolCaptureOwner>(),
                shared_header_storage_data(
                    1,
                    align_of::<crate::protocol_snapshot::ProtocolCaptureOwner>(),
                )?,
            )?,
        )?,
        // Hello's literal bank has its own Rc allocation. All inline Option
        // headers, including Session/Connection/Controller, are in the root.
        crate::transport::original_frames::original_frame_bank_layout(),
        shared_header_storage_data(
            1,
            align_of::<
                std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>,
            >(),
        )?,
        // The Session retains a second verified edge to the journal's same
        // Hello bank. The conservative observer counts both original views.
        hello_bank,
        crate::transport::original_frames::original_frame_bank_layout(),
        shared_header_storage_data(
            1,
            align_of::<
                std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>,
            >(),
        )?,
        // Original request and journal request_value are independently owned
        // Value trees. Their actual successful encoded bodies fit this ceiling.
        mul(
            2,
            original_json_value_storage_extent_data(hello::MAXIMUM_HELLO_BYTES)?
                .value_dom_requested_bytes,
        )?,
        // One concrete ZST schema is retained through two independently
        // observed Rc edges. No caller-defined callback backing is accepted.
        shared_header_storage_data(2, align_of::<hello::InitialHelloSchema>())?,
        // Empty custody/correlation maps retain their compiled container
        // observation allowance, independently of initialized content entries.
        tree_storage_data(
            6,
            0,
            size_of::<Id>() + size_of::<crate::envelope::Envelope>(),
            align_of::<Id>(),
        )?,
    ])?;

    let raw = original_json_value_storage_extent_data(hello::MAXIMUM_HELLO_BYTES)?;
    let raw_pass = raw.canonical_pass_requested_bytes()?;
    // Raw framing/DOM is charged before the closed guard. Afterwards all
    // independently decoded provider children equal the actual selected
    // declaration, and dynamic nonce banks have an exact 32-byte grammar.
    // Sum the concrete simultaneously live raw Value, decoded Envelope,
    // ResponseShape, and canonical decode/copy phase conservatively.
    let hello_phase = sum(&[
        raw_pass,
        raw_pass,
        raw_pass,
        raw_pass,
        selection,
        registration,
        registration,
        registration,
        size_of::<HelloRequest>(),
        size_of::<HelloResult>(),
        4 * 33,
        4 * 44,
        size_of::<crate::bodies::ResponseBody>(),
        size_of::<crate::bodies::RequestBody>(),
        // HelloRequest::validate constructs a temporary protocol-version set;
        // admission constructs a temporary set of actual offered features.
        tree_storage_data(
            2,
            original_json_value_storage_extent_data(inputs.registration.len())?.maximum_value_nodes,
            size_of::<Id>().max(size_of::<String>()),
            align_of::<Id>(),
        )?,
        raw.maximum_canonical_encoded_bytes,
        closed_failure_storage_data(hello::MAXIMUM_HELLO_BYTES)?,
    ])?;
    let preparation_phase = sum(&[
        registration,
        selection,
        coordinator,
        closed_failure_storage_data(16 * 1024)?,
        // Actual pending content clone is retained in the root; hash and
        // installation locals are distinct fixed construction scratch.
        size_of::<blake3::Hasher>(),
        size_of::<ContentRef>(),
    ])?;
    let transient = hello_phase.max(preparation_phase).max(
        crate::reference_packet::service::ack_emitter::original_prepare_executable_measurement_counter_scratch_data());
    let result = PacketNativeHostStartupStorageData {
        retained,
        transient,
        scratch: original_packet_host_startup_counter_scratch_data(),
        content_bytes,
        content_objects: inputs.content.len(),
        maximum_chunk,
        maximum_requests,
    };
    result.requested_peak_data()?;
    Ok(result)
}

impl OriginalPacketHostStartup {
    pub(super) fn reconcile_prepared_data(&self) -> Result<(), ProviderError> {
        let requested = self.retained_requested_storage_data(None)?;
        if requested > self.quote.retained {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn reconcile_connected_data(
        &self,
        supervisor: &crate::connection::OriginalRetainedSupervisor,
    ) -> Result<(), ProviderError> {
        let requested = self.retained_requested_storage_data(Some(supervisor))?;
        if requested > self.quote.retained {
            return Err(refused());
        }
        Ok(())
    }

    /// Observes the same concrete initial SDK owners without renewing them.
    ///
    /// The installed caller separately checks its Source/private birth/guard
    /// association. This includes both verified Hello-bank views and counts
    /// actual spare capacities. The already admitted same supervisor backing
    /// is checked by identity and observed by the enclosing installed holder.
    ///
    /// # Errors
    /// Refuses a foreign creator, partial failure, missing concrete supervisor
    /// for a connected owner, changed initial phase or bounded walk overflow.
    pub fn retained_requested_storage_data(
        &self,
        supervisor: Option<&crate::connection::OriginalRetainedSupervisor>,
    ) -> Result<usize, ProviderError> {
        let Self {
            creator,
            quote: _,
            registration,
            selection,
            coordinator,
            profile,
            executable,
            schemas,
            deadline,
            plain_handshake,
            handshake,
            hello,
            hello_journal,
            pending_content,
            content,
            custody,
            frames,
            route,
            stream: _,
            hello_attempt,
            session,
            controller,
            failure,
            preparing: _,
            prepared: _,
            connecting: _,
            connected: _,
            initial_attachment_attempted,
        } = self;
        creator.ensure_current()?;
        if failure.is_some() {
            return Err(refused());
        }
        let mut total = size_of::<Self>();
        let mut observer = MetadataObserver::new();
        if let Some(registration) = registration {
            registration.observe(&mut observer)?;
        }
        if let Some(selection) = selection {
            observer.observe(selection)?;
        }
        if let Some(coordinator) = coordinator {
            observer.observe(coordinator)?;
        }
        if let Some(profile) = profile {
            observer.observe(profile)?;
        }
        if let Some(executable) = executable {
            observer.observe(executable)?;
        }
        if let Some(schemas) = schemas {
            observer.shared_value(schemas.as_ref())?;
        }
        if let Some(deadline) = deadline {
            deadline.observe_owned11_metadata(&mut observer)?;
        }
        if let Some(hello) = hello {
            observer.observe(hello)?;
        }
        if let Some((reference, bytes)) = pending_content {
            observer.observe(reference)?;
            observer.observe(bytes)?;
        }
        if let Some(content) = content {
            content.observe_owned_metadata(&mut observer)?;
        }
        if let Some(custody) = custody {
            custody.observe_owned_metadata(&mut observer)?;
        }
        if let Some(frames) = frames {
            frames.observe_owned11_metadata(&mut observer)?;
        }
        if let Some(route) = route {
            observer.observe(&route.node)?;
            observer.observe(&route.execution_owner)?;
        }
        if let Some(attempt) = hello_attempt {
            attempt.observe_completed_metadata(&mut observer)?;
        }
        if let Some(session) = session {
            session.observe_original_host_startup_metadata(
                schemas.as_ref().ok_or_else(refused)?,
                supervisor.ok_or_else(refused)?,
                &mut observer,
            )?;
        }
        if let Some(controller) = controller {
            if *initial_attachment_attempted {
                total = add(
                    total,
                    requested_metadata_backing_storage_data(
                        &controller.original_live_host_metadata_facts_with_retained_supervisor(
                            supervisor.ok_or_else(refused)?,
                            None,
                        )?,
                    )?,
                )?;
            } else {
                controller.observe_original_host_startup_metadata(
                    schemas.as_ref().ok_or_else(refused)?,
                    supervisor.ok_or_else(refused)?,
                    &mut observer,
                )?;
            }
        }
        total = add(
            total,
            requested_metadata_backing_storage_data(&observer.finish())?,
        )?;
        if let Some(plain) = plain_handshake {
            total = add(
                total,
                requested_metadata_backing_storage_data(&plain.retained_metadata_facts_data()?)?,
            )?;
        }
        if let Some(handshake) = handshake {
            let registry = handshake.retain_original_registry_metadata_owner()?;
            total = add(
                total,
                requested_metadata_backing_storage_data(
                    &handshake.retained_metadata_facts_data(&registry)?,
                )?,
            )?;
        }
        if let Some(hello) = hello_journal {
            total = add(
                total,
                requested_metadata_backing_storage_data(
                    &hello.original_retained_metadata_facts()?,
                )?,
            )?;
        }
        creator.ensure_current()?;
        Ok(total)
    }
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(refused)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(refused)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0, |total, value| add(total, *value))
}

// The selected raw guard precedes typed Hello decode; Registration has nine
// closed fields and its nested portable types have fixed expected-field lists.
// A displayed rejected input string can escape each source byte to at most six
// ASCII bytes. 512 covers the fixed error vocabulary, expected-field names and
// two full usize line/column spellings on this closed path. The actual pinned
// serde_json ErrorImpl contains ErrorCode plus two usize fields; its only
// owning variants are Box<str> and io::Error. The tuple below dominates that
// enum payload/tag/alignment without exposing a private serde layout.
fn closed_failure_storage_data(maximum_raw: usize) -> Result<usize, ProviderError> {
    let message = add(mul(maximum_raw, 6)?, 512)?;
    sum(&[
        // Geometric String growth and into_boxed_str's old/new banks are
        // conservatively summed, rather than using only the final error text.
        mul(message, 4)?,
        size_of::<(String, std::io::Error, usize, usize, usize)>(),
        size_of::<(std::io::ErrorKind, Box<dyn std::error::Error + Send + Sync>)>(),
        size_of::<ProviderError>(),
        size_of::<crucible_node_format::ContractError>(),
    ])
}
