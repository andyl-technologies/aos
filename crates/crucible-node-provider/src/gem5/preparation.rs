//! Retains original native Ready bytes and their actual owning control session.
//!
//! The preparation token names the original validated session transcript. Its
//! public spelling grants no readiness authority: common mapping additionally
//! requires the original live child, private control session, current independent
//! capture/certificate and installed exact-profile qualification. Restored birth
//! remains distinct even when its modeled event boundary happens to be zero.

use super::*;
use crucible_node_contract::{HashRef, canonical};

/// Retains native preparation provenance without a public minting constructor.
pub struct Gem5PreparedSession {
    origin: PreparationOrigin,
    pid: u32,
    start_ticks: String,
    launch_scope: HashRef,
    ready: Ready,
    packet: ContentRef,
    bytes: Vec<u8>,
    transcript: ContentRef,
    transcript_bytes: Vec<u8>,
    token: Id,
}

/// Retains received preparation bytes before fallible native authentication.
///
/// A packet variant records transport data only. The private owning process
/// transitions it to a session only after actual native identity checks; this
/// enum cannot construct a live process or grant execution authority.
pub enum Gem5PreparationCustody {
    /// Preserves the fact that no complete native Ready packet has arrived.
    AwaitingReady,
    /// Preserves the unchanged received packet while validation is incomplete.
    Received(Vec<u8>),
    /// Preserves the original authenticated session and its complete raw packet.
    Validated(Box<Gem5PreparedSession>),
}

impl Gem5PreparationCustody {
    pub(super) fn authenticate(
        &mut self,
        child: &Child,
        launch: &Gem5Launch,
        ready: Ready,
        origin: PreparationOrigin,
    ) -> Result<(), ProviderError> {
        let Self::Received(bytes) = self else {
            return Err(ProviderError::Correlation(
                "gem5 preparation has no original received Ready packet",
            ));
        };
        // Borrow the retained bytes through every fallible check. Failure leaves
        // the original packet in the already reserved native custody capsule.
        let session = Gem5PreparedSession::retain(child, launch, ready, bytes, origin)?;
        *self = Self::Validated(Box::new(session));
        Ok(())
    }

    fn session(&self) -> Option<&Gem5PreparedSession> {
        match self {
            Self::Validated(session) => Some(session),
            Self::AwaitingReady | Self::Received(_) => None,
        }
    }
}

/// Is installed only by the actual spawn or actual native image-restore path.
pub(super) enum PreparationOrigin {
    Original,
    Restored { source_capture: Id },
}

impl Gem5PreparedSession {
    /// Retains a packet only after its real child/session and Ready fields match.
    ///
    /// This private constructor is called while the actual Child still belongs
    /// to its mandatory pre-reserved custody. It never qualifies native execution.
    pub(super) fn retain(
        child: &Child,
        launch: &Gem5Launch,
        ready: Ready,
        bytes: &[u8],
        origin: PreparationOrigin,
    ) -> Result<Self, ProviderError> {
        let value = canonical::parse_json(bytes, GEM5_NATIVE_FRAME_BYTES)?;
        let packet_ready: Ready = serde_json::from_value(value)
            .map_err(|_| ProviderError::Frame("retained gem5 Ready packet shape"))?;
        if packet_ready.kind != ready.kind
            || packet_ready.schema != ready.schema
            || packet_ready.owner != ready.owner
            || packet_ready.incarnation != ready.incarnation
            || packet_ready.generation != ready.generation
            || packet_ready.continuation != ready.continuation
            || packet_ready.boundary != ready.boundary
            || ready.kind != "ready"
            || ready.schema != GEM5_NATIVE_PROTOCOL
            || ready.owner != launch.owner
            || ready.incarnation != launch.incarnation
            || ready.generation != launch.generation
        {
            return Err(ProviderError::Correlation(
                "retained native preparation differs from its actual Ready packet",
            ));
        }
        let continuation = match &origin {
            PreparationOrigin::Original => "original",
            PreparationOrigin::Restored { .. } => "restored",
        };
        if ready.continuation != continuation {
            return Err(ProviderError::Correlation(
                "native preparation birth differs from the owning construction path",
            ));
        }
        containment::capture_identity(child)?;
        let pid = child.id();
        let start_ticks = closure::kernel_start_ticks(pid)?;
        let launch_scope = closure::source_scope(launch)?;
        let packet = canonical::content_ref(bytes, "application/json")?;
        let source_capture = match &origin {
            PreparationOrigin::Original => None,
            PreparationOrigin::Restored { source_capture } => Some(source_capture),
        };
        let transcript_bytes = canonical::canonical_json(&json!({
            "format":"crucible.gem5.native-preparation-session", "version":1,
            "origin":continuation, "source_capture":source_capture,
            "pid":pid, "start_ticks":start_ticks, "launch_scope":launch_scope,
            "controller":launch.owner_script.content, "model":launch.model_script.content,
            "owner":launch.owner, "incarnation":launch.incarnation,
            "generation":launch.generation, "ready_packet":packet,
        }))?;
        let transcript = canonical::content_ref(&transcript_bytes, "application/json")?;
        let token = Id::new(format!("gem5/prepared/{}", transcript.hash.digest))?;
        let mut retained = Vec::new();
        retained.try_reserve_exact(bytes.len()).map_err(|_| {
            ProviderError::Frame("gem5 original preparation packet credit exhausted")
        })?;
        retained.extend_from_slice(bytes);

        Ok(Self {
            origin,
            pid,
            start_ticks,
            launch_scope,
            ready,
            packet,
            bytes: retained,
            transcript,
            transcript_bytes,
            token,
        })
    }

    /// Returns the original transcript's portable identity, which grants no authority.
    pub fn token(&self) -> &Id {
        &self.token
    }

    /// Returns the unchanged original wire packet after bounded transport validation.
    pub fn packet(&self) -> (&ContentRef, &[u8]) {
        (&self.packet, &self.bytes)
    }

    /// Returns the actual original kernel/control-session scope and its dependency.
    pub fn transcript(&self) -> (&ContentRef, &[u8]) {
        (&self.transcript, &self.transcript_bytes)
    }

    fn authenticate_initial(
        &self,
        native: &Gem5NativeProcess,
        authority: &exact::Gem5ExactAuthority,
    ) -> Result<(), ProviderError> {
        self.packet.verify(&self.bytes)?;
        self.transcript.verify(&self.transcript_bytes)?;
        if !matches!(self.origin, PreparationOrigin::Original)
            || native.source_image.is_some()
            || native.child_pid() != Some(self.pid)
            || closure::kernel_start_ticks(self.pid)? != self.start_ticks
            || closure::source_scope(&native.launch)? != self.launch_scope
            || native.stream.is_none()
            || native.listener.is_none()
            || native.quarantine.is_some()
            || !native.completed.is_empty()
            || native.pending.is_some()
            || native.last_acknowledged.is_some()
            || native.unresolved.is_some()
            || native.unresolved_capture.is_some()
            || self.ready.boundary.tick.get() != 0
            || self.ready.boundary.ordinal.get() != 0
            || native.logical_position()
                != Position::new(U64::new(0), U64::new(0), Phase::BoundaryControl)
        {
            return Err(ProviderError::Correlation(
                "native initial preparation lacks original untouched session custody",
            ));
        }
        native.next_publication_bound(authority)?;
        Ok(())
    }
}

impl Gem5NativeProcess {
    /// Authenticates original native birth under this peer's sealed live exact authority.
    ///
    /// Administrative capture and independent current qualification may precede
    /// this check. Restored birth, native grants/output/ACK history and changed
    /// owner/control custody always refuse, including at an event-zero boundary.
    ///
    /// # Errors
    /// Refuses missing original Ready bytes, a reconstructed or used owner,
    /// changed live kernel/control scope or a foreign/stale exact authority.
    pub fn initial_prepared_session(
        &self,
        authority: &exact::Gem5ExactAuthority,
    ) -> Result<&Gem5PreparedSession, ProviderError> {
        let original = self
            .preparation
            .session()
            .ok_or(ProviderError::Correlation(
                "original native preparation transcript is absent",
            ))?;
        original.authenticate_initial(self, authority)?;
        Ok(original)
    }
}
