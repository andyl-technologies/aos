//! Retains only the three typed restoration stages consumed by historical MAC checks.

use super::*;
use crate::bodies::ObserveRequest;
use crate::envelope::Envelope;
use crate::protocol_snapshot::restored_settled17::current_stages::{
    CurrentActivation17, CurrentFirstObservation17,
};
use crate::reference_packet::service::complete_restore::{activation::*, restoration_observe::*};
use crucible_node_format::ActivationManifest;
use serde_json::Value;

current_component17!(
    CurrentActivation17,
    CurrentActivation17LineageReadAttempt,
    [
        schema, creator, thread, phase, original, incoming_slot, artifact,
        context, coordinator, manifest, terminal, verified, dispatched, published
    ],
    {
        0 => creator: Plain17<u32>,
        1 => phase: Inline17<PacketRestorationActivationPhase>,
        2 => original: Plain17<Option<Envelope>>,
        3 => incoming_slot: Plain17<Option<usize>>,
        4 => artifact: Optional17<CurrentDto17<PacketRestorationActivationArtifact>>,
        5 => context: Optional17<CurrentDto17<PacketRestorationActivationContext>>,
        6 => coordinator: Plain17<Option<Value>>,
        7 => manifest: Optional17<CurrentDto17<ActivationManifest>>,
        8 => terminal: Plain17<Option<Envelope>>,
        9 => verified: Plain17<bool>,
        10 => dispatched: Plain17<bool>,
        11 => published: Plain17<bool>
    },
    roles {
        schema: "source-private.native-restoration-activation-history/1",
        thread: "same-original-thread-history-only"
    },
    positive [creator]
);

current_component17!(
    CurrentFirstObservation17,
    CurrentFirstObservation17LineageReadAttempt,
    [
        schema, creator, thread, original, body, artifact, context,
        terminal, received, verified, dispatched, published
    ],
    {
        0 => creator: Plain17<u32>,
        1 => original: Plain17<Option<Envelope>>,
        2 => body: Optional17<CurrentDto17<ObserveRequest>>,
        3 => artifact: Optional17<CurrentDto17<PacketRestorationObservationArtifact>>,
        4 => context: Optional17<CurrentDto17<PacketRestorationObservationContext>>,
        5 => terminal: Plain17<Option<Envelope>>,
        6 => received: Plain17<bool>,
        7 => verified: Plain17<bool>,
        8 => dispatched: Plain17<bool>,
        9 => published: Plain17<bool>
    },
    roles {
        schema: "source-private.native-restoration-observation-history/1",
        thread: "same-original-thread-history-only"
    },
    positive [creator]
);
