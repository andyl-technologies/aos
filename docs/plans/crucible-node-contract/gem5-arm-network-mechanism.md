# Closed native Ethernet lifecycle

This separate source-selected functional model owns every actual original TX
frame and a strictly ordered future receive reaction. It has no host socket,
TAP, network worker, external packet input or file-backed boot disk. Its boot
disk uses the frozen native-owned 1 MiB zero-disk callbacks and retains all
read/write/flush commands, replies and first original ACK positions.

Before callbacks the model binds a retained private TX-birth Event and enables
the source-owned publication stop. Native TX invokes that handler synchronously
inside the actual publishing callback; the handler retains immutable frame bytes
and schedules a strong managed PyEvent at a sealed future tick. That reaction
stages the exact original bytes into native RX one tick later. Actual DMA can
wait for a guest receive buffer; its genuine completion tick/ordinal is observed
separately from its original earliest delivery time. Default-disabled device
stops remain inert. The private Event pointer never crosses the public process
protocol; stock drained checkpoint serialization refuses the bound handler.

The closed loopback ledger retains 64 originals of at most 4096 bytes. Native
TX/RX retain sixteen frames per direction. Before each bounded native callback
batch the model reserves sixteen potential TX originals and the existing disk
and publication credits. Native TX/RX births stop only after their whole actual
callback. The fixed reaction delay is 10000 ps and the earliest native delivery
is one ps later; these functional delays do not certify physical network or bus
latency. Original TX ACK and RX retirement are distinct; neither deletes the
model's original frame, reaction, completion or first administration position.

Each of the disk and network diagnostic domains has a 65536-byte reservation.
Their sum plus the original 4034560-byte bounded native projection remains
below the unchanged 4194304-byte object ceiling. Raw frame/disk bytes, Python
objects and callback payloads remain inside the opaque image rather than being
misrepresented as complete typed visitors. Callback/tick, UART, object and total
diagnostic limits remain 16000000/1e12, 32768, 4 MiB and 256 MiB.

The fixed source-built Linux PID1 sets PACKET_IGNORE_OUTGOING on its bound raw
packet socket. The private predecessor reached INIT_READY, held the exact
64-byte EtherType 0x88b5 TX before its future RX reaction, and verified actual
native RX bytes and the guest incoming readback marker. After the complete
source image/resource/temporary namespace disappeared, two concurrent fresh
owners each recaptured and audited the unchanged cut before retry, original
ACK and continuation. Chronological receipts, UART births/bytes, incoming
results and original TX/RX administration agreed; all groups were reclaimed.
The installed predecessor binds 42 measured roles and 168 configuration files.
Its actual native enabled/disabled boundary witnesses also passed. These are
fixed closed-loopback mechanism results, not ordinary node admission.

The canonical recipes use repository-relative helpers and the distinct causal
auditor alias. The changed source paths have a new native/package identity and
require their own matching installed/Linux proof before registration; private
predecessor evidence cannot qualify that identity. The model-only successor
validates a bounded candidate administration ledger before calling native ACK,
then installs it only after native acceptance. Rejected native TX, RX, disk
request and completion administrations cannot mark the actual backend accepted.
An exception after any earlier native effects remains transport uncertainty;
no failed operation is presented as NoEffects or an accepted original ACK.

Formal combined multi-endpoint publication bounds across one Atomic callback
remain required before broad Compute/device admission. The fixed closed
workload and its finite original histories are the measured scope; no unseen
body may be dropped or a cumulative limit silently widened. Raw managed
Python/native state remains owned by the process image while typed diagnostics
stay partial. Common Ready/NativeArchive/external Serial, broad device parity
and CPU timing remain unqualified. Root/SE and prior block artifacts are
unchanged.
