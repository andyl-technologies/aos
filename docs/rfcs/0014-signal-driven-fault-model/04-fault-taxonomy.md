# 04 — Cross-domain fault and degradation taxonomy

This taxonomy fixes vocabulary and adapter boundaries. It is intentionally
broader than the executable scope. `Core` identifies foundational effects,
`Next` identifies the complete practical device-model tier, and `Advanced`
identifies research- or technology-specific semantics. Model tier communicates
complexity, not implementation status: all three tiers ship for the network,
storage, and node domains. A row in a specification-only domain does not reserve
an enum variant or make a value legal in scenario TOML.

A row may name a **cause** (heat, movement, rain, vibration), a **hardware state**
(read-only, disconnected, throttled), or an **operation effect** (drop, delay,
corrupt). Causes are usually signals; states and effects are binding outputs.
Keeping them distinct lets one cause drive several correlated outcomes.

The single implementation PR has this exact support boundary:

| Domain | Executable in the implementation PR | Specification-only |
| --- | --- | --- |
| Network, including wired, logical, radio, mobile, shared-medium, satellite, and contact links | Every row in §§4.2–4.4 | None |
| Storage, block, flash, and 9p/filesystem-facing devices | Every row in §4.6 | None |
| Node lifecycle, CPU, interrupt, memory, clock, and accelerator | Every row in §4.5 | None |
| Sensors, IoT buses/peripherals/actuators, power-device state, and dedicated thermal/cooling devices | None; vocabulary and future adapter contract only | Every row in §§4.7–4.9 |
| Laptop/mobile/edge compositions | Supported only when every constituent effect resolves to the network, storage, or node adapter above | Any composition requiring a specification-only adapter |

Environmental, movement, power, thermal, vibration, radiation, and load values
may still be implemented as generic signal sources and drive supported effects.
For example, a voltage trace may drive a node reset and a temperature trace may
drive CPU throttling; that does not imply a separately modeled PDU, battery,
sensor, or fan device.

- **[TAX-1]** Every shipped effect kind MUST document target, opportunity phase,
  lifetime class, parameters and units, composition algebra, capability ID,
  observability record, checkpoint state, and locked-replay evidence.
- **[TAX-2]** New technology-specific faults SHOULD reuse a generic effect when
  observable semantics are identical and SHOULD retain technology detail as
  typed cause/telemetry metadata.
- **[TAX-3]** A fault that changes modeled physical truth MUST be distinct from a
  fault that changes only guest-observed measurements.
- **[TAX-4]** Only effects inside the executable boundary above MAY appear in
  schema enums, codecs, builders, capability manifests, or runtime dispatch.
  Specification-only effects MUST be rejected as unknown rather than accepted
  as unsupported.

## 4.1 Generic operation effects

These effect families are reusable across adapters, but each adapter exposes a
typed schema rather than accepting one universal untyped operation.

| Family | Effect | Semantics | Model tier |
| --- | --- | --- | --- |
| Availability | unavailable | Reject or suppress operations while active. | Core |
| Availability | intermittent/flap | Alternate availability from a signal/state machine. | Core |
| Availability | directional availability | Permit only one operation direction or mode. | Core |
| Admission | reject | Return an immediate typed rejection. | Core |
| Admission | drop | Admit no completion/delivery. | Core |
| Timing | fixed latency | Add exact virtual duration. | Core |
| Timing | signal-driven latency | Map a signal to exact added duration. | Core |
| Timing | jitter | Add keyed nonnegative variation. | Core |
| Timing | stall/hang | Withhold progress until recovery or timeout. | Next |
| Capacity | rate cap | Restrict bits, bytes, operations, samples, or work per virtual second. | Core |
| Capacity | burst/token cap | Restrict sustained and burst service. | Next |
| Capacity | shared service | Allocate capacity among consumers. | Next |
| Outcome | typed failure | Return adapter-specific error/status/exception. | Core |
| Outcome | timeout | Produce no result before modeled timeout. | Core |
| Ordering | reorder | Delay selected operations past siblings. | Core |
| Multiplicity | duplicate | Emit an additional result with stable order. | Core |
| Payload | bit flip | Flip keyed bit positions. | Core |
| Payload | field mutation | Change a typed field or deterministic byte selector. | Next |
| Payload | truncation | Remove a bounded suffix or shorten a result. | Core |
| Payload | stale substitution | Return a prior version/sample. | Next |
| Payload | stuck value | Force selected bits/fields/value while active. | Next |
| Lifecycle | reset/restart | Transition a component through reset and recovery. | Core |
| Lifecycle | permanent failure | Remain failed until explicit repair. | Core |
| Lifecycle | degraded mode | Enter a lower-capability state. | Next |

## 4.2 Wired and logical networking

| Area | Fault/degradation | Primary targets and observable effect | Model tier |
| --- | --- | --- | --- |
| Physical | cable/fiber cut | Conduit or segment becomes unavailable; shared conduit fans out. | Core |
| Physical | unplugged/loose connector | Link down or intermittent flap. | Core |
| Physical | connector contamination/corrosion | Signal-driven BER, loss, rate fallback, or flap. | Next |
| Physical | fiber bend/microbend | Attenuation drives loss/rate/availability. | Next |
| Physical | water ingress | Correlated attenuation, leakage, and eventual outage. | Advanced |
| Physical | transceiver failure | Port down, one-way failure, or degraded optical budget. | Core |
| Physical | laser/receiver degradation | Signal-driven BER and negotiated-rate fallback. | Next |
| Physical | repeater/amplifier failure | Segment outage or range-dependent degradation. | Next |
| Physical | duplex mismatch | Collision/loss/throughput degradation and asymmetric behavior. | Next |
| Physical | polarity/pair fault | Link down, lane loss, or negotiated-rate fallback. | Advanced |
| Ethernet | autonegotiation failure | No link, duplex/rate mismatch, or deterministic fallback after training. | Next |
| Ethernet | FEC/lane degradation | Corrected-error telemetry, reduced lane/rate mode, CRC loss, or outage. | Next |
| Optical | wavelength/ROADM failure | Selected wavelength or route becomes unavailable or misdirected. | Advanced |
| Optical | amplifier saturation/noise | Optical budget drives BER, FEC corrections, fallback, or loss. | Advanced |
| PON | OLT/ONU/ranging failure | Shared access loss, registration failure, or upstream timing errors. | Next |
| PON | split/shared-upstream contention | Subscriber set shares reduced service and queueing. | Next |
| DSL | loss of synchronization | Copper access link retrains, falls back, or becomes unavailable. | Next |
| DSL | impulse noise/crosstalk | Burst errors, retransmission, interleaving delay, or rate fallback. | Next |
| Cable/DOCSIS | ingress and microreflections | Signal quality drives correctable errors, loss, and rate degradation. | Next |
| Cable/DOCSIS | CMTS/upstream contention | Shared service reduction, admission delay, and queueing. | Next |
| Power-line networking | appliance/grid interference | Shared power signal drives burst errors, fallback, or outage. | Advanced |
| Microwave/free-space optical | obstruction/misalignment | Weather, movement, or pointing drives attenuation and outage. | Next |
| Subsea cable | cut/repeater degradation | Long-haul path fails or incurs wavelength/capacity degradation. | Next |
| Link | link down | Directed or bidirectional availability loss. | Core |
| Link | link flap | Stateful up/down transitions with training/recovery time. | Core |
| Link | one-way failure | Receive-only or transmit-only path. | Core |
| Link | negotiation failure | No link or fallback mode after deterministic training. | Next |
| Link | bit-error rate | CRC loss or explicit undetected corruption. | Next |
| Link | burst errors | Correlated loss/corruption from a burst-state signal. | Next |
| Link | frame loss | Per-frame keyed or recorded loss. | Core |
| Link | duplicate frame | Additional delivery with deterministic gap/order. | Core |
| Link | frame reordering | Delivery shift past sibling frames. | Core |
| Link | frame corruption | Bit flip, field mutation, or truncation. | Core |
| Link | framing/CRC failure | Receiver drops frame and records link-layer error. | Next |
| Link | propagation change | Length/path-driven delay above minimum floor. | Next |
| Link | latency/jitter | Fixed or signal-driven delay variation. | Core |
| Link | bandwidth restriction | Serialization/service-rate cap. | Core |
| Link | MTU reduction | Drop, fragment, or ICMP-style modeled outcome. | Next |
| Link | pause/backpressure | Queue stall or reduced service. | Next |
| Link | broadcast/multicast loss | Recipient-subset loss with stable membership order. | Next |
| Queue | tail drop | Drop on bounded queue overflow. | Next |
| Queue | RED/early drop | Occupancy-driven keyed drop. | Advanced |
| Queue | bufferbloat | Load-driven queue delay. | Next |
| Queue | priority starvation | Selected class receives reduced/no service. | Next |
| Queue | head-of-line blocking | One blocked class delays siblings by declared rule. | Next |
| Queue | queue reset | Buffered frames lost or replayed according to policy. | Next |
| Switch | port failure | One port or line-card segment unavailable. | Core |
| Switch | line-card failure | Correlated port outage and queue loss. | Next |
| Switch | supervisor restart | Control-plane interruption and convergence. | Next |
| Switch | forwarding-table corruption | Wrong port, flood, blackhole, or loop. | Advanced |
| Switch | MAC-table aging anomaly | Flooding or temporary misforwarding. | Advanced |
| Switch | switching-loop/storm | Shared capacity collapse, duplication, queue overflow. | Advanced |
| Router | interface failure | Path segment unavailable. | Core |
| Router | route withdrawal | Path replacement or no route after convergence. | Next |
| Router | route blackhole | Accepted traffic silently dropped. | Next |
| Router | routing loop | Repeated segments until deterministic TTL/hop limit. | Next |
| Router | asymmetric route | Direction-specific path replacement. | Next |
| Router | convergence delay | Timed stale/partial forwarding state. | Next |
| Router | ECMP churn | Stable flow mapping changes at a boundary. | Next |
| Router | control-plane overload | Delayed/lost routing and management events. | Advanced |
| Network function | firewall reject/drop | Typed rejection or silent loss by rule/state. | Next |
| Network function | connection-tracking loss | Existing flows reset/dropped after state loss. | Next |
| Network function | NAT exhaustion | New mappings rejected while existing state persists. | Next |
| Network function | NAT state reset | Address/port mapping discontinuity. | Next |
| Network function | load-balancer backend loss | Membership and flow mapping transition. | Next |
| Network function | tunnel endpoint loss | Overlay segment outage/reconnect. | Next |
| Network function | tunnel MTU mismatch | Fragmentation or blackhole behavior. | Next |
| Network function | VPN key/session expiry | Tunnel admission fails or existing state reconnects. | Next |
| Network function | MPLS label-state failure | Drop, loop, or misroute at a modeled label-switched hop. | Advanced |
| Network function | SD-WAN policy/controller loss | Path selection freezes, changes, or loses reachability. | Advanced |
| Network function | DNS service/path failure | Delay, timeout, stale answer, or wrong answer when DNS is modeled. | Advanced |
| Provider | maintenance window | Scheduled path/rate transition. | Core |
| Provider | peering/transit failure | Route/path outage or congestion. | Next |
| Provider | traffic-engineering change | Latency/capacity/path transition. | Next |
| Physical domain | conduit cut | Correlated failure of all member links. | Core |
| Physical domain | rack/chassis power loss | Correlated switch, NIC, storage, and sensor effects. | Core |

## 4.3 Radios, wireless, mobile, and IoT networking

| Area | Fault/degradation | Primary targets and observable effect | Model tier |
| --- | --- | --- | --- |
| Propagation | path loss | Distance/environment drives received power and profile. | Next |
| Propagation | shadowing/obstruction | Spatial field or zone drives attenuation. | Next |
| Propagation | building/tunnel entry | Correlated attenuation, outage, or technology switch. | Next |
| Propagation | multipath fading | Spatiotemporal fading drives error/retry/rate. | Advanced |
| Propagation | Doppler | Relative motion drives acquisition/error/rate. | Advanced |
| Propagation | rain/weather fade | Weather trace/field drives attenuation. | Next |
| Propagation | foliage/seasonal attenuation | Spatial/environment signal drives loss/rate. | Advanced |
| RF | narrowband interference | Affected channel loses SINR/capacity. | Next |
| RF | broadband interference | Shared band degradation across links. | Next |
| RF | pulsed/intermittent interference | Time waveform drives burst loss. | Next |
| RF | adjacent-channel interference | Channel allocation and power drive degradation. | Advanced |
| RF | self-interference/desense | Co-located transmitter state degrades receiver. | Advanced |
| RF | intentional jamming | Shared spatial/temporal interference source. | Next |
| RF | antenna disconnect/damage | Directional loss, reduced gain, or outage. | Next |
| RF | antenna orientation/polarization mismatch | Movement/orientation drives attenuation. | Next |
| RF | oscillator drift | Frequency error drives acquisition/loss. | Next |
| RF | transmit-power reduction | Battery/thermal/regulatory signal reduces range/rate. | Next |
| RF | receiver-noise increase | Temperature/component state degrades SINR. | Advanced |
| Medium | collision | Joint transmission state causes loss/retry. | Next |
| Medium | hidden terminal | Topology/visibility-dependent collision. | Advanced |
| Medium | exposed terminal | Unnecessary deferral reduces capacity. | Advanced |
| Medium | capture effect | Stronger transmission survives collision by exact rule. | Advanced |
| Medium | backoff anomaly | Excess delay, starvation, or unfair service. | Next |
| Medium | channel occupancy | Shared load trace reduces service. | Core |
| Medium | duty-cycle restriction | Bounded transmit eligibility. | Next |
| Wi-Fi | AP outage/restart | Association loss and reconnect. | Core |
| Wi-Fi | authentication failure | Association rejected or delayed. | Next |
| Wi-Fi | roaming/handoff | AP/path transition with interruption and buffering policy. | Next |
| Wi-Fi | rate adaptation fallback | Signal quality drives lower service rate. | Next |
| Wi-Fi | beacon loss | Association state degrades after modeled timeout. | Advanced |
| Cellular | no coverage | Detached/searching and access outage. | Core |
| Cellular | cell congestion | Load reduces capacity and adds access delay. | Core |
| Cellular | cell/sector outage | Correlated access loss and reselection. | Core |
| Cellular | handover interruption | Buffered/lost/reordered traffic during transition. | Next |
| Cellular | handover failure | Reconnect or outage state. | Next |
| Cellular | ping-pong handover | Repeated association transitions from hysteresis inputs. | Advanced |
| Cellular | RRC idle/reconnect delay | First-traffic delay and possible timeout. | Next |
| Cellular | core/backhaul congestion | Path delay, loss, and capacity degradation. | Next |
| Cellular | SIM/authentication failure | Attach rejected or service limited. | Advanced |
| Cellular | modem reset | Interface/path loss and state reinitialization. | Next |
| Bluetooth LE/Zigbee | advertising loss | Discovery/association delay. | Next |
| Bluetooth LE/Zigbee | channel-map degradation | Reduced usable channels and increased loss. | Advanced |
| Bluetooth LE/Zigbee | connection-interval miss | Delayed/lost operation opportunity. | Next |
| UWB | ranging bias/dropout | Multipath, obstruction, or clock error corrupts or suppresses ranging. | Advanced |
| NFC/RFID | coupling loss/collision | Read, discovery, or transaction fails or is delayed. | Advanced |
| LoRa/LPWAN | duty-cycle exhaustion | Transmit admission denied until recovery. | Next |
| LoRa/LPWAN | spreading-factor/rate change | Capacity/airtime transition. | Next |
| Private/land-mobile radio | repeater/channel loss | Push-to-talk admission, coverage, or group delivery degrades. | Next |
| Mesh | parent/route loss | Association and path transition. | Next |
| Mesh | partition/merge | Dynamic path membership and buffered traffic policy. | Next |
| IoT gateway | gateway outage | Correlated device reachability loss. | Core |
| IoT gateway | uplink degradation | Access network healthy but upstream path degraded. | Core |

## 4.4 Satellite, aerospace, and contact networking

| Area | Fault/degradation | Primary targets and observable effect | Model tier |
| --- | --- | --- | --- |
| Contact | visibility-window closure | Link unavailable outside exact contact intervals. | Core |
| Contact | acquisition delay/failure | Delayed or failed transition into service. | Next |
| Contact | antenna pointing loss | Outage or attenuation from orientation error. | Next |
| Contact | beam handover | Path/beam transition with interruption. | Next |
| Contact | gateway handover | Ground path transition and queue policy. | Next |
| Propagation | range-varying delay | Position trace drives propagation delay. | Core |
| Propagation | Doppler acquisition error | Rate/loss/outage from relative velocity. | Advanced |
| Propagation | rain fade | Weather drives attenuation/loss/rate. | Next |
| Propagation | ionospheric scintillation | Burst signal degradation. | Advanced |
| Propagation | solar interference | Scheduled/spatial degradation or outage. | Advanced |
| Capacity | transponder contention | Shared service reduction and queueing. | Next |
| Capacity | ground-station congestion | Queue delay/loss/capacity restriction. | Next |
| Infrastructure | ground-station outage | Correlated contact/path loss. | Core |
| Infrastructure | inter-satellite link loss | Route/contact-plan transition. | Next |
| DTN | contact-plan error | Missed or shortened contact opportunity. | Next |
| DTN | custody queue overflow | Stored bundle loss or rejection. | Next |
| DTN | stale route/contact data | Delay, loop, or missed delivery. | Advanced |
| Space environment | radiation upset | Correlated onboard memory/compute bit flip or reset. | Next |
| Space environment | thermal cycle | Clock/radio/battery/compute degradation signal. | Advanced |
| Space environment | power eclipse | Battery discharge, service restriction, shutdown. | Next |

## 4.5 Datacenter compute, CPU, memory, clock, and accelerators

| Area | Fault/degradation | Primary targets and observable effect | Model tier |
| --- | --- | --- | --- |
| Node | crash | Stop node with explicit restart policy. | Core |
| Node | power-cycle reset | Lose volatile state and restart from declared boundary. | Next |
| Node | hang | Remain running but make no modeled progress. | Core |
| Node | intermittent reset | Signal-driven repeated reset/recovery. | Next |
| Node | boot failure | Start/restart transition fails or times out. | Next |
| CPU | capacity throttle | Reduce modeled compute service/counter mapping. | Core |
| CPU | thermal throttle | Temperature signal drives capacity throttle. | Next |
| CPU | vCPU stall | Selected vCPU makes no progress for an interval. | Next |
| CPU | vCPU offline | Selected vCPU unavailable with topology/capability checks. | Advanced |
| CPU | machine check | Guest-visible architecture-specific hardware exception. | Next |
| CPU | reset/triple fault | Architecture-specific reset transition. | Advanced |
| CPU | register bit flip | Impulse mutation of resolved architectural register bits. | Next |
| CPU | instruction-result corruption | Mutate selected result at exact instruction opportunity. | Advanced |
| CPU | instruction skip/replay | Modify instruction execution semantics. | Advanced |
| CPU | illegal/spurious exception | Inject typed exception at exact boundary. | Advanced |
| Interrupt | dropped interrupt | Suppress selected interrupt delivery. | Next |
| Interrupt | delayed interrupt | Shift delivery while preserving causality. | Next |
| Interrupt | duplicate/spurious interrupt | Deliver additional interrupt. | Next |
| Interrupt | interrupt storm | Periodic/burst event sequence causes load/livelock. | Next |
| Memory | transient bit flip | One-shot physical/virtual memory mutation. | Core |
| Memory | stuck-at bit | Persistent read/write transform for selected bits. | Next |
| Memory | read corruption | Opportunity-specific returned-data mutation. | Next |
| Memory | lost/torn write | Suppress or partially apply selected memory write. | Advanced |
| Memory | poison | Access produces guest-visible fatal/correctable outcome. | Next |
| Memory | ECC corrected error | Telemetry/event without exposed data corruption. | Next |
| Memory | ECC uncorrectable error | Poison, machine check, or fatal policy. | Next |
| Memory | row/region failure | Persistent range fault. | Next |
| Memory | retention decay | Time/refresh/temperature-controlled bit errors. | Advanced |
| Memory | rowhammer-style disturbance | Access-pattern-driven adjacent-row errors. | Advanced |
| Memory | latency/bandwidth degradation | Capacity/timing restriction. | Next |
| Clock | offset/skew | Signed guest-visible time offset. | Core |
| Clock | drift/rate error | Exact rational clock-rate change. | Core |
| Clock | jump/step | Impulse change in offset. | Next |
| Clock | freeze | Clock value stops while scheduler continues. | Next |
| Clock | jitter/wander | Signal-driven read variation with monotonicity policy. | Next |
| Clock | source failure/fallback | RTC/TSC/paravirtual/source transition. | Advanced |
| Clock | synchronization loss | Drift/offset evolves until resynchronization event. | Next |
| Accelerator | device disappearance/reset | GPU/TPU/FPGA unavailable and reinitialized. | Advanced |
| Accelerator | compute corruption | Typed result corruption at kernel/job boundary. | Advanced |
| Accelerator | memory/ECC error | Corrected/uncorrectable device-memory event. | Advanced |
| Accelerator | thermal/power throttle | Service-rate restriction. | Advanced |

## 4.6 Storage, flash, and filesystem-facing devices

| Area | Fault/degradation | Primary targets and observable effect | Model tier |
| --- | --- | --- | --- |
| Device | disappearance/offline | Admission rejection or no completion. | Core |
| Device | reset/reconnect | Queue treatment and reinitialization transition. | Core |
| Device | read-only transition | Writes rejected while reads continue. | Next |
| Device | capacity change | Reported length changes under explicit policy. | Advanced |
| Timing | read latency | Fixed/signal-driven completion delay and jitter. | Core |
| Timing | write latency | Fixed/signal-driven completion delay and jitter. | Core |
| Timing | flush latency | Flush completion delay/stall. | Core |
| Capacity | bandwidth cap | Exact byte/bit service limit. | Core |
| Capacity | IOPS cap | Operation service limit. | Next |
| Capacity | queue-depth restriction | Admission, queueing, and backpressure change. | Next |
| Outcome | read error | Typed status/errno at opportunity. | Core |
| Outcome | write error | Typed status/errno at opportunity. | Core |
| Outcome | flush error | Typed status/errno. | Core |
| Outcome | timeout/dropped completion | No completion before modeled timeout. | Core |
| Ordering | completion reorder | Delay selected completion past siblings. | Core |
| Multiplicity | duplicate completion | Emit duplicate completion under protocol-valid policy. | Advanced |
| Data | read bit corruption | Mutate returned bytes. | Core |
| Data | stale read | Return prior block/version. | Next |
| Data | misdirected read/write | Access wrong resolved block/range. | Advanced |
| Write | lost write | Acknowledge or fail while suppressing persistence by policy. | Next |
| Write | torn/partial write | Persist a deterministic subset of sectors/bytes. | Next |
| Write | reordered persistence | Completion order differs from durable order. | Next |
| Write | volatile-cache loss | Reset/power removes acknowledged non-durable writes. | Core |
| Flush | lying flush | Report success without satisfying durability barrier. | Next |
| Media | bad sector/range | Persistent range-specific error/corruption. | Next |
| Media | latent sector error | Error appears after time/read-count threshold. | Advanced |
| Flash | erase-block wear | Wear state drives latency/error/read-only transition. | Next |
| Flash | program/erase failure | Operation error or partial persistence. | Next |
| Flash | retention error | Time/temperature/wear-driven corruption. | Advanced |
| Flash | read disturb | Read-count-driven neighboring corruption. | Advanced |
| NVMe/SATA | controller reset | Queue loss/retry and re-enumeration. | Next |
| NVMe/SATA | namespace/path loss | Selected namespace/path unavailable. | Next |
| RAID/multipath | member/path failure | Degraded service and rebuild/failover state. | Next |
| RAID/multipath | rebuild load/failure | Capacity/latency and second-failure risk. | Advanced |
| Filesystem-facing | errno injection | Typed 9p/filesystem operation error. | Core |
| Filesystem-facing | stale metadata/data | Return prior modeled result. | Next |
| Filesystem-facing | delayed visibility | Namespace/data update becomes visible later. | Advanced |

## 4.7 Sensors, measurement chains, and location/orientation

| Area | Fault/degradation | Primary targets and observable effect | Model tier |
| --- | --- | --- | --- |
| Sample | dropout | No sample at expected opportunity. | Core |
| Sample | delayed sample | Delivery after exact added latency. | Core |
| Sample | stale sample | Repeat prior sample with timestamp policy. | Core |
| Sample | duplicate sample | Additional sample with stable sequence. | Core |
| Sample | reordered samples | Delay selected sample past siblings. | Next |
| Sample | timestamp offset | Sample value correct, timestamp shifted. | Core |
| Sample | timestamp drift/jitter | Time-varying timestamp error. | Next |
| Value | additive bias | Add unit-compatible signal. | Core |
| Value | scale/gain error | Multiply by exact rational. | Core |
| Value | drift | Bias/gain evolves with time/environment. | Core |
| Value | noise | Add recorded or deterministic keyed noise. | Core |
| Value | burst noise/spikes | Event/burst-driven outliers. | Next |
| Value | saturation/clipping | Clamp at declared limits. | Core |
| Value | quantization loss | Coarsen resolution with fixed rounding. | Next |
| Value | deadband | Suppress small changes. | Next |
| Value | hysteresis | Stateful threshold-dependent output. | Next |
| Value | stuck-at | Force constant or last value. | Core |
| Value | wrap/overflow | Apply explicit finite-width wrapping. | Advanced |
| Multi-axis | cross-axis coupling | Mix axes by exact matrix. | Next |
| Multi-axis | axis swap/inversion | Permute or negate axes. | Next |
| Multi-axis | orientation miscalibration | Rotate vector by exact lookup/matrix approximation. | Advanced |
| Calibration | calibration loss | Enter default/incorrect calibration state. | Next |
| Calibration | warm-up error | Time-since-start controls bias/noise. | Next |
| Environment | temperature sensitivity | Temperature signal drives bias/gain/noise. | Next |
| Environment | vibration sensitivity | Vibration drives noise/dropout/bias. | Next |
| Environment | electromagnetic interference | Shared signal drives noise/dropout. | Next |
| GPS/GNSS | position offset/drift | Guest-observed location differs from truth. | Core |
| GPS/GNSS | multipath jump | Spatial/event-driven position error. | Next |
| GPS/GNSS | loss of fix | Validity/state transition and missing samples. | Core |
| GPS/GNSS | stale fix | Prior solution repeated. | Core |
| GPS/GNSS | spoofed solution | Explicit adversarial observation substitution. | Advanced |
| IMU | accelerometer/gyro bias | Axis-specific additive bias. | Core |
| IMU | integration drift | Stateful accumulated orientation/position error. | Next |
| Magnetometer | magnetic interference/hard-iron bias | Orientation observation receives environmental bias or distortion. | Next |
| Barometer | blocked port/weather coupling | Altitude/pressure samples lag, drift, or stick. | Next |
| Radar/LiDAR/sonar | occlusion/dropout | Expected returns are suppressed by visibility or hardware state. | Next |
| Radar/LiDAR/sonar | ghost/range bias | Extra returns or shifted range/velocity observations appear. | Advanced |
| Encoder/tachometer | missed/extra transition | Position, speed, or distance count diverges from truth. | Next |
| Electrical metering | offset/saturation/phase error | Voltage, current, power, or energy observation is transformed. | Next |
| Thermocouple/RTD | open/short/reference-junction fault | Typed invalid state, rail value, or temperature bias. | Next |
| Camera | dropped/corrupt frame | Missing or payload-transformed frame. | Next |
| Camera | exposure/focus fault | Signal-driven image transform metadata/model. | Advanced |
| Microphone | dropout/clipping/noise | Sample-stream effects. | Next |
| Environmental | humidity/pressure/light drift | Common sensor-value transforms. | Core |

## 4.8 IoT buses, peripherals, actuators, and embedded devices

| Area | Fault/degradation | Primary targets and observable effect | Model tier |
| --- | --- | --- | --- |
| MCU | watchdog reset | Node/peripheral reset transition. | Core |
| MCU | brownout reset | Power-signal-driven reset and volatile-state loss. | Core |
| MCU | clock drift | Timer/baud/sample timing error. | Next |
| MCU | flash wear/corruption | Persistent program/data range fault. | Next |
| GPIO | stuck high/low | Persistent pin value. | Core |
| GPIO | bounce/glitch | Pulse/event sequence around transition. | Core |
| GPIO | floating/noisy input | Keyed/trace-driven value. | Next |
| I2C/SPI | bus unavailable | Admission failure/timeout. | Core |
| I2C/SPI | NACK/error | Typed operation failure. | Core |
| I2C/SPI | corrupted transfer | Payload mutation or CRC failure. | Next |
| I2C/SPI | bus contention | Delay, arbitration loss, or corruption. | Next |
| UART/serial | baud mismatch | Framing errors, corruption, loss. | Next |
| UART/serial | overrun | Buffer/queue loss. | Next |
| CAN bus/fieldbus | arbitration delay/loss | Shared-medium service and retry. | Next |
| CAN bus/fieldbus | bus-off | Interface unavailable until recovery. | Core |
| CAN bus/fieldbus | dominant stuck bit | Shared bus outage/corruption. | Next |
| USB/PCIe | disconnect/hot reset | Peripheral unavailable/re-enumerated. | Next |
| USB/PCIe | link-width/rate fallback | Capacity degradation. | Advanced |
| USB/PCIe | completion timeout | Operation failure. | Next |
| Actuator | command dropout | No physical state transition. | Core |
| Actuator | delayed response | Transition begins/completes late. | Core |
| Actuator | stuck/jammed | State cannot change or changes only partly. | Core |
| Actuator | backlash/deadband | Stateful command-to-truth mapping. | Next |
| Actuator | overshoot/oscillation | Dynamic response signal. | Advanced |
| Actuator | wrong-direction/gain | Command mapping error. | Next |
| Gateway | protocol translation error | Drop, delay, field mutation, stale mapping. | Next |
| Gateway | time synchronization loss | Sensor/actuator timestamps diverge. | Next |

## 4.9 Power, battery, thermal, cooling, and environment

| Area | Fault/degradation | Primary targets and observable effect | Model tier |
| --- | --- | --- | --- |
| Grid/source | outage | Downstream power domain unavailable. | Core |
| Grid/source | brownout/sag | Voltage signal drives reset, corruption, or degraded mode. | Core |
| Grid/source | swell/surge/transient | Impulse damage/reset/error bindings. | Next |
| Grid/source | frequency/phase error | Clock/motor/PSU effects. | Advanced |
| Grid/source | ripple/noise | Sensor/radio/compute/storage degradation signal. | Next |
| PDU | outlet failure | Selected devices lose power. | Core |
| PDU | controller failure | Group transition or inability to switch. | Next |
| PSU | failure | Device/rack power loss. | Core |
| PSU | current limiting | Capacity throttle or brownout under load. | Next |
| PSU | redundant-feed loss | Degraded redundancy, then outage on second cause. | Next |
| UPS | battery depletion | Runtime state reaches shutdown/outage threshold. | Core |
| UPS | transfer failure/delay | Interruption or brownout during source switch. | Next |
| Battery | discharge | State-of-charge integration from load/charge signals. | Core |
| Battery | degraded capacity | Lower usable capacity. | Next |
| Battery | internal-resistance rise | Load-dependent voltage sag/throttle/reset. | Next |
| Battery | sudden disconnect | Immediate power loss. | Core |
| Charger | unavailable/slow | Charge-rate reduction. | Core |
| Charger | intermittent contact | Charge/power flap. | Next |
| Thermal | ambient heat/cold | Shared environmental signal. | Core |
| Thermal | thermal-zone rise | Stateful heat integration from power/load/cooling. | Next |
| Thermal | throttle | CPU/radio/storage/charge capacity reduction. | Core |
| Thermal | shutdown | Lifecycle transition at threshold/hysteresis. | Core |
| Cooling | fan failure | Cooling reduction and thermal rise. | Core |
| Cooling | pump/loop failure | Shared rack/system thermal rise. | Next |
| Cooling | blocked airflow | Thermal-field change. | Next |
| Environment | vibration/shock | Shared disk, connector, sensor, and mechanical effects. | Core |
| Environment | humidity/condensation | Sensor drift, leakage, connector degradation. | Advanced |
| Environment | dust/contamination | Cooling and optical/sensor degradation. | Advanced |
| Environment | radiation | Memory/compute/storage bit errors and resets. | Next |
| Environment | pressure/altitude | Cooling, disk, radio, and sensor effects. | Advanced |

## 4.10 Laptops, mobile computers, and edge systems

These systems compose other domains but merit explicit scenarios because their
failure modes are strongly coupled.

| Area | Fault/degradation | Primary targets and observable effect | Model tier |
| --- | --- | --- | --- |
| Power | battery depletion | Throttle, sleep, then shutdown by policy. | Core |
| Power | charger/dock disconnect | Power-source and peripheral/path transition. | Core |
| Thermal | CPU/GPU throttle | Load/temperature-driven service reduction. | Core |
| Thermal | emergency shutdown | Node lifecycle transition. | Core |
| Lifecycle | suspend/resume | Timers, devices, network association, and queues transition. | Next |
| Lifecycle | failed resume | Device/path unavailable or node reset. | Next |
| Network | Wi-Fi roam/outage | Association/path transition. | Core |
| Network | cellular fallback/handoff | Interface/path selection transition. | Next |
| Network | VPN/tunnel reconnect | Overlay state and address/path discontinuity. | Next |
| Peripheral | USB/dock disconnect | Device and network segments disappear. | Next |
| Storage | shock/thermal storage error | Shared environment drives I/O effects. | Next |
| Sensor | lid/ambient/orientation fault | Guest-observed control inputs transformed. | Advanced |
| Clock | sleep/resume discontinuity | Guest clock offset/drift/source transition. | Next |
| Firmware | embedded-controller reset | Power, fan, battery, and input state transition. | Advanced |

## 4.11 Common-cause fault domains

The taxonomy above becomes most useful when scenarios name shared causes:

| Fault domain | Representative fan-out |
| --- | --- |
| fiber conduit | Many physical network segments down together. |
| rack power | Nodes, switches, disks, fans, and sensors transition together. |
| chassis/line card | Port group, queues, and forwarding state fail together. |
| cooling loop | Temperature rises across compute, storage, and power equipment. |
| vibration/shock zone | Connector flaps, disk errors, and sensor noise correlate. |
| RF spectrum region | Several links share interference, load, and outage. |
| cellular sector | UEs share coverage, congestion, and sector reset. |
| satellite beam/gateway | Contacts share capacity, weather, and gateway outage. |
| vehicle/device enclosure | Battery, thermal, sensor, radio, and compute effects correlate. |
| weather region | Radio attenuation, power, environmental sensors, and satellite fade correlate. |
| radiation event | Compute/memory/storage upsets across affected hardware. |
| software/firmware controller | Repeated device family reset or shared wrong state. |

- **[TAX-5]** A common-cause domain MUST use shared signal/state and explicit
  fan-out bindings. It MUST NOT fake correlation by choosing equal seeds for
  otherwise independent hazards.
- **[TAX-6]** Fault-domain membership MUST be static or transition through a
  deterministic declared rule, such as an endpoint moving into a spatial zone.

## 4.12 Taxonomy extension rules

A proposal for a new effect must answer:

1. Is it a cause signal, a persistent state, an opportunity outcome, or an
   impulse transition?
2. Can an existing generic effect represent the observable semantics?
3. Which target and lifecycle phase apply?
4. Which parameters and exact units are required?
5. What is the deterministic composition algebra?
6. What state must be checkpointed?
7. What event-log evidence explains it?
8. What does locked replay validate?
9. Which backend capability applies?
10. How is it tested in isolation, overlap, checkpoint, and divergence gates?

- **[TAX-7]** An effect kind MUST NOT be added solely to encode a new waveform;
  waveform variation belongs in signals and mappings.
- **[TAX-8]** Technology-specific metrics MAY be added as typed telemetry without
  becoming generic effect parameters.
- **[TAX-9]** User-facing reference documentation MUST enumerate every shipped
  effect and signal kind with its required fields, units, composition, backend
  requirements, and configuration example.
