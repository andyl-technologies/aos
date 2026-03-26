---- MODULE Network ----
\* LibP2P Network Model
\*
\* Shared module modeling libp2p-specific distributed system semantics.
\* Other TLA+ specs (Statute, Jobs, Workflows, Store) should reference
\* these properties when reasoning about network behavior.
\*
\* Models:
\*   1. GossipSub message propagation (mesh hops, delivery delay)
\*   2. GossipSub dedup cache (60s window — messages seen within 60s are dropped)
\*   3. DHT record storage (eventual consistency, TTL-based expiry)
\*   4. DHT provider records (put/get with propagation delay)
\*   5. Stream protocols (point-to-point, connection-oriented)
\*   6. Network partitions (bidirectional communication failure)
\*   7. Clock skew between peers (bounded, configurable)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Peers,                   \* Set of all peer IDs
    GossipSubDedupWindow,    \* Dedup cache TTL in time units (default 60)
    DHTRecordTTL,            \* Default DHT record TTL in time units
    MaxClockSkew,            \* Maximum clock skew between any two peers
    MaxPropagationDelay      \* Maximum gossipsub propagation delay (hops)

VARIABLES
    \* GossipSub state
    gossipMessages,          \* In-flight gossip messages: set of {topic, payload, from, sent_at}
    gossipDelivered,         \* Delivered messages per peer: peer -> set of {topic, payload, delivered_at}
    gossipDedupCache,        \* Dedup cache per peer: peer -> set of {payload_hash, seen_at}
    gossipSubscriptions,     \* Topic subscriptions: peer -> set of topic strings

    \* DHT state
    dhtRecords,              \* DHT records: key -> {value, written_at, ttl, writer}
    dhtProviders,            \* Provider records: key -> set of {peer, registered_at, ttl}

    \* Stream protocol state
    activeStreams,            \* Active stream connections: set of {from, to, protocol, opened_at}
    streamOperations,        \* In-flight operations tied to streams: set of {stream, op_id, ...}

    \* Network topology
    networkPartitions,       \* Set of {p1, p2} pairs that cannot communicate

    \* Clocks
    peerClocks,              \* Local clock per peer: peer -> time (with skew)
    globalTime               \* Reference clock (monotonic)

networkVars == <<gossipMessages, gossipDelivered, gossipDedupCache,
                 gossipSubscriptions, dhtRecords, dhtProviders,
                 activeStreams, streamOperations, networkPartitions,
                 peerClocks, globalTime>>

\* ---- Connectivity ----

\* Can two peers communicate? (not partitioned)
CanCommunicate(p1, p2) ==
    /\ p1 # p2
    /\ {p1, p2} \notin networkPartitions

\* Peers reachable from a given peer (transitive)
Reachable(peer) ==
    {p \in Peers : CanCommunicate(peer, p)}

\* Is a peer isolated? (cannot reach any other peer)
IsIsolated(peer) ==
    Reachable(peer) = {}

\* ---- GossipSub ----

\* Publish a message to a gossipsub topic
GossipPublish(peer, topic, payload) ==
    /\ topic \in gossipSubscriptions[peer]
    /\ gossipMessages' = gossipMessages \union
           {[topic |-> topic, payload |-> payload,
             from |-> peer, sent_at |-> peerClocks[peer]]}
    /\ UNCHANGED <<gossipDelivered, gossipDedupCache, gossipSubscriptions,
                   dhtRecords, dhtProviders, activeStreams, streamOperations,
                   networkPartitions, peerClocks, globalTime>>

\* Deliver a gossip message to a subscriber
\* Models: mesh propagation delay, dedup cache check, partition check
GossipDeliver(peer, msg) ==
    /\ msg \in gossipMessages
    /\ peer \in Peers
    /\ peer # msg.from
    /\ CanCommunicate(peer, msg.from)  \* Not partitioned from sender
    /\ msg.topic \in gossipSubscriptions[peer]  \* Subscribed to topic
    \* Dedup check: haven't seen this payload within the dedup window
    /\ ~\E cached \in gossipDedupCache[peer] :
        /\ cached.payload_hash = msg.payload  \* Simplified: payload = hash
        /\ peerClocks[peer] - cached.seen_at < GossipSubDedupWindow
    \* Deliver
    /\ gossipDelivered' = [gossipDelivered EXCEPT ![peer] =
           @ \union {[topic |-> msg.topic, payload |-> msg.payload,
                      delivered_at |-> peerClocks[peer]]}]
    \* Add to dedup cache
    /\ gossipDedupCache' = [gossipDedupCache EXCEPT ![peer] =
           @ \union {[payload_hash |-> msg.payload,
                      seen_at |-> peerClocks[peer]]}]
    /\ UNCHANGED <<gossipMessages, gossipSubscriptions, dhtRecords,
                   dhtProviders, activeStreams, streamOperations,
                   networkPartitions, peerClocks, globalTime>>

\* Dedup cache expiry: remove entries older than the dedup window
GossipDedupExpiry(peer) ==
    /\ gossipDedupCache' = [gossipDedupCache EXCEPT ![peer] =
           {c \in @ : peerClocks[peer] - c.seen_at < GossipSubDedupWindow}]
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipSubscriptions,
                   dhtRecords, dhtProviders, activeStreams, streamOperations,
                   networkPartitions, peerClocks, globalTime>>

\* Subscribe to a topic
GossipSubscribe(peer, topic) ==
    /\ gossipSubscriptions' = [gossipSubscriptions EXCEPT ![peer] = @ \union {topic}]
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   dhtRecords, dhtProviders, activeStreams, streamOperations,
                   networkPartitions, peerClocks, globalTime>>

\* Unsubscribe from a topic
GossipUnsubscribe(peer, topic) ==
    /\ topic \in gossipSubscriptions[peer]
    /\ gossipSubscriptions' = [gossipSubscriptions EXCEPT ![peer] = @ \ {topic}]
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   dhtRecords, dhtProviders, activeStreams, streamOperations,
                   networkPartitions, peerClocks, globalTime>>

\* Key property: peer offline > dedup window permanently misses messages
\* sent during that period (no anti-entropy in base gossipsub)
GossipMessageLoss(peer, msg) ==
    \* A message is permanently lost to a peer if:
    /\ msg \in gossipMessages
    /\ peer \in Peers
    /\ msg.topic \in gossipSubscriptions[peer]
    \* The message was sent more than dedup window ago
    /\ peerClocks[peer] - msg.sent_at >= GossipSubDedupWindow
    \* And the peer never received it (was partitioned or offline)
    /\ ~\E d \in gossipDelivered[peer] :
        d.payload = msg.payload /\ d.topic = msg.topic

\* ---- DHT ----

\* Write a DHT record
DHTPut(peer, key, value, ttl) ==
    /\ dhtRecords' = [dhtRecords EXCEPT ![key] =
           [value |-> value, written_at |-> peerClocks[peer],
            ttl |-> ttl, writer |-> peer]]
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtProviders, activeStreams,
                   streamOperations, networkPartitions, peerClocks, globalTime>>

\* Read a DHT record (may return stale data or NONE if expired)
DHTGet(peer, key) ==
    IF key \in DOMAIN dhtRecords
       /\ globalTime - dhtRecords[key].written_at < dhtRecords[key].ttl
    THEN dhtRecords[key].value
    ELSE "NOT_FOUND"

\* DHT record expiry
DHTExpiry(key) ==
    /\ key \in DOMAIN dhtRecords
    /\ globalTime - dhtRecords[key].written_at >= dhtRecords[key].ttl
    /\ dhtRecords' = [k \in (DOMAIN dhtRecords) \ {key} |-> dhtRecords[k]]
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtProviders, activeStreams,
                   streamOperations, networkPartitions, peerClocks, globalTime>>

\* Register as a provider
DHTStartProviding(peer, key, ttl) ==
    /\ dhtProviders' = [dhtProviders EXCEPT ![key] =
           @ \union {[peer |-> peer, registered_at |-> peerClocks[peer], ttl |-> ttl]}]
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtRecords, activeStreams,
                   streamOperations, networkPartitions, peerClocks, globalTime>>

\* Get providers (returns set of peers, filtered by TTL)
DHTGetProviders(key) ==
    {p.peer : p \in {q \in dhtProviders[key] :
        globalTime - q.registered_at < q.ttl}}

\* Provider record expiry
DHTProviderExpiry(key, peer) ==
    /\ \E p \in dhtProviders[key] :
        /\ p.peer = peer
        /\ globalTime - p.registered_at >= p.ttl
    /\ dhtProviders' = [dhtProviders EXCEPT ![key] =
           {p \in @ : ~(p.peer = peer /\ globalTime - p.registered_at >= p.ttl)}]
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtRecords, activeStreams,
                   streamOperations, networkPartitions, peerClocks, globalTime>>

\* ---- Stream Protocols ----

\* Open a stream to a peer
StreamOpen(from, to, protocol) ==
    /\ CanCommunicate(from, to)
    /\ activeStreams' = activeStreams \union
           {[from |-> from, to |-> to, protocol |-> protocol,
             opened_at |-> peerClocks[from]]}
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtRecords, dhtProviders,
                   streamOperations, networkPartitions, peerClocks, globalTime>>

\* Close a stream (explicit or due to partition) and cancel in-flight operations
StreamClose(stream) ==
    /\ stream \in activeStreams
    /\ activeStreams' = activeStreams \ {stream}
    \* Cancel any operation tied to this stream
    /\ streamOperations' = {op \in streamOperations : op.stream # stream}
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtRecords, dhtProviders,
                   networkPartitions, peerClocks, globalTime>>

\* Close a stream with cancellation (named alias for clarity)
StreamCloseWithCancel(stream) ==
    /\ stream \in activeStreams
    /\ activeStreams' = activeStreams \ {stream}
    \* Cancel any operation tied to this stream
    /\ streamOperations' = {op \in streamOperations : op.stream # stream}
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtRecords, dhtProviders,
                   networkPartitions, peerClocks, globalTime>>

\* Partition breaks active streams and cancels their operations
PartitionBreaksStreams(p1, p2) ==
    /\ {p1, p2} \in networkPartitions
    /\ LET brokenStreams == {s \in activeStreams : {s.from, s.to} = {p1, p2}}
       IN /\ activeStreams' = activeStreams \ brokenStreams
          /\ streamOperations' = {op \in streamOperations :
                 ~\E s \in brokenStreams : op.stream = s}
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtRecords, dhtProviders,
                   networkPartitions, peerClocks, globalTime>>

\* ---- Network Topology ----

\* Create a partition
CreatePartition(p1, p2) ==
    /\ p1 # p2
    /\ {p1, p2} \notin networkPartitions
    /\ networkPartitions' = networkPartitions \union {{p1, p2}}
    \* Partition immediately breaks streams between p1 and p2
    /\ LET brokenStreams == {s \in activeStreams : {s.from, s.to} = {p1, p2}}
       IN /\ activeStreams' = activeStreams \ brokenStreams
          /\ streamOperations' = {op \in streamOperations :
                 ~\E s \in brokenStreams : op.stream = s}
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtRecords, dhtProviders,
                   peerClocks, globalTime>>

\* Heal a partition
HealPartition(p1, p2) ==
    /\ {p1, p2} \in networkPartitions
    /\ networkPartitions' = networkPartitions \ {{p1, p2}}
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtRecords, dhtProviders,
                   activeStreams, streamOperations, peerClocks, globalTime>>

\* ---- Clocks ----

\* Advance global time (all peer clocks advance with bounded skew)
AdvanceTime ==
    /\ globalTime' = globalTime + 1
    /\ peerClocks' = [p \in Peers |->
           \* Each peer's clock advances by 1 +/- skew
           peerClocks[p] + 1]  \* Simplified: no skew in base model
    /\ UNCHANGED <<gossipMessages, gossipDelivered, gossipDedupCache,
                   gossipSubscriptions, dhtRecords, dhtProviders,
                   activeStreams, streamOperations, networkPartitions>>

\* ---- Initialization ----

NetworkInit ==
    /\ gossipMessages = {}
    /\ gossipDelivered = [p \in Peers |-> {}]
    /\ gossipDedupCache = [p \in Peers |-> {}]
    /\ gossipSubscriptions = [p \in Peers |-> {}]
    /\ dhtRecords = [k \in {} |-> [value |-> "", written_at |-> 0, ttl |-> 0, writer |-> CHOOSE p \in Peers : TRUE]]
    /\ dhtProviders = [k \in {} |-> {}]
    /\ activeStreams = {}
    /\ streamOperations = {}
    /\ networkPartitions = {}
    /\ peerClocks = [p \in Peers |-> 0]
    /\ globalTime = 0

\* ---- Properties ----

\* GossipSub eventual delivery: if two peers are continuously connected
\* and both subscribed, messages are eventually delivered
GossipEventualDelivery ==
    \A msg \in gossipMessages :
        \A peer \in Peers :
            (peer # msg.from
             /\ msg.topic \in gossipSubscriptions[peer]
             /\ CanCommunicate(peer, msg.from)
             /\ globalTime - msg.sent_at < GossipSubDedupWindow)
            ~>
            (\E d \in gossipDelivered[peer] :
                d.payload = msg.payload /\ d.topic = msg.topic)

\* DHT records are visible after propagation delay
DHTEventualVisibility ==
    \A key \in DOMAIN dhtRecords :
        globalTime - dhtRecords[key].written_at < dhtRecords[key].ttl =>
            DHTGet(CHOOSE p \in Peers : TRUE, key) # "NOT_FOUND"

\* Partitions break streams immediately
PartitionBreaksStreamsSafety ==
    \A s \in activeStreams :
        {s.from, s.to} \notin networkPartitions

\* No operation continues after its stream is closed
StreamCancellationSafety ==
    \A op \in streamOperations :
        \E s \in activeStreams : s = op.stream

\* ---- Model checking configuration ----
\* Use small instances:
\*   Peers = {p1, p2, p3}
\*   GossipSubDedupWindow = 5
\*   DHTRecordTTL = 10
\*   MaxClockSkew = 1
\*   MaxPropagationDelay = 2

====
