---- MODULE Store ----
\* AOS Content-Addressed Store: Replication, GC, and Compaction
\*
\* This specification models:
\*   1. Store object publication and provider records
\*   2. Replication: nearest-N assignment, claim/nack/rebalance
\*   3. GC: LRU eviction, Statute auto-pinning, closure protection
\*   4. Pack compaction: concurrent reads during compaction
\*   5. Min hold duration for newly published objects
\*
\* Safety properties:
\*   - Pinned objects are never GC'd (Statute refs, active views, manual pins)
\*   - Replicated objects meet the replication factor (eventually)
\*   - Compaction never loses live chunks
\*   - Content-addressed: same hash = same content (no poisoning)
\*
\* Liveness properties:
\*   - Published objects are eventually replicated
\*   - Nack cascading terminates
\*   - Dead space is eventually compacted

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Objects,             \* Set of all store object IDs
    Peers,               \* Set of all peer IDs
    Replicators,         \* Subset of Peers that participate in replication
    ReplicationFactor,   \* Minimum number of replicas (N)
    MaxTime,             \* Maximum time step
    MinHoldDuration,     \* Time before newly published objects can be GC'd
    PinnedObjects        \* Set of objects pinned by Statute (auto-pinning)

VARIABLES
    providers,           \* Who has each object: object -> set of peers
    replicaState,        \* Replication claim state: (object, peer) -> state
    nackCount,           \* Nack count per (object, replicator): (obj, rep) -> count
    publishedAt,         \* When each object was published: object -> time
    lastAccess,          \* Last access time: object -> time
    gcRoots,             \* Active GC roots (FUSE views + Statute pins)
    packs,               \* Pack state: pack_id -> {live_chunks, dead_chunks}
    time                 \* Global logical clock

vars == <<providers, replicaState, nackCount, publishedAt,
          lastAccess, gcRoots, packs, time>>

ReplicaStates == {"none", "assigned", "claiming", "downloading",
                  "success", "nacked"}

\* ---- Helper operators ----

Min(S) == CHOOSE x \in S : \A y \in S : x <= y

\* N nearest replicators to an object (simplified: any subset of correct size)
\* In a real system this would use XOR distance; for model checking we
\* just pick a deterministic subset via CHOOSE.
NearestN(object) ==
    LET n == Min({ReplicationFactor, Cardinality(Replicators)})
    IN CHOOSE S \in SUBSET Replicators : Cardinality(S) = n

\* Is an object pinned? (Statute auto-pinning or active FUSE view)
IsPinned(object) == object \in gcRoots \/ object \in PinnedObjects

\* Is an object within min hold duration?
InHoldPeriod(object) ==
    /\ object \in DOMAIN publishedAt
    /\ time - publishedAt[object] < MinHoldDuration

\* Provider count for an object
ProviderCount(object) == Cardinality(providers[object])

\* ---- Initial state ----

Init ==
    /\ providers = [o \in Objects |-> {}]
    /\ replicaState = [o \in Objects, r \in Replicators |-> "none"]
    /\ nackCount = [o \in Objects, r \in Replicators |-> 0]
    /\ publishedAt = [o \in {} |-> 0]
    /\ lastAccess = [o \in Objects |-> 0]
    /\ gcRoots = PinnedObjects
    /\ packs = [p \in {1} |-> [live |-> Cardinality(Objects), dead |-> 0]]
    /\ time = 0

\* ---- Actions ----

\* Publish a new store object
PublishObject(object, peer) ==
    /\ peer \in Peers
    /\ providers' = [providers EXCEPT ![object] = @ \union {peer}]
    /\ publishedAt' = publishedAt @@ (object :> time)
    /\ lastAccess' = [lastAccess EXCEPT ![object] = time]
    /\ UNCHANGED <<replicaState, nackCount, gcRoots, packs, time>>

\* A replicator is assigned to replicate an object
AssignReplica(object, replicator) ==
    /\ replicator \in NearestN(object)
    /\ replicaState[object, replicator] = "none"
    /\ object \in DOMAIN publishedAt  \* Object has been published
    /\ replicaState' = [replicaState EXCEPT ![object, replicator] = "assigned"]
    /\ UNCHANGED <<providers, nackCount, publishedAt, lastAccess,
                   gcRoots, packs, time>>

\* Replicator claims the object (lease)
ClaimReplica(object, replicator) ==
    /\ replicaState[object, replicator] = "assigned"
    /\ replicaState' = [replicaState EXCEPT ![object, replicator] = "claiming"]
    /\ UNCHANGED <<providers, nackCount, publishedAt, lastAccess,
                   gcRoots, packs, time>>

\* Replicator successfully downloads the object
ReplicaSuccess(object, replicator) ==
    /\ replicaState[object, replicator] = "claiming"
    /\ replicaState' = [replicaState EXCEPT ![object, replicator] = "success"]
    /\ providers' = [providers EXCEPT ![object] = @ \union {replicator}]
    /\ UNCHANGED <<nackCount, publishedAt, lastAccess, gcRoots, packs, time>>

\* Replicator nacks (cannot replicate)
ReplicaNack(object, replicator) ==
    /\ replicaState[object, replicator] = "claiming"
    /\ replicaState' = [replicaState EXCEPT ![object, replicator] = "nacked"]
    /\ nackCount' = [nackCount EXCEPT ![object, replicator] = @ + 1]
    /\ UNCHANGED <<providers, publishedAt, lastAccess, gcRoots, packs, time>>

\* Nack rate limiting: after 3 nacks, replicator is excluded
NackExclusion(object, replicator) ==
    /\ nackCount[object, replicator] >= 3
    /\ replicaState' = [replicaState EXCEPT ![object, replicator] = "none"]
    /\ UNCHANGED <<providers, nackCount, publishedAt, lastAccess,
                   gcRoots, packs, time>>

\* Rebalance: detect under-replicated object
Rebalance(object) ==
    /\ ProviderCount(object) < ReplicationFactor
    /\ object \in DOMAIN publishedAt
    \* Trigger re-assignment for the object
    /\ \E r \in Replicators :
        /\ replicaState[object, r] = "none"
        /\ r \notin providers[object]
        /\ replicaState' = [replicaState EXCEPT ![object, r] = "assigned"]
    /\ UNCHANGED <<providers, nackCount, publishedAt, lastAccess,
                   gcRoots, packs, time>>

\* ---- Garbage Collection ----

\* GC evicts an object (LRU, unpinned, past hold period)
GCEvict(object, peer) ==
    /\ peer \in providers[object]
    /\ ~IsPinned(object)
    /\ ~InHoldPeriod(object)
    /\ providers' = [providers EXCEPT ![object] = @ \ {peer}]
    /\ UNCHANGED <<replicaState, nackCount, publishedAt, lastAccess,
                   gcRoots, packs, time>>

\* Access an object (updates last access time)
AccessObject(object) ==
    /\ object \in DOMAIN publishedAt
    /\ lastAccess' = [lastAccess EXCEPT ![object] = time]
    /\ UNCHANGED <<providers, replicaState, nackCount, publishedAt,
                   gcRoots, packs, time>>

\* Add a FUSE view pin
AddPin(object) ==
    /\ gcRoots' = gcRoots \union {object}
    /\ UNCHANGED <<providers, replicaState, nackCount, publishedAt,
                   lastAccess, packs, time>>

\* Remove a FUSE view pin
RemovePin(object) ==
    /\ object \in gcRoots
    /\ object \notin PinnedObjects  \* Can't remove Statute pins
    /\ gcRoots' = gcRoots \ {object}
    /\ UNCHANGED <<providers, replicaState, nackCount, publishedAt,
                   lastAccess, packs, time>>

\* ---- Pack Compaction ----

\* Compaction: rewrite a pack, moving live chunks to new pack
CompactPack(packId) ==
    /\ packId \in DOMAIN packs
    /\ packs[packId].dead * 100 > packs[packId].live * 30  \* >30% dead space
    \* Create new pack with only live chunks
    /\ packs' = [packs EXCEPT ![packId] =
           [live |-> packs[packId].live, dead |-> 0]]
    /\ UNCHANGED <<providers, replicaState, nackCount, publishedAt,
                   lastAccess, gcRoots, time>>

\* ---- Time ----

Tick ==
    /\ time' = time + 1
    /\ time < MaxTime
    /\ UNCHANGED <<providers, replicaState, nackCount, publishedAt,
                   lastAccess, gcRoots, packs>>

\* ---- Purge ----

\* Purge request: best-effort removal (respects hold period)
PurgeObject(object) ==
    /\ ~IsPinned(object)
    /\ ~InHoldPeriod(object)
    /\ providers' = [providers EXCEPT ![object] = {}]
    /\ UNCHANGED <<replicaState, nackCount, publishedAt, lastAccess,
                   gcRoots, packs, time>>

\* ---- Next state ----

Next ==
    \/ \E o \in Objects, p \in Peers : PublishObject(o, p)
    \/ \E o \in Objects, r \in Replicators : AssignReplica(o, r)
    \/ \E o \in Objects, r \in Replicators : ClaimReplica(o, r)
    \/ \E o \in Objects, r \in Replicators : ReplicaSuccess(o, r)
    \/ \E o \in Objects, r \in Replicators : ReplicaNack(o, r)
    \/ \E o \in Objects, r \in Replicators : NackExclusion(o, r)
    \/ \E o \in Objects : Rebalance(o)
    \/ \E o \in Objects, p \in Peers : GCEvict(o, p)
    \/ \E o \in Objects : AccessObject(o)
    \/ \E o \in Objects : AddPin(o)
    \/ \E o \in Objects : RemovePin(o)
    \/ \E p \in DOMAIN packs : CompactPack(p)
    \/ \E o \in Objects : PurgeObject(o)
    \/ Tick

Spec == Init /\ [][Next]_vars

\* ---- Safety Properties ----

\* Pinned objects are NEVER evicted (no providers = evicted)
PinnedNeverEvicted ==
    \A o \in Objects :
        IsPinned(o) /\ o \in DOMAIN publishedAt =>
            ProviderCount(o) > 0

\* Objects in hold period are never evicted
HoldPeriodRespected ==
    \A o \in Objects :
        InHoldPeriod(o) =>
            ProviderCount(o) > 0

\* Compaction never reduces live chunk count
CompactionSafety ==
    \A p \in DOMAIN packs :
        packs'[p].live >= packs[p].live \/ p \notin DOMAIN packs'

\* Nack count never exceeds the limit without exclusion
NackBounded ==
    \A o \in Objects, r \in Replicators :
        nackCount[o, r] <= 3 \/ replicaState[o, r] = "none"

\* ---- Liveness Properties ----

\* Published objects eventually reach replication factor
ReplicationTarget ==
    \A o \in Objects :
        o \in DOMAIN publishedAt ~>
            ProviderCount(o) >= ReplicationFactor

\* Nack cascading terminates (doesn't nack forever)
NackTermination ==
    \A o \in Objects :
        (\E r \in Replicators : replicaState[o, r] = "nacked") ~>
            (\A r \in Replicators :
                replicaState[o, r] \in {"none", "success"})

\* ---- Model checking configuration ----
\* Use small instances for TLC:
\*   Objects = {obj1, obj2, obj3}
\*   Peers = {p1, p2, p3, p4}
\*   Replicators = {p1, p2, p3}
\*   ReplicationFactor = 2
\*   MaxTime = 10
\*   MinHoldDuration = 2
\*   PinnedObjects = {obj1}

====
