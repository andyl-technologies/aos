---- MODULE Jobs ----
\* AOS Job Claiming, Scheduling, and Execution Protocol
\*
\* This specification models the full job lifecycle including the
\* load-report-based scheduling algorithm, claim delay computation,
\* eligibility filtering, and three job types (BuildSpec, FetchSpec, RunSpec).
\*
\* References:
\*   - docs/design/p2p-v2/jobs.md
\*   - docs/design/p2p-v2/scheduling.md
\*   - docs/design/p2p-v2/load-reports.md
\*   - docs/design/p2p-v2/containers.md
\*
\* Built on: Network.tla (libp2p semantics)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Peers,               \* Set of all peer IDs
    Jobs,                \* Set of all job IDs
    MaxTime,             \* Maximum time step

    \* Job types
    BuildJobs,           \* Subset: deterministic builds (idempotent)
    FetchJobs,           \* Subset: FOD downloads (content-addressed, idempotent)
    RunJobs,             \* Subset: mutable containers (NOT idempotent)

    \* Per-peer config (from daemon cluster config)
    PeerSystem,          \* peer -> system string (e.g., "x86_64-linux")
    PeerFeatures,        \* peer -> set of feature strings
    PeerLabels,          \* peer -> set of label strings
    PeerTaints,          \* peer -> set of {key, effect} (NoSchedule or PreferNoSchedule)
    PeerMaxConcurrent,   \* peer -> max concurrent jobs

    \* Per-job requirements
    JobSystem,           \* job -> required system
    JobFeatures,         \* job -> required features (subset of peer's)
    JobLabels,           \* job -> required labels
    JobTolerations,      \* job -> set of tolerated taint keys
    JobDeadline,         \* job -> absolute deadline (time units)

    \* Scheduling parameters
    HeartbeatTTL,        \* Liveness heartbeat TTL
    ReservationTTL,      \* Reservation token validity window
    MaxFailuresBeforeExclusion,  \* Max failures before peer is excluded from job (default 3)
    AutoStartTimeout     \* Time after claim before auto-start without creator

ASSUME BuildJobs \union FetchJobs \union RunJobs = Jobs
ASSUME BuildJobs \intersect FetchJobs = {}
ASSUME BuildJobs \intersect RunJobs = {}
ASSUME FetchJobs \intersect RunJobs = {}

VARIABLES
    \* Job lifecycle
    jobState,            \* job -> state
    jobClaimer,          \* job -> peer (or "none")
    jobExecutor,         \* job -> peer (or "none")
    jobOutput,           \* job -> output hash (or "none")
    jobPostedAt,         \* job -> time posted

    \* Claim protocol
    claimTimers,         \* Set of {job, peer, fires_at} — pending claim timers
    claims,              \* Set of {job, peer, claimed_at} — published claims
    jobClaimedAt,        \* job -> time when claimed (for auto-start timeout)

    \* Load reports
    peerLoad,            \* peer -> {cpu, memory, jobs_running, jobs_claimed, updated_at}
    loadTable,           \* peer -> (peer -> load_record) — each peer's view of others

    \* Affinity
    localStore,          \* peer -> set of store hashes held locally
    jobInputClosure,     \* job -> set of store hashes needed

    \* Failure history
    failureHistory,      \* peer -> (job -> failure_count)

    \* Reservations
    reservations,        \* Set of {builder, creator, job, valid_until}

    \* Heartbeat
    lastHeartbeat,       \* job -> time of last heartbeat

    \* Network
    partitions,          \* Set of {p1, p2} pairs

    \* Time
    time                 \* Global logical clock

vars == <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
          claimTimers, claims, jobClaimedAt, peerLoad, loadTable, localStore,
          jobInputClosure, failureHistory, reservations, lastHeartbeat,
          partitions, time>>

States == {"none", "posted", "claimed", "starting", "running",
           "exited", "errored", "cancelled"}

\* ---- Helper operators ----

Max(a, b) == IF a >= b THEN a ELSE b

CanCommunicate(p1, p2) == {p1, p2} \notin partitions

\* ---- Eligibility ----

\* Full eligibility check: all hard filters must pass
IsEligible(peer, job) ==
    /\ PeerSystem[peer] = JobSystem[job]                          \* System match
    /\ JobFeatures[job] \subseteq PeerFeatures[peer]              \* Features match
    /\ JobLabels[job] \subseteq PeerLabels[peer]                  \* Labels match
    /\ \A taint \in PeerTaints[peer] :                            \* Taint toleration
        taint.effect # "NoSchedule" \/ taint.key \in JobTolerations[job]
    /\ peerLoad[peer].jobs_running + peerLoad[peer].jobs_claimed  \* Capacity
        < PeerMaxConcurrent[peer]
    /\ JobDeadline[job] > time                                    \* Deadline not passed
    /\ failureHistory[peer][job] < MaxFailuresBeforeExclusion     \* Failure avoidance

\* ---- Claim Delay ----

\* Claim delay computation (discretized for model checking).
\*
\* Real formula:
\*   delay = (load_rank_delay - affinity_bonus + confidence_penalty
\*            + taint_penalty) * urgency + failure_penalty
\*
\* load_rank_delay (50-500ms):  rank among eligible peers by CPU load
\*     Uses conservative self-estimate, optimistic view of others.
\* affinity_bonus (0-200ms):    fraction of input closure already local
\* confidence_penalty (0-200ms): staleness of load data
\* taint_penalty (0 or 200ms):  PreferNoSchedule taints
\* urgency (0.5-1.0):           deadline proximity
\* failure_penalty (0-2000ms):  past failures on this derivation
\*
\* Here we map to discrete time units (1 unit ~ 50ms).

ClaimDelay(peer, job) ==
    LET
        \* --- Load rank delay (1-10 units) ---
        \* Conservative: treat own load as +1 (will be running this job)
        myLoad == peerLoad[peer].cpu + 1
        eligibleOthers == {p \in Peers : p # peer /\ IsEligible(p, job)}
        \* Optimistic: use loadTable view of others (may be stale/low)
        betterThanMe == Cardinality({p \in eligibleOthers :
            loadTable[peer][p].cpu < myLoad})
        totalEligible == Cardinality(eligibleOthers) + 1  \* include self
        rank == IF totalEligible > 1
                THEN (betterThanMe * 9) \div (totalEligible - 1)
                ELSE 0  \* 0-9 scale
        loadRankDelay == 1 + rank  \* 1-10 units

        \* --- Affinity bonus (0-4 units) ---
        closure == jobInputClosure[job]
        closureSize == Cardinality(closure)
        localHits == Cardinality(closure \intersect localStore[peer])
        affinityBonus == IF closureSize > 0
                         THEN (localHits * 4) \div closureSize
                         ELSE 0

        \* --- Confidence penalty (0-4 units) ---
        \* Staleness of our own load report
        myDataAge == time - peerLoad[peer].updated_at
        confidencePenalty == IF myDataAge > 5 THEN 4
                           ELSE IF myDataAge > 2 THEN 2
                           ELSE 0

        \* --- Taint penalty (0 or 4 units) ---
        hasSoftTaint == \E t \in PeerTaints[peer] :
            t.effect = "PreferNoSchedule" /\ t.key \in JobTolerations[job]
        taintPenalty == IF hasSoftTaint THEN 4 ELSE 0

        \* --- Urgency multiplier (discretized) ---
        \* Closer to deadline -> lower multiplier (faster claim)
        timeToDeadline == JobDeadline[job] - time
        \* Map: <=2 units left -> urgency 1 (half delay), else -> 2 (full delay)
        urgencyFactor == IF timeToDeadline <= 2 THEN 1 ELSE 2

        \* --- Failure penalty (0-20 units) ---
        failures == failureHistory[peer][job]
        failurePenalty == IF failures > 4 THEN 20
                         ELSE failures * 4

        \* --- Combined ---
        baseDelay == loadRankDelay - affinityBonus + confidencePenalty + taintPenalty
        scaledDelay == (Max(baseDelay, 1) * urgencyFactor) \div 2
    IN
        Max(scaledDelay + failurePenalty, 1)  \* Always >= 1 (safety property)

\* ---- Initial state ----

Init ==
    /\ jobState = [j \in Jobs |-> "none"]
    /\ jobClaimer = [j \in Jobs |-> "none"]
    /\ jobExecutor = [j \in Jobs |-> "none"]
    /\ jobOutput = [j \in Jobs |-> "none"]
    /\ jobPostedAt = [j \in Jobs |-> 0]
    /\ claimTimers = {}
    /\ claims = {}
    /\ jobClaimedAt = [j \in Jobs |-> 0]
    /\ peerLoad = [p \in Peers |->
           [cpu |-> 0, memory |-> 0, jobs_running |-> 0,
            jobs_claimed |-> 0, updated_at |-> 0]]
    /\ loadTable = [p \in Peers |->
           [q \in Peers |-> [cpu |-> 0, memory |-> 0, updated_at |-> 0]]]
    /\ localStore = [p \in Peers |-> {}]
    /\ jobInputClosure = [j \in Jobs |-> {}]
    /\ failureHistory = [p \in Peers |-> [j \in Jobs |-> 0]]
    /\ reservations = {}
    /\ lastHeartbeat = [j \in Jobs |-> 0]
    /\ partitions = {}
    /\ time = 0

\* ---- Load Report Actions ----

\* Peer publishes its load report via gossipsub.
\* CPU load is approximated by jobs_running (discretized).
PublishLoadReport(peer) ==
    /\ peerLoad' = [peerLoad EXCEPT ![peer] =
           [cpu |-> peerLoad[peer].jobs_running,
            memory |-> peerLoad[peer].memory,
            jobs_running |-> peerLoad[peer].jobs_running,
            jobs_claimed |-> peerLoad[peer].jobs_claimed,
            updated_at |-> time]]
    /\ UNCHANGED <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, loadTable, localStore,
                   jobInputClosure, failureHistory, reservations, lastHeartbeat,
                   partitions, time>>

\* Peer receives another peer's load report (gossipsub delivery).
\* Updates its local load table. Staleness is tracked via updated_at.
ReceiveLoadReport(receiver, sender) ==
    /\ receiver # sender
    /\ CanCommunicate(receiver, sender)
    /\ loadTable' = [loadTable EXCEPT ![receiver][sender] =
           [cpu |-> peerLoad[sender].cpu,
            memory |-> peerLoad[sender].memory,
            updated_at |-> peerLoad[sender].updated_at]]
    /\ UNCHANGED <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, peerLoad, localStore,
                   jobInputClosure, failureHistory, reservations, lastHeartbeat,
                   partitions, time>>

\* ---- Job Lifecycle ----

\* Post a new job (published to gossipsub topic)
PostJob(job) ==
    /\ jobState[job] = "none"
    /\ jobState' = [jobState EXCEPT ![job] = "posted"]
    /\ jobPostedAt' = [jobPostedAt EXCEPT ![job] = time]
    /\ UNCHANGED <<jobClaimer, jobExecutor, jobOutput, claimTimers, claims,
                   jobClaimedAt, peerLoad, loadTable, localStore, jobInputClosure,
                   failureHistory, reservations, lastHeartbeat, partitions, time>>

\* Eligible peer sets a claim timer (delayed by ClaimDelay).
\* The peer waits this duration before publishing its claim to gossipsub.
SetClaimTimer(job, peer) ==
    /\ jobState[job] = "posted"
    /\ IsEligible(peer, job)
    /\ ~\E t \in claimTimers : t.job = job /\ t.peer = peer  \* No existing timer
    /\ ~\E c \in claims : c.job = job                         \* No existing claim
    /\ LET delay == ClaimDelay(peer, job)
       IN claimTimers' = claimTimers \union
              {[job |-> job, peer |-> peer, fires_at |-> time + delay]}
    /\ UNCHANGED <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claims, jobClaimedAt, peerLoad, loadTable, localStore,
                   jobInputClosure, failureHistory, reservations, lastHeartbeat,
                   partitions, time>>

\* Claim timer fires: peer publishes claim via gossipsub.
\* Tie-breaking: if two claims arrive at the same time, lowest peer ID wins.
\* (Modeled here by checking no prior claim exists.)
FireClaimTimer(timer) ==
    /\ timer \in claimTimers
    /\ time >= timer.fires_at
    /\ jobState[timer.job] = "posted"              \* Job still unclaimed
    /\ ~\E c \in claims : c.job = timer.job        \* No one else claimed yet
    /\ claims' = claims \union
           {[job |-> timer.job, peer |-> timer.peer, claimed_at |-> time]}
    /\ jobState' = [jobState EXCEPT ![timer.job] = "claimed"]
    /\ jobClaimer' = [jobClaimer EXCEPT ![timer.job] = timer.peer]
    /\ peerLoad' = [peerLoad EXCEPT ![timer.peer].jobs_claimed = @ + 1]
    /\ jobClaimedAt' = [jobClaimedAt EXCEPT ![timer.job] = time]
    /\ claimTimers' = claimTimers \ {timer}
    /\ UNCHANGED <<jobExecutor, jobOutput, jobPostedAt, loadTable,
                   localStore, jobInputClosure, failureHistory,
                   reservations, lastHeartbeat, partitions, time>>

\* Cancel claim timer: peer sees another claim arrive via gossipsub
\* before its own timer fires.
CancelClaimTimer(timer) ==
    /\ timer \in claimTimers
    /\ \E c \in claims : c.job = timer.job         \* Someone already claimed
    /\ claimTimers' = claimTimers \ {timer}
    /\ UNCHANGED <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claims, jobClaimedAt, peerLoad, loadTable, localStore,
                   jobInputClosure, failureHistory, reservations, lastHeartbeat,
                   partitions, time>>

\* Use a reservation token to skip the claim delay.
\* Reservation tokens are offered after job exit, valid for ReservationTTL,
\* and single-use.
UseReservation(job, peer) ==
    /\ jobState[job] = "posted"
    /\ \E r \in reservations :
        /\ r.builder = peer
        /\ r.job = job
        /\ r.valid_until > time
    \* Consume the token (remove from set = single-use)
    /\ LET r == CHOOSE r \in reservations :
               r.builder = peer /\ r.job = job /\ r.valid_until > time
       IN reservations' = reservations \ {r}
    /\ jobState' = [jobState EXCEPT ![job] = "claimed"]
    /\ jobClaimer' = [jobClaimer EXCEPT ![job] = peer]
    /\ peerLoad' = [peerLoad EXCEPT ![peer].jobs_claimed = @ + 1]
    /\ jobClaimedAt' = [jobClaimedAt EXCEPT ![job] = time]
    /\ UNCHANGED <<jobExecutor, jobOutput, jobPostedAt, claimTimers, claims,
                   loadTable, localStore, jobInputClosure, failureHistory,
                   lastHeartbeat, partitions, time>>

\* Creator issues start UCAN to the claimant (two-phase handshake)
StartJob(job) ==
    /\ jobState[job] = "claimed"
    /\ jobClaimer[job] # "none"
    /\ jobState' = [jobState EXCEPT ![job] = "starting"]
    /\ jobExecutor' = [jobExecutor EXCEPT ![job] = jobClaimer[job]]
    /\ UNCHANGED <<jobClaimer, jobOutput, jobPostedAt, claimTimers, claims,
                   jobClaimedAt, peerLoad, loadTable, localStore, jobInputClosure,
                   failureHistory, reservations, lastHeartbeat, partitions, time>>

\* Job transitions to running (container launched, heartbeat begins)
JobRunning(job) ==
    /\ jobState[job] = "starting"
    /\ jobState' = [jobState EXCEPT ![job] = "running"]
    /\ peerLoad' = [peerLoad EXCEPT
           ![jobExecutor[job]].jobs_running = @ + 1,
           ![jobExecutor[job]].jobs_claimed = @ - 1]
    /\ lastHeartbeat' = [lastHeartbeat EXCEPT ![job] = time]
    /\ UNCHANGED <<jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, loadTable, localStore,
                   jobInputClosure, failureHistory, reservations,
                   partitions, time>>

\* Job executor publishes heartbeat to DHT (refreshes TTL)
RefreshHeartbeat(job) ==
    /\ jobState[job] = "running"
    /\ lastHeartbeat' = [lastHeartbeat EXCEPT ![job] = time]
    /\ UNCHANGED <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, peerLoad, loadTable,
                   localStore, jobInputClosure, failureHistory, reservations,
                   partitions, time>>

\* Job exits successfully.
\* BuildSpec/FetchSpec always produce "out1" (deterministic/content-addressed).
\* RunSpec may produce varying outputs (modeled as "out1" here for simplicity).
JobExit(job, output) ==
    /\ jobState[job] = "running"
    /\ jobState' = [jobState EXCEPT ![job] = "exited"]
    /\ jobOutput' = [jobOutput EXCEPT ![job] = output]
    /\ peerLoad' = [peerLoad EXCEPT ![jobExecutor[job]].jobs_running = @ - 1]
    \* Add output to executor's local store
    /\ localStore' = [localStore EXCEPT ![jobExecutor[job]] = @ \union {output}]
    /\ UNCHANGED <<jobClaimer, jobExecutor, jobPostedAt, claimTimers, claims,
                   jobClaimedAt, loadTable, jobInputClosure, failureHistory,
                   reservations, lastHeartbeat, partitions, time>>

\* Job errors (build failure, OOM, etc.)
JobError(job) ==
    /\ jobState[job] = "running"
    /\ jobState' = [jobState EXCEPT ![job] = "errored"]
    /\ peerLoad' = [peerLoad EXCEPT ![jobExecutor[job]].jobs_running = @ - 1]
    /\ failureHistory' = [failureHistory EXCEPT ![jobExecutor[job]][job] = @ + 1]
    /\ UNCHANGED <<jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, loadTable, localStore,
                   jobInputClosure, reservations, lastHeartbeat,
                   partitions, time>>

\* Cancel a job (user-initiated or deadline expiry)
CancelJob(job) ==
    /\ jobState[job] \in {"posted", "claimed", "starting", "running"}
    /\ jobState' = [jobState EXCEPT ![job] = "cancelled"]
    /\ IF jobState[job] = "running"
       THEN peerLoad' = [peerLoad EXCEPT ![jobExecutor[job]].jobs_running = @ - 1]
       ELSE IF jobState[job] \in {"claimed", "starting"}
            THEN peerLoad' = [peerLoad EXCEPT ![jobClaimer[job]].jobs_claimed = @ - 1]
            ELSE peerLoad' = peerLoad
    /\ UNCHANGED <<jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, loadTable, localStore,
                   jobInputClosure, failureHistory, reservations,
                   lastHeartbeat, partitions, time>>

\* DHT heartbeat expiry: TTL lapses, job considered crashed.
\* The job becomes reclaimable (transitions to errored, can be re-posted).
HeartbeatExpiry(job) ==
    /\ jobState[job] = "running"
    /\ time - lastHeartbeat[job] > HeartbeatTTL
    /\ jobState' = [jobState EXCEPT ![job] = "errored"]
    /\ peerLoad' = [peerLoad EXCEPT ![jobExecutor[job]].jobs_running = @ - 1]
    /\ failureHistory' = [failureHistory EXCEPT ![jobExecutor[job]][job] = @ + 1]
    /\ UNCHANGED <<jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, loadTable, localStore,
                   jobInputClosure, reservations, lastHeartbeat,
                   partitions, time>>

\* Reclaim an errored job (re-post for scheduling)
ReclaimJob(job) ==
    /\ jobState[job] = "errored"
    /\ \E p \in Peers : IsEligible(p, job)         \* At least one eligible peer
    /\ jobState' = [jobState EXCEPT ![job] = "posted"]
    /\ jobClaimer' = [jobClaimer EXCEPT ![job] = "none"]
    /\ jobExecutor' = [jobExecutor EXCEPT ![job] = "none"]
    /\ jobPostedAt' = [jobPostedAt EXCEPT ![job] = time]
    /\ lastHeartbeat' = [lastHeartbeat EXCEPT ![job] = 0]
    /\ jobClaimedAt' = [jobClaimedAt EXCEPT ![job] = 0]
    /\ UNCHANGED <<jobOutput, claimTimers, claims, peerLoad, loadTable,
                   localStore, jobInputClosure, failureHistory, reservations,
                   partitions, time>>

\* Offer reservation token after job exit.
\* Valid for ReservationTTL time units, single-use.
OfferReservation(job, nextJob) ==
    /\ jobState[job] = "exited"
    /\ jobExecutor[job] # "none"
    /\ reservations' = reservations \union
           {[builder |-> jobExecutor[job], creator |-> jobExecutor[job],
             job |-> nextJob, valid_until |-> time + ReservationTTL]}
    /\ UNCHANGED <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, peerLoad, loadTable,
                   localStore, jobInputClosure, failureHistory, lastHeartbeat,
                   partitions, time>>

\* NoExecute taint eviction: a running job is evicted when its peer
\* acquires a NoExecute taint that the job does not tolerate.
EvictForTaint(job, peer) ==
    /\ jobState[job] = "running"
    /\ jobExecutor[job] = peer
    /\ \E taint \in PeerTaints[peer] :
        /\ taint.effect = "NoExecute"
        /\ taint.key \notin JobTolerations[job]
    /\ jobState' = [jobState EXCEPT ![job] = "errored"]
    /\ peerLoad' = [peerLoad EXCEPT ![peer].jobs_running = @ - 1]
    /\ failureHistory' = [failureHistory EXCEPT ![peer][job] = @ + 1]
    /\ UNCHANGED <<jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, loadTable, localStore,
                   jobInputClosure, reservations, lastHeartbeat,
                   partitions, time>>

\* Creator offline fallback: if a claimed job has been waiting for the
\* creator's start UCAN longer than AutoStartTimeout, the claimant
\* auto-starts without the creator's explicit handshake.
AutoStartOnTimeout(job) ==
    /\ jobState[job] = "claimed"
    /\ jobClaimer[job] # "none"
    /\ time - jobClaimedAt[job] > AutoStartTimeout
    /\ jobState' = [jobState EXCEPT ![job] = "starting"]
    /\ jobExecutor' = [jobExecutor EXCEPT ![job] = jobClaimer[job]]
    /\ UNCHANGED <<jobClaimer, jobOutput, jobPostedAt, claimTimers, claims,
                   jobClaimedAt, peerLoad, loadTable, localStore, jobInputClosure,
                   failureHistory, reservations, lastHeartbeat, partitions, time>>

\* ---- Split-brain behavior ----

\* During a network partition, a second peer may also claim a job.
\* For BuildSpec/FetchSpec this is safe: deterministic/content-addressed
\*   builds produce identical output (duplicate work, no correctness issue).
\* For RunSpec this is UNSAFE: mutable containers are not idempotent,
\*   so duplicate execution can cause split-brain service conflicts.
\*   This is a documented limitation — operators must handle via fencing.
SplitBrainClaim(job, peer) ==
    /\ jobState[job] \in {"claimed", "starting", "running"}
    /\ peer # jobClaimer[job]
    /\ IsEligible(peer, job)
    /\ ~CanCommunicate(peer, jobClaimer[job])       \* Partitioned from claimer
    \* This action is a no-op on state: it documents that the scenario
    \* is reachable. The safety properties below distinguish by job type.
    /\ UNCHANGED vars

\* ---- Network model ----

\* Network partition (models gossipsub/DHT message delivery failure)
CreatePartition(p1, p2) ==
    /\ p1 # p2
    /\ {p1, p2} \notin partitions
    /\ partitions' = partitions \union {{p1, p2}}
    /\ UNCHANGED <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, peerLoad, loadTable,
                   localStore, jobInputClosure, failureHistory, reservations,
                   lastHeartbeat, time>>

\* Partition heals (connectivity restored)
HealPartition(p1, p2) ==
    /\ {p1, p2} \in partitions
    /\ partitions' = partitions \ {{p1, p2}}
    /\ UNCHANGED <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, peerLoad, loadTable,
                   localStore, jobInputClosure, failureHistory, reservations,
                   lastHeartbeat, time>>

\* Global clock tick
Tick ==
    /\ time' = time + 1
    /\ time < MaxTime
    /\ UNCHANGED <<jobState, jobClaimer, jobExecutor, jobOutput, jobPostedAt,
                   claimTimers, claims, jobClaimedAt, peerLoad, loadTable,
                   localStore, jobInputClosure, failureHistory, reservations,
                   lastHeartbeat, partitions>>

\* ---- Next state ----

Next ==
    \/ \E j \in Jobs : PostJob(j)
    \/ \E j \in Jobs, p \in Peers : SetClaimTimer(j, p)
    \/ \E t \in claimTimers : FireClaimTimer(t)
    \/ \E t \in claimTimers : CancelClaimTimer(t)
    \/ \E j \in Jobs, p \in Peers : UseReservation(j, p)
    \/ \E j \in Jobs : StartJob(j)
    \/ \E j \in Jobs : JobRunning(j)
    \/ \E j \in Jobs, o \in {"out1"} : JobExit(j, o)
    \/ \E j \in Jobs : JobError(j)
    \/ \E j \in Jobs : CancelJob(j)
    \/ \E j \in Jobs : RefreshHeartbeat(j)
    \/ \E j \in Jobs : HeartbeatExpiry(j)
    \/ \E j \in Jobs, p \in Peers : EvictForTaint(j, p)
    \/ \E j \in Jobs : AutoStartOnTimeout(j)
    \/ \E j \in Jobs : ReclaimJob(j)
    \/ \E j1 \in Jobs, j2 \in Jobs : OfferReservation(j1, j2)
    \/ \E p \in Peers : PublishLoadReport(p)
    \/ \E p1 \in Peers, p2 \in Peers : ReceiveLoadReport(p1, p2)
    \/ \E j \in Jobs, p \in Peers : SplitBrainClaim(j, p)
    \/ \E p1 \in Peers, p2 \in Peers : CreatePartition(p1, p2)
    \/ \E p1 \in Peers, p2 \in Peers : HealPartition(p1, p2)
    \/ Tick

Spec == Init /\ [][Next]_vars /\ WF_vars(Tick)

\* ---- Safety Properties ----

\* S1: Eligibility is sound — only eligible peers claim jobs
EligibilitySafety ==
    \A j \in Jobs :
        jobClaimer[j] # "none" => IsEligible(jobClaimer[j], j)

\* S2: BuildSpec/FetchSpec idempotency — all executions produce identical output
\* (deterministic builds from .drv, content-addressed fetches)
BuildFetchIdempotency ==
    \A j \in BuildJobs \union FetchJobs :
        jobOutput[j] # "none" => jobOutput[j] = "out1"

\* S3: Claim delay is always positive (>= 1 time unit, ~10ms real)
PositiveDelay ==
    \A t \in claimTimers : t.fires_at > time

\* S4: Capacity respected — no peer runs more than max_concurrent
CapacityRespected ==
    \A p \in Peers :
        peerLoad[p].jobs_running <= PeerMaxConcurrent[p]

\* S5: Reservation tokens are single-use
\* (Enforced structurally: UseReservation removes from set)
ReservationSingleUse ==
    \A r1 \in reservations : \A r2 \in reservations :
        (r1.builder = r2.builder /\ r1.job = r2.job /\
         r1.valid_until = r2.valid_until) => r1 = r2

\* S6: Heartbeat expiry correctly detects crashes
\* (If heartbeat has lapsed and job is still "running", HeartbeatExpiry is enabled)
HeartbeatSafety ==
    \A j \in Jobs :
        (jobState[j] = "running" /\ time - lastHeartbeat[j] > HeartbeatTTL)
        => ENABLED HeartbeatExpiry(j)

\* S7: Every job is in a valid state
ValidStates ==
    \A j \in Jobs : jobState[j] \in States

\* S8: Terminal states are absorbing (exited/cancelled cannot change)
\* Note: errored CAN transition back to posted via ReclaimJob
Terminality ==
    [][\A j \in Jobs :
        jobState[j] \in {"exited", "cancelled"} =>
            jobState'[j] = jobState[j]]_vars

\* RunSpec split-brain is a documented safety violation:
\* two peers may execute the same RunSpec job concurrently during partition
RunSpecSplitBrainPossible ==
    \E j \in RunJobs :
        \E p1, p2 \in Peers :
            p1 # p2
            /\ jobExecutor[j] = p1
            /\ ~CanCommunicate(p1, p2)
            \* This state IS reachable — documented limitation

\* ---- Liveness Properties ----

\* L1: Every posted job with eligible peers is eventually claimed
\*     (or cancelled/errored)
JobEventuallyClaimed ==
    \A j \in Jobs :
        (jobState[j] = "posted" /\ \E p \in Peers : IsEligible(p, j))
        ~> jobState[j] \in {"claimed", "starting", "running",
                            "exited", "errored", "cancelled"}

\* L2: Load reports eventually converge (bounded staleness)
\*     Under fair scheduling, every peer pair eventually has fresh data
LoadConvergence ==
    \A p \in Peers, q \in Peers :
        p # q => <>(time - loadTable[p][q].updated_at < 5)

\* L3: Failed jobs are eventually reclaimed via heartbeat expiry
\*     If a job is running and heartbeat expires, it eventually errors
FailedJobReclaim ==
    \A j \in Jobs :
        (jobState[j] = "running" /\ time - lastHeartbeat[j] > HeartbeatTTL)
        ~> jobState[j] # "running"

\* ---- Model checking configuration ----
\* Use small instances for TLC:
\*   Peers = {p1, p2, p3}
\*   Jobs = {j1, j2}
\*   BuildJobs = {j1}
\*   FetchJobs = {}
\*   RunJobs = {j2}
\*   PeerSystem = [p \in Peers |-> "x86_64"]
\*   PeerFeatures = [p \in Peers |-> {"kvm"}]
\*   PeerLabels = [p \in Peers |-> {}]
\*   PeerTaints = [p \in Peers |-> {}]
\*   PeerMaxConcurrent = [p \in Peers |-> 2]
\*   JobSystem = [j \in Jobs |-> "x86_64"]
\*   JobFeatures = [j \in Jobs |-> {"kvm"}]
\*   JobLabels = [j \in Jobs |-> {}]
\*   JobTolerations = [j \in Jobs |-> {}]
\*   JobDeadline = [j \in Jobs |-> 20]
\*   HeartbeatTTL = 5
\*   ReservationTTL = 3
\*   MaxFailuresBeforeExclusion = 3
\*   AutoStartTimeout = 5
\*   MaxTime = 15

====
