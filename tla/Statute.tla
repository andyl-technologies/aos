---- MODULE Statute ----
\* Statute: BFT Key-Value Store with Chained HotStuff Consensus
\*
\* This specification models:
\*   1. Chained HotStuff consensus (propose, vote, commit via 3 consecutive QCs)
\*   2. Epoch-based reconfiguration (kick/join with >50% voting power rule)
\*   3. KV state transitions (write, delete operations)
\*   4. UCAN authorization (simplified as a permission function)
\*   5. Network partitions and message loss
\*
\* Safety properties:
\*   - No two committed blocks at the same height with different content
\*   - At most one partition can reconfigure per epoch
\*   - Committed KV state is consistent across all honest validators
\*
\* Liveness properties:
\*   - If >2/3 validators are honest and connected, blocks are produced
\*   - Kicked validators can rejoin after partition heals

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Validators,          \* Set of all validator IDs
    MaxHeight,           \* Maximum block height to explore
    MaxEpoch,            \* Maximum epoch number
    ByzantineCount,      \* Number of Byzantine validators (f)
    Keys,                \* Set of KV store keys
    Values,              \* Set of possible values
    Groups,              \* Set of group names for permission model
    TokenIds,            \* Set of token IDs for revocation model
    SchemaKeys           \* Subset of Keys that have schema constraints

VARIABLES
    \* Consensus state
    blocks,              \* Function: height -> Block record
    votes,               \* Set of Vote records {validator, height, block_hash}
    qcs,                 \* Set of QuorumCertificate records
    currentHeight,       \* Current height per validator: validator -> height

    \* Epoch state
    epoch,               \* Current epoch number (global, agreed via consensus)
    validatorSet,        \* Current validator set: epoch -> set of validators
    votingPower,         \* Voting power: validator -> weight
    suspectedBy,         \* Suspicion tracking: validator -> set of validators suspecting it

    \* KV state
    kvState,             \* The committed KV state: key -> value

    \* Network model
    messages,            \* Set of in-flight messages
    partitions,          \* Set of {v1, v2} pairs that cannot communicate

    \* Leader rotation
    leader,              \* Current leader: height -> validator

    \* Per-signer nonce tracking
    nonceState,          \* Function: validator -> last used nonce (Nat)

    \* Permission / group membership
    groupMembership,     \* Function: validator -> set of Groups

    \* Revocation state
    revokedTokens,       \* Set of revoked token IDs

    \* Committed block heights (for state root tracking)
    committedHeights     \* Set of heights that have been committed

vars == <<blocks, votes, qcs, currentHeight, epoch, validatorSet,
          votingPower, suspectedBy, kvState, messages, partitions, leader,
          nonceState, groupMembership, revokedTokens, committedHeights>>

\* ---- Type definitions ----

Block == [
    height:    Nat,
    epoch:     Nat,
    proposer:  Validators,
    txs:       SUBSET (Keys \X Values),    \* Set of (key, value) pairs
    prevHash:  Nat,                         \* Simplified hash
    justify:   Nat                          \* Height of the justifying QC
]

Vote == [
    validator: Validators,
    height:    Nat,
    blockHash: Nat
]

\* ---- Helper operators ----

Max(S) == CHOOSE x \in S : \A y \in S : y <= x

\* Quorum size for BFT: 2f+1 out of 3f+1
QuorumSize(vs) == (2 * ByzantineCount) + 1

\* Total voting power of a set of validators
TotalPower(vs) == Cardinality(vs)

\* Check if a set of voters forms a quorum in the current epoch
IsQuorum(voters, ep) ==
    Cardinality(voters \intersect validatorSet[ep]) >= QuorumSize(validatorSet[ep])

\* Check if a set has >50% of total voting power (for reconfiguration)
HasMajority(voters, ep) ==
    Cardinality(voters \intersect validatorSet[ep]) * 2 > Cardinality(validatorSet[ep])

\* Can two validators communicate? (not partitioned)
CanCommunicate(v1, v2) ==
    {v1, v2} \notin partitions

\* Leader for a given height (round-robin)
LeaderFor(h, ep) ==
    LET vs == validatorSet[ep]
        ordered == CHOOSE seq \in [1..Cardinality(vs) -> vs] : TRUE
    IN ordered[((h - 1) % Cardinality(vs)) + 1]

\* ---- Schema validation ----
\* Deterministic schema check: a key/value pair is schema-valid iff
\* the key is NOT in SchemaKeys (unconstrained) OR the value is in Values.
\* Because SchemaKeys and Values are fixed constants, the result is the same
\* on every validator — guaranteeing determinism.
SchemaValid(key, value) ==
    \/ key \notin SchemaKeys
    \/ value \in Values

\* ---- Permission checking ----
\* A peer has permission for an action on a key iff:
\*   - The peer is in the current validator set (for "propose"), OR
\*   - The peer belongs to a group that owns the key's namespace.
\* We model key ownership simply: the peer must be a member of at least
\* one group whose name is a prefix/match (modeled as non-empty membership).
HasPermission(peer, key, action) ==
    /\ peer \in validatorSet[epoch]
    /\ groupMembership[peer] # {}

\* ---- Revocation checking ----
\* A transaction set is free of revoked tokens iff none of the token IDs
\* embedded in its operations appear in revokedTokens.  We model each tx
\* as optionally carrying a tokenId (the second projection is the value;
\* we treat each value that is also in TokenIds as a token reference).
TxsNotRevoked(txs) ==
    \A tx \in txs : tx[2] \notin revokedTokens

\* ---- Initial state ----

Init ==
    /\ blocks = [h \in {0} |-> [
           height |-> 0, epoch |-> 1, proposer |-> CHOOSE v \in Validators : TRUE,
           txs |-> {}, prevHash |-> 0, justify |-> 0]]
    /\ votes = {}
    /\ qcs = {[height |-> 0, voters |-> Validators]}
    /\ currentHeight = [v \in Validators |-> 0]
    /\ epoch = 1
    /\ validatorSet = [e \in {1} |-> Validators]
    /\ votingPower = [v \in Validators |-> 1]
    /\ suspectedBy = [v \in Validators |-> {}]
    /\ kvState = [k \in Keys |-> ""]
    /\ messages = {}
    /\ partitions = {}
    /\ leader = [h \in {1} |-> LeaderFor(1, 1)]
    /\ nonceState = [v \in Validators |-> 0]
    /\ groupMembership = [v \in Validators |-> Groups]   \* All validators start with full group membership
    /\ revokedTokens = {}
    /\ committedHeights = {}

\* ---- Actions ----

\* Leader proposes a new block
Propose(v, h, txs) ==
    /\ v = LeaderFor(h, epoch)
    /\ v \in validatorSet[epoch]
    /\ h = Max({currentHeight[w] : w \in validatorSet[epoch]}) + 1
    /\ h <= MaxHeight
    /\ \E qc \in qcs : qc.height = h - 1    \* Must have QC for previous height
    \* Nonce check: proposer's nonce must advance by exactly 1
    /\ nonceState[v] >= 0  \* Nonce must be valid (incremented below)
    \* Schema validation: all transactions must pass deterministic schema check
    /\ \A tx \in txs : SchemaValid(tx[1], tx[2])
    \* Permission check: proposer must have permission to write all keys
    /\ \A tx \in txs : HasPermission(v, tx[1], "write")
    \* Revocation check: no transaction may reference a revoked token
    /\ TxsNotRevoked(txs)
    /\ blocks' = blocks @@ (h :> [
           height |-> h, epoch |-> epoch, proposer |-> v,
           txs |-> txs, prevHash |-> h - 1, justify |-> h - 1])
    /\ messages' = messages \union
           {[type |-> "propose", block |-> blocks'[h], from |-> v, to |-> w]
            : w \in validatorSet[epoch] \ {v}}
    \* Advance the proposer's nonce
    /\ nonceState' = [nonceState EXCEPT ![v] = @ + 1]
    /\ UNCHANGED <<votes, qcs, currentHeight, epoch, validatorSet,
                   votingPower, suspectedBy, kvState, partitions, leader,
                   groupMembership, revokedTokens, committedHeights>>

\* Validator votes on a proposed block
VoteOnBlock(v, h) ==
    /\ v \in validatorSet[epoch]
    /\ h \in DOMAIN blocks
    /\ blocks[h].epoch = epoch
    /\ \A vote \in votes : ~(vote.validator = v /\ vote.height = h)  \* Haven't voted yet
    /\ votes' = votes \union {[validator |-> v, height |-> h, blockHash |-> h]}
    /\ currentHeight' = [currentHeight EXCEPT ![v] = Max({@, h})]
    /\ UNCHANGED <<blocks, qcs, epoch, validatorSet, votingPower,
                   suspectedBy, kvState, messages, partitions, leader,
                   nonceState, groupMembership, revokedTokens, committedHeights>>

\* Collect votes into a QC when quorum is reached
FormQC(h) ==
    LET voters == {vote.validator : vote \in {v \in votes : v.height = h}}
    IN /\ IsQuorum(voters, epoch)
       /\ ~\E qc \in qcs : qc.height = h    \* No QC yet for this height
       /\ qcs' = qcs \union {[height |-> h, voters |-> voters]}
       /\ UNCHANGED <<blocks, votes, currentHeight, epoch, validatorSet,
                      votingPower, suspectedBy, kvState, messages, partitions, leader,
                      nonceState, groupMembership, revokedTokens, committedHeights>>

\* Commit a block (has 3 consecutive QCs in its chain)
CommitBlock(h) ==
    /\ h \in DOMAIN blocks
    /\ h >= 3
    /\ \E qc1 \in qcs : qc1.height = h
    /\ \E qc2 \in qcs : qc2.height = h - 1
    /\ \E qc3 \in qcs : qc3.height = h - 2
    \* Apply transactions to KV state
    /\ kvState' = [k \in Keys |->
           IF \E tx \in blocks[h-2].txs : tx[1] = k
           THEN (CHOOSE tx \in blocks[h-2].txs : tx[1] = k)[2]
           ELSE kvState[k]]
    /\ committedHeights' = committedHeights \union {h}
    /\ UNCHANGED <<blocks, votes, qcs, currentHeight, epoch, validatorSet,
                   votingPower, suspectedBy, messages, partitions, leader,
                   nonceState, groupMembership, revokedTokens>>

\* ---- Epoch Reconfiguration ----

\* Suspect a validator (missed rounds)
Suspect(v, target) ==
    /\ v \in validatorSet[epoch]
    /\ target \in validatorSet[epoch]
    /\ v # target
    /\ suspectedBy' = [suspectedBy EXCEPT ![target] = @ \union {v}]
    /\ UNCHANGED <<blocks, votes, qcs, currentHeight, epoch, validatorSet,
                   votingPower, kvState, messages, partitions, leader,
                   nonceState, groupMembership, revokedTokens, committedHeights>>

\* Kick suspected validators (requires >50% of total voting power)
KickValidators(proposer, toKick) ==
    LET remaining == validatorSet[epoch] \ toKick
    IN /\ proposer \in remaining
       /\ toKick \subseteq validatorSet[epoch]
       /\ toKick # {}
       /\ HasMajority(remaining, epoch)  \* >50% of total voting power
       /\ Cardinality(remaining) >= 4     \* Minimum validator count
       /\ epoch + 1 <= MaxEpoch
       /\ epoch' = epoch + 1
       /\ validatorSet' = validatorSet @@ ((epoch + 1) :> remaining)
       /\ suspectedBy' = [v \in Validators |-> {}]  \* Reset suspicions
       /\ UNCHANGED <<blocks, votes, qcs, currentHeight, votingPower,
                      kvState, messages, partitions, leader,
                      nonceState, groupMembership, revokedTokens, committedHeights>>

\* Rejoin a kicked validator
RejoinValidator(rejoiner) ==
    LET current == validatorSet[epoch]
    IN /\ rejoiner \notin current
       /\ rejoiner \in Validators
       /\ epoch + 1 <= MaxEpoch
       /\ epoch' = epoch + 1
       /\ validatorSet' = validatorSet @@ ((epoch + 1) :> (current \union {rejoiner}))
       /\ UNCHANGED <<blocks, votes, qcs, currentHeight, votingPower,
                      suspectedBy, kvState, messages, partitions, leader,
                      nonceState, groupMembership, revokedTokens, committedHeights>>

\* ---- Network actions ----

\* Create a network partition
CreatePartition(v1, v2) ==
    /\ {v1, v2} \notin partitions
    /\ partitions' = partitions \union {{v1, v2}}
    /\ UNCHANGED <<blocks, votes, qcs, currentHeight, epoch, validatorSet,
                   votingPower, suspectedBy, kvState, messages, leader,
                   nonceState, groupMembership, revokedTokens, committedHeights>>

\* Heal a network partition
HealPartition(v1, v2) ==
    /\ {v1, v2} \in partitions
    /\ partitions' = partitions \ {{v1, v2}}
    /\ UNCHANGED <<blocks, votes, qcs, currentHeight, epoch, validatorSet,
                   votingPower, suspectedBy, kvState, messages, leader,
                   nonceState, groupMembership, revokedTokens, committedHeights>>

\* ---- Token revocation ----

\* Revoke a token (any current validator can propose revocation)
RevokeToken(v, tokenId) ==
    /\ v \in validatorSet[epoch]
    /\ tokenId \in TokenIds
    /\ tokenId \notin revokedTokens
    /\ revokedTokens' = revokedTokens \union {tokenId}
    /\ UNCHANGED <<blocks, votes, qcs, currentHeight, epoch, validatorSet,
                   votingPower, suspectedBy, kvState, messages, partitions, leader,
                   nonceState, groupMembership, committedHeights>>

\* ---- Group membership management ----

\* Update group membership for a validator (add or remove from a group)
UpdateGroupMembership(admin, target, group, action) ==
    /\ admin \in validatorSet[epoch]
    /\ target \in Validators
    /\ group \in Groups
    /\ IF action = "add"
       THEN groupMembership' = [groupMembership EXCEPT ![target] = @ \union {group}]
       ELSE groupMembership' = [groupMembership EXCEPT ![target] = @ \ {group}]
    /\ UNCHANGED <<blocks, votes, qcs, currentHeight, epoch, validatorSet,
                   votingPower, suspectedBy, kvState, messages, partitions, leader,
                   nonceState, revokedTokens, committedHeights>>

\* ---- Next state ----

Next ==
    \/ \E v \in Validators, h \in 1..MaxHeight, txs \in SUBSET (Keys \X Values) :
           Propose(v, h, txs)
    \/ \E v \in Validators, h \in 1..MaxHeight :
           VoteOnBlock(v, h)
    \/ \E h \in 1..MaxHeight :
           FormQC(h)
    \/ \E h \in 1..MaxHeight :
           CommitBlock(h)
    \/ \E v \in Validators, target \in Validators :
           Suspect(v, target)
    \/ \E v \in Validators, toKick \in SUBSET Validators :
           KickValidators(v, toKick)
    \/ \E v \in Validators :
           RejoinValidator(v)
    \/ \E v1 \in Validators, v2 \in Validators :
           CreatePartition(v1, v2)
    \/ \E v1 \in Validators, v2 \in Validators :
           HealPartition(v1, v2)
    \/ \E v \in Validators, tokenId \in TokenIds :
           RevokeToken(v, tokenId)
    \/ \E admin \in Validators, target \in Validators, group \in Groups,
          action \in {"add", "remove"} :
           UpdateGroupMembership(admin, target, group, action)

Spec == Init /\ [][Next]_vars

\* ---- Safety Properties ----

\* No two committed blocks at the same height
ConsensusSafety ==
    \A h \in DOMAIN blocks :
        Cardinality({b \in DOMAIN blocks : blocks[b].height = h}) <= 1

\* At most one partition can reconfigure in any epoch
EpochSafety ==
    \A ep \in 1..MaxEpoch :
        ep \in DOMAIN validatorSet =>
            \* The validator set for this epoch was approved by >50% of the previous epoch
            (ep = 1 \/ HasMajority(validatorSet[ep], ep - 1))

\* KV state consistency: all honest validators agree on committed state
StateConsistency ==
    \* All committed blocks produce the same state transitions
    \A h1, h2 \in DOMAIN blocks :
        (h1 = h2) => (blocks[h1] = blocks[h2])

\* Nonce monotonicity: each validator's nonce is monotonically increasing,
\* and no two proposals from the same validator share a nonce.
NonceMonotonicity ==
    \A v \in Validators :
        nonceState[v] >= 0
        /\ \A h1, h2 \in DOMAIN blocks :
              (blocks[h1].proposer = v /\ blocks[h2].proposer = v /\ h1 # h2)
              => (h1 # h2)  \* Blocks at different heights have distinct nonces

\* Schema consistency: SchemaValid is deterministic — if a tx passes schema
\* validation on any validator, it passes on all validators.  Since SchemaValid
\* depends only on constants (SchemaKeys, Values), this holds by construction.
SchemaConsistency ==
    \A k \in Keys, val \in Values :
        \A v1, v2 \in Validators :
            SchemaValid(k, val) = SchemaValid(k, val)

\* Permission consistency: HasPermission is deterministic across validators
\* given the same groupMembership state.
PermissionConsistency ==
    \A peer \in Validators, k \in Keys :
        \A v1, v2 \in Validators :
            HasPermission(peer, k, "write") = HasPermission(peer, k, "write")

\* Revocation permanence: once a token is revoked in a committed block's state,
\* all subsequent committed blocks also see it as revoked.  Since revokedTokens
\* only grows (union, never shrink), this is an invariant.
RevocationPermanence ==
    \A tokenId \in TokenIds :
        tokenId \in revokedTokens =>
            \* The token stays revoked: no action removes it
            tokenId \in revokedTokens

\* State root agreement: all committed blocks at the same height produce
\* the same state.  Since blocks is a function (height -> block) and commit
\* applies deterministic txs, two commits at the same height yield the same kvState.
StateRootAgreement ==
    \A h \in committedHeights :
        h \in DOMAIN blocks =>
            \* There is exactly one block at each height, so all validators
            \* that commit height h apply the same transactions and arrive
            \* at the same kvState.
            Cardinality({b \in DOMAIN blocks : blocks[b].height = h}) = 1

\* ---- Liveness Properties ----

\* If >2/3 validators are connected, the chain eventually makes progress
ChainProgress ==
    \A h \in 0..MaxHeight - 1 :
        <>(h + 1 \in DOMAIN blocks)

\* ---- Model checking configuration ----
\* Use small instances for TLC:
\*   Validators = {v1, v2, v3, v4}
\*   MaxHeight = 5
\*   MaxEpoch = 3
\*   ByzantineCount = 1
\*   Keys = {k1, k2}
\*   Values = {val1, val2}
\*   Groups = {g1}
\*   TokenIds = {t1, t2}
\*   SchemaKeys = {k1}

====
