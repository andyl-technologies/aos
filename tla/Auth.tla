---- MODULE Auth ----
\* AOS Authorization: UCAN Revocation and Permission Propagation
\*
\* This specification models the distributed authorization concerns:
\*   1. UCAN revocation propagation (Statute write → gossipsub notification → cache invalidation)
\*   2. Statute permission change propagation (_permissions write → block commit → enforcement)
\*   3. Revocation window (time between revocation and universal enforcement)
\*   4. Split-brain authorization (partition during revocation)
\*   5. Epoch reconfiguration impact on authorization
\*
\* Safety properties:
\*   - Revocations are eventually enforced by all honest peers
\*   - Permission changes are eventually enforced by all honest peers
\*   - No peer accepts a revoked UCAN after the revocation window expires
\*
\* Liveness properties:
\*   - Revocation propagation completes within bounded time
\*   - Permission changes take effect within one block
\*
\* References:
\*   - docs/design/p2p-v2/auth.md
\*   - docs/design/p2p-v2/permissions.md
\*   - docs/design/p2p-v2/statute.md
\*
\* Built on: Network.tla (libp2p semantics)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Peers,               \* Set of all peer IDs
    Tokens,              \* Set of all UCAN token IDs
    Groups,              \* Set of all group IDs
    MaxTime,             \* Maximum time step
    NegCacheTTL,         \* Negative cache TTL (default 60s → 6 time units)
    PosCacheTTL,         \* Positive cache TTL (matches token expiry)
    MaxNegCacheSize      \* Max negative cache entries (LRU bound)

VARIABLES
    \* Token state
    tokenValid,          \* Ground truth: token -> bool (is the token valid?)
    tokenRevokedAt,      \* When each token was revoked: token -> time (0 = not revoked)
    tokenIssuedBy,       \* Which cert issued each token: token -> cert ID

    \* Certificate state
    certExpiry,          \* Cert expiry times: cert ID -> time
    certRevoked,         \* Cert revocation state: cert ID -> bool
    certChildren,        \* Cert hierarchy: cert ID -> set of child cert IDs

    \* Per-peer authorization cache
    posCache,            \* Positive cache (known revoked): peer -> set of {token, cached_at}
    negCache,            \* Negative cache (known NOT revoked): peer -> set of {token, cached_at}

    \* Gossipsub revocation notifications
    revocationNotices,   \* In-flight revocation notices: set of {token, sent_at}

    \* Statute permission state
    groupMembers,        \* Group membership: group -> set of peers
    permissionVersion,   \* Statute block height of last permission change
    peerPermView,        \* Each peer's view of permissions: peer -> version
    relationInheritance, \* Zanzibar relation inheritance: (group, relation) -> parent relation

    \* Operations attempted
    operationsAccepted,  \* Set of {peer, token, time} — operations accepted
    operationsRejected,  \* Set of {peer, token, time} — operations rejected

    \* Network
    partitions,          \* Set of {p1, p2} pairs

    \* Time
    time                 \* Global logical clock

vars == <<tokenValid, tokenRevokedAt, tokenIssuedBy,
          certExpiry, certRevoked, certChildren,
          posCache, negCache,
          revocationNotices, groupMembers, permissionVersion,
          peerPermView, relationInheritance,
          operationsAccepted, operationsRejected,
          partitions, time>>

\* ---- Helper operators ----

CanCommunicate(p1, p2) == {p1, p2} \notin partitions

\* Has an intermediate certificate expired?
CertExpired(cert, t) ==
    /\ cert \in DOMAIN certExpiry
    /\ certExpiry[cert] < t

\* Is a token considered valid by a specific peer?
\* Uses tiered validation: check pos cache, neg cache, then ground truth
\* Also checks if the issuing cert has expired or been revoked
PeerConsidersValid(peer, token) ==
    \* 0. Issuing cert expired → REJECT
    IF token \in DOMAIN tokenIssuedBy
       /\ CertExpired(tokenIssuedBy[token], time)
    THEN FALSE
    \* 0b. Issuing cert revoked → REJECT
    ELSE IF token \in DOMAIN tokenIssuedBy
            /\ tokenIssuedBy[token] \in DOMAIN certRevoked
            /\ certRevoked[tokenIssuedBy[token]]
    THEN FALSE
    \* 1. Positive cache hit: known revoked → REJECT
    ELSE IF \E c \in posCache[peer] : c.token = token
    THEN FALSE
    \* 2. Negative cache hit: known NOT revoked (within TTL) → ACCEPT
    ELSE IF \E c \in negCache[peer] :
        c.token = token /\ time - c.cached_at < NegCacheTTL
    THEN TRUE
    \* 3. Cache miss: check ground truth (simplified: instant DHT lookup)
    ELSE tokenValid[token]

\* Is a peer authorized by current Statute permissions?
\* Depends on whether the peer has synced the latest permission version
\* Walks the Zanzibar relation inheritance chain
RECURSIVE PeerHasPermission(_, _)
PeerHasPermission(peer, group) ==
    \/ /\ peer \in groupMembers[group]
       /\ peerPermView[peer] >= permissionVersion
    \/ \E parentRelation \in DOMAIN relationInheritance :
        relationInheritance[parentRelation] = group
        /\ PeerHasPermission(peer, parentRelation)

\* ---- Initial state ----

Init ==
    /\ tokenValid = [t \in Tokens |-> TRUE]
    /\ tokenRevokedAt = [t \in Tokens |-> 0]
    /\ tokenIssuedBy = [t \in Tokens |-> CHOOSE c \in Tokens : TRUE]  \* Simplified: cert IDs drawn from Tokens
    /\ certExpiry = [c \in {} |-> 0]          \* Initially no certs with expiry set
    /\ certRevoked = [c \in {} |-> FALSE]     \* Initially no certs revoked
    /\ certChildren = [c \in {} |-> {}]       \* Initially no cert hierarchy
    /\ posCache = [p \in Peers |-> {}]
    /\ negCache = [p \in Peers |-> {}]
    /\ revocationNotices = {}
    /\ groupMembers = [g \in Groups |-> Peers]  \* All peers in all groups initially
    /\ permissionVersion = 0
    /\ peerPermView = [p \in Peers |-> 0]
    /\ relationInheritance = [r \in {} |-> CHOOSE g \in Groups : TRUE]  \* Initially no inheritance
    /\ operationsAccepted = {}
    /\ operationsRejected = {}
    /\ partitions = {}
    /\ time = 0

\* ---- UCAN Revocation ----

\* Revoke a token (issuer writes to Statute)
RevokeToken(token) ==
    /\ tokenValid[token] = TRUE
    /\ tokenValid' = [tokenValid EXCEPT ![token] = FALSE]
    /\ tokenRevokedAt' = [tokenRevokedAt EXCEPT ![token] = time]
    \* Publish revocation notice to gossipsub
    /\ revocationNotices' = revocationNotices \union
           {[token |-> token, sent_at |-> time]}
    /\ UNCHANGED <<tokenIssuedBy, certExpiry, certRevoked, certChildren,
                   posCache, negCache, groupMembers, permissionVersion,
                   peerPermView, relationInheritance, operationsAccepted,
                   operationsRejected, partitions, time>>

\* Peer receives revocation notice (via gossipsub)
ReceiveRevocation(peer, notice) ==
    /\ notice \in revocationNotices
    /\ CanCommunicate(peer, CHOOSE p \in Peers : TRUE)  \* Simplified: can receive gossip
    \* Add to positive cache
    /\ posCache' = [posCache EXCEPT ![peer] =
           @ \union {[token |-> notice.token, cached_at |-> time]}]
    \* Invalidate negative cache for this token
    /\ negCache' = [negCache EXCEPT ![peer] =
           {c \in @ : c.token # notice.token}]
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   revocationNotices, groupMembers, permissionVersion,
                   peerPermView, relationInheritance, operationsAccepted,
                   operationsRejected, partitions, time>>

\* Peer adds a token to negative cache (checked and found valid)
CacheAsValid(peer, token) ==
    /\ tokenValid[token] = TRUE
    /\ ~\E c \in posCache[peer] : c.token = token
    /\ Cardinality(negCache[peer]) < MaxNegCacheSize  \* LRU bound
    /\ negCache' = [negCache EXCEPT ![peer] =
           @ \union {[token |-> token, cached_at |-> time]}]
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   posCache, revocationNotices, groupMembers, permissionVersion,
                   peerPermView, relationInheritance, operationsAccepted,
                   operationsRejected, partitions, time>>

\* Negative cache entry expires
NegCacheExpiry(peer, cached) ==
    /\ cached \in negCache[peer]
    /\ time - cached.cached_at >= NegCacheTTL
    /\ negCache' = [negCache EXCEPT ![peer] = @ \ {cached}]
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   posCache, revocationNotices, groupMembers, permissionVersion,
                   peerPermView, relationInheritance, operationsAccepted,
                   operationsRejected, partitions, time>>

\* ---- Statute Permission Changes ----

\* Remove a peer from a group (operator writes to Statute)
RemoveFromGroup(peer, group) ==
    /\ peer \in groupMembers[group]
    /\ groupMembers' = [groupMembers EXCEPT ![group] = @ \ {peer}]
    /\ permissionVersion' = permissionVersion + 1
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   posCache, negCache, revocationNotices,
                   peerPermView, relationInheritance, operationsAccepted,
                   operationsRejected, partitions, time>>

\* Add a peer to a group
AddToGroup(peer, group) ==
    /\ peer \notin groupMembers[group]
    /\ groupMembers' = [groupMembers EXCEPT ![group] = @ \union {peer}]
    /\ permissionVersion' = permissionVersion + 1
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   posCache, negCache, revocationNotices,
                   peerPermView, relationInheritance, operationsAccepted,
                   operationsRejected, partitions, time>>

\* Peer syncs to latest Statute block (updates permission view)
SyncPermissions(peer) ==
    /\ peerPermView[peer] < permissionVersion
    /\ peerPermView' = [peerPermView EXCEPT ![peer] = permissionVersion]
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   posCache, negCache, revocationNotices,
                   groupMembers, permissionVersion,
                   relationInheritance, operationsAccepted,
                   operationsRejected, partitions, time>>

\* ---- Operations (using tokens and permissions) ----

\* Peer attempts an operation using a UCAN token
AttemptOperation(peer, token) ==
    /\ IF PeerConsidersValid(peer, token)
       THEN operationsAccepted' = operationsAccepted \union
                {[peer |-> peer, token |-> token, time |-> time]}
            /\ operationsRejected' = operationsRejected
       ELSE operationsRejected' = operationsRejected \union
                {[peer |-> peer, token |-> token, time |-> time]}
            /\ operationsAccepted' = operationsAccepted
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   posCache, negCache, revocationNotices,
                   groupMembers, permissionVersion,
                   peerPermView, relationInheritance, partitions, time>>

\* ---- Network ----

CreatePartition(p1, p2) ==
    /\ p1 # p2
    /\ {p1, p2} \notin partitions
    /\ partitions' = partitions \union {{p1, p2}}
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   posCache, negCache, revocationNotices,
                   groupMembers, permissionVersion,
                   peerPermView, relationInheritance,
                   operationsAccepted, operationsRejected, time>>

HealPartition(p1, p2) ==
    /\ {p1, p2} \in partitions
    /\ partitions' = partitions \ {{p1, p2}}
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   posCache, negCache, revocationNotices,
                   groupMembers, permissionVersion,
                   peerPermView, relationInheritance,
                   operationsAccepted, operationsRejected, time>>

Tick ==
    /\ time' = time + 1
    /\ time < MaxTime
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certRevoked, certChildren,
                   posCache, negCache, revocationNotices,
                   groupMembers, permissionVersion,
                   peerPermView, relationInheritance,
                   operationsAccepted, operationsRejected,
                   partitions>>

\* ---- Certificate Revocation ----

\* Helper: compute the transitive closure of child certs
RECURSIVE SubtreeCerts(_)
SubtreeCerts(cert) ==
    IF cert \in DOMAIN certChildren
    THEN certChildren[cert] \union
         UNION {SubtreeCerts(child) : child \in certChildren[cert]}
    ELSE {}

\* Revoke a certificate and invalidate its entire subtree
RevokeCert(cert) ==
    /\ cert \in DOMAIN certExpiry
    /\ cert \in DOMAIN certRevoked
    /\ ~certRevoked[cert]
    /\ certRevoked' = [c \in DOMAIN certRevoked |->
           IF c = cert \/ c \in SubtreeCerts(cert)
           THEN TRUE
           ELSE certRevoked[c]]
    /\ UNCHANGED <<tokenValid, tokenRevokedAt, tokenIssuedBy,
                   certExpiry, certChildren,
                   posCache, negCache, revocationNotices,
                   groupMembers, permissionVersion,
                   peerPermView, relationInheritance,
                   operationsAccepted, operationsRejected,
                   partitions, time>>

\* ---- Next state ----

Next ==
    \/ \E t \in Tokens : RevokeToken(t)
    \/ \E p \in Peers, n \in revocationNotices : ReceiveRevocation(p, n)
    \/ \E p \in Peers, t \in Tokens : CacheAsValid(p, t)
    \/ \E p \in Peers, c \in UNION {negCache[q] : q \in Peers} : NegCacheExpiry(p, c)
    \/ \E p \in Peers, g \in Groups : RemoveFromGroup(p, g)
    \/ \E p \in Peers, g \in Groups : AddToGroup(p, g)
    \/ \E p \in Peers : SyncPermissions(p)
    \/ \E p \in Peers, t \in Tokens : AttemptOperation(p, t)
    \/ \E cert \in DOMAIN certExpiry : RevokeCert(cert)
    \/ \E p1 \in Peers, p2 \in Peers : CreatePartition(p1, p2)
    \/ \E p1 \in Peers, p2 \in Peers : HealPartition(p1, p2)
    \/ Tick

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

\* ---- Safety Properties ----

\* After revocation + negative cache expiry, no peer accepts the token
\* The revocation window is bounded by NegCacheTTL
RevocationEventualEnforcement ==
    \A t \in Tokens :
        (tokenRevokedAt[t] > 0 /\ time - tokenRevokedAt[t] > NegCacheTTL) =>
            ~\E op \in operationsAccepted :
                op.token = t /\ op.time > tokenRevokedAt[t] + NegCacheTTL

\* Positive cache entries are never wrong
\* (if a token is in the positive cache, it IS revoked)
PosCacheCorrectness ==
    \A p \in Peers :
        \A c \in posCache[p] :
            tokenValid[c.token] = FALSE

\* Negative cache is bounded (LRU)
NegCacheBounded ==
    \A p \in Peers :
        Cardinality(negCache[p]) <= MaxNegCacheSize

\* Permission changes are eventually visible
\* (after sync, peer sees the latest version)
PermissionVisibility ==
    \A p \in Peers :
        peerPermView[p] <= permissionVersion

\* A UCAN issued by an expired cert is always rejected
ExpiredCertRejection ==
    \A t \in Tokens, p \in Peers :
        (\E cert \in DOMAIN certExpiry :
            certExpiry[cert] < time /\ tokenIssuedBy[t] = cert)
        => ~PeerConsidersValid(p, t)

\* Revoking a cert invalidates its entire subtree
SubtreeRevocation ==
    \A cert \in DOMAIN certExpiry :
        certRevoked[cert] =>
            \A childCert \in certChildren[cert] :
                \A t \in Tokens :
                    tokenIssuedBy[t] = childCert => ~PeerConsidersValid(CHOOSE p \in Peers : TRUE, t)

\* ---- Liveness Properties ----

\* Revocations are eventually received by all connected peers
RevocationPropagation ==
    \A t \in Tokens :
        tokenRevokedAt[t] > 0 =>
            <>(\A p \in Peers :
                \E c \in posCache[p] : c.token = t)

\* Permission changes are eventually synced by all peers
PermissionConvergence ==
    <>(\A p \in Peers : peerPermView[p] = permissionVersion)

\* ---- Revocation Window Analysis ----

\* The maximum time a revoked token can still be used
\* = max(gossipsub propagation delay, negative cache TTL)
\* After this window, all peers reject the token
RevocationWindowBound ==
    \A t \in Tokens, p \in Peers :
        (tokenRevokedAt[t] > 0
         /\ time - tokenRevokedAt[t] > NegCacheTTL + 2)  \* +2 for propagation
        => ~PeerConsidersValid(p, t)

\* ---- Model checking configuration ----
\* Use small instances:
\*   Peers = {p1, p2, p3}
\*   Tokens = {t1, t2}
\*   Groups = {g1}
\*   MaxTime = 20
\*   NegCacheTTL = 6
\*   PosCacheTTL = 20
\*   MaxNegCacheSize = 5

====
