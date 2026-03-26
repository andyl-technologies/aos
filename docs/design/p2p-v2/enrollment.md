# Network Enrollment

Enrollment is the process of admitting a node to the AOS network and
authorizing it to participate in clusters. A newly booted node starts in a
**pending** state — it has a peer keypair and the network public key but no
credentials. It can only accept inbound enrollment requests. Once enrolled,
the node joins the mesh and optionally participates in zero or more clusters.

## Trust Hierarchy

```
Network key (operator holds private, nodes have public via cloud-init)
  ├── [optional intermediates]
  │     └── Cluster root key (per-cluster, explicit creation)
  │           └── Intermediate certs (per-admin-domain)
  │                 └── UCANs (per-peer, per-job)
  └── Enrollment authority (network key itself, or a delegate cert chain)
```

The network key is the ultimate root of trust. It can delegate enrollment
authority to intermediate certs — an ops team can enroll nodes into specific
clusters without holding the network private key directly.

Cluster root keys are independent of the network key but can optionally be
signed by it (or by an intermediate in the network cert chain). Explicit
creation is required — cluster keys are never auto-generated.

## Node States

```
[booted] → [pending] → [enrolled]
```

### Pending

A pending node has:
- A peer keypair (generated on first boot, persisted locally)
- The network public key (from cloud-init)
- The `/aos/auth/enroll/1.0.0` stream protocol handler (listening)

A pending node does NOT:
- Participate in the mesh (no connections except inbound enroll requests)
- Subscribe to any GossipSub topics
- Publish any DHT records
- Accept any stream protocol requests except enrollment

The node verifies inbound enrollment requests against the network public key.
Connections from peers that cannot prove enrollment authority are rejected.

### Enrolled

An enrolled node participates in the network. It may belong to zero or more
clusters:

| Clusters | Behavior |
|---|---|
| Zero | Mesh routing, store protocols only. Useful for archive/submit-only nodes. |
| One | Full participation in that cluster (jobs, load reports, etc.). |
| Many | Per-cluster participation with separate UCANs, slices, and resource allocations. |

An enrolled node with zero clusters is valid — it can serve store content
and submit workflows, but does not subscribe to any cluster-specific topics.

**One-shot enrollment.** The `/aos/auth/enroll/1.0.0` endpoint accepts exactly
one enrollment request. After enrollment, the endpoint is disabled and returns
`503 Already Enrolled`. All subsequent configuration changes (cluster
membership, UCAN rotation, node features, labels, taints) are managed via
Statute writes at `/nodes/{peer_id}/*`. To factory-reset a node and return to
pending state, delete `/etc/aos/enrollment/` and restart the daemon.

## Key Management

### Network Key

```
aos net init
```

Generates the network ed25519 keypair. The public key is distributed to nodes
via cloud-init. The private key is stored in the operator's key store.

### Cluster Root Key

```
aos net cluster create <name>
```

Generates a cluster root ed25519 keypair. The cluster root key is independent
of the network key — it roots the cluster's own cert tree. The private key is
stored in the operator's key store.

### Key Store

The operator's machine uses a pluggable key store for network keys, cluster
root keys, and intermediate certs:

```toml
# ~/.config/aos/keystore.toml
[keystore]
type = "directory"              # plaintext directory (development)
path = "~/.config/aos/keys/"

# Other backends (TBD):
# type = "sops"                 # SOPS-encrypted files (git-committable)
# type = "age"                  # age-encrypted files
# type = "aws-kms"              # AWS KMS
# type = "vault"                # HashiCorp Vault
```

The CLI reads and writes keys through this abstraction. The key store holds:

```
~/.config/aos/keys/
  network.key                   # network private key
  network.pub                   # network public key
  clusters/
    prod/
      root.key                  # cluster root private key
      root.pub                  # cluster root public key
    staging/
      root.key
      root.pub
  intermediates/
    ops-admin.cert              # intermediate cert (signed by cluster root)
    ci-admin.cert
```

## Manual Enrollment

### CLI

```
aos net enroll <node_address> \
  --lifetime unlimited \
  --cluster prod \
  --cluster staging \
  --node-features kvm,big-parallel \
  --node-labels rack=r1,region=us-east \
  --capabilities prod:/aos/job/claim,/aos/store/read,/aos/load/write,/aos/load/read \
  --capabilities staging:/aos/store/read,/aos/load/read \
  --jobs-max prod:8,staging:4 \
  --slice-cpu-weight prod:100,staging:50 \
  --slice-memory-max prod:32G,staging:16G
```

This command only works on pending (unenrolled) nodes. If the node is already
enrolled, it returns an error (`503 Already Enrolled`). Post-enrollment
configuration changes are made via Statute writes (see Post-Enrollment
Configuration below).

The `<node_address>` can be:
- A direct IP + port: `10.0.1.5:4001`
- A multiaddr: `/ip4/10.0.1.5/udp/4001/quic-v1`
- Via SSH tunnel: `--ssh user@bastion -- 10.0.1.5:4001`

Capabilities are specified per-cluster. The node might be a builder in prod
and a cache in staging.

### Protocol Flow

1. **Connect.** The CLI opens a libp2p connection to the pending node and
   requests the `/aos/auth/enroll/1.0.0` stream.

2. **Challenge.** The node sends a random challenge nonce.

   The challenge nonce must be cryptographically random (at least 32 bytes) and
   single-use. The node tracks recently-used nonces and rejects replays. Nonces
   expire after 60 seconds — enrollment requests with stale nonces are rejected.

3. **Authenticate.** The CLI signs the challenge with the network private key
   (or presents a delegate cert chain rooted at the network key). The node
   verifies the signature against the network public key from its cloud-init
   config.

4. **Send enrollment.** The CLI sends an `EnrollRequest` containing:
   - Cluster configurations (IDs, root public keys, intermediate certs, UCANs)
   - Node configuration overrides (features, labels, taints, slice config)
   - Enrollment lifetime

5. **Node activates.** The node:
   a. Persists the enrollment config and credentials to disk
   b. Joins the libp2p mesh (begins connecting to other enrolled peers)
   c. For each cluster: creates the systemd slice, subscribes to cluster
      topics, publishes membership provider record, sends initial LoadReport
   d. Begins accepting stream protocol requests

6. **Respond.** The node sends an `EnrollResponse` confirming activation with
   the node's PeerId and the list of clusters joined.

### Stream Protocol

```
/aos/auth/enroll/1.0.0

  Node → CLI:   EnrollChallenge { nonce }
  CLI  → Node:  EnrollRequest { auth, clusters, config, lifetime }
  Node → CLI:   EnrollResponse { peer_id, clusters_joined, status }
```

### What Gets Persisted

After enrollment, the node stores:

```
/etc/aos/
  peer.key                          # generated on first boot (unchanged)
  daemon.toml                       # from cloud-init (unchanged)
  enrollment/
    enrollment.toml                 # enrollment metadata (lifetime, enrolled_at, enrolled_by)
    clusters/
      prod/
        config.toml                 # node config overrides for prod
        cluster_root.pub            # prod cluster root public key
        intermediate.cert           # intermediate cert for this node
        peer.ucan                   # UCAN chain for this node in prod
      staging/
        config.toml
        cluster_root.pub
        intermediate.cert
        peer.ucan
```

The `enrollment.toml` tracks enrollment metadata:

```toml
enrolled_at = 1710288000000000      # epoch microseconds
enrolled_by = "QmDeveloperPeerId"
lifetime = 0                        # 0 = unlimited
expires_at = 0                      # 0 = never

[network]
public_key = "ed25519:abc123..."

[clusters]
members = ["prod", "staging"]
```

### Cloud-Init Overrides

The enrollment config is an overlay on top of the cloud-init config. Fields
in the enrollment override cloud-init defaults:

```
Priority (highest wins):
  1. Enrollment config (from aos net enroll)
  2. Cloud-init user data
  3. Cloud-init vendor data
  4. Built-in defaults
```

For example, cloud-init might set `features = ["kvm"]` and enrollment adds
`big-parallel`. The merge behavior is:
- Lists (features, taints): union
- Maps (labels): merge (enrollment overrides per-key)
- Scalars (max_jobs): enrollment wins

### Post-Enrollment Configuration

After enrollment, node configuration is managed through Statute, not the
enrollment protocol. The node watches its own config namespace in Statute
for changes:

```
/nodes/{peer_id}/
    clusters                 → cluster membership list
    clusters/{id}/ucan       → per-cluster UCAN chain
    clusters/{id}/config     → per-cluster node config (features, labels, taints)
    config                   → global node config overrides
```

**Adding a cluster:** an operator writes a new entry to
`/nodes/{peer_id}/clusters/{new_cluster_id}/ucan` in Statute. The node sees
the change and subscribes to the new cluster's topics.

**Removing a cluster:** the operator deletes the cluster entry. The node
drains jobs and unsubscribes from that cluster's topics.

**Rotating UCANs:** the operator writes a new UCAN to
`/nodes/{peer_id}/clusters/{id}/ucan`. The node picks up the new UCAN on
the next Statute block.

**Updating features/labels/taints:** the operator writes to
`/nodes/{peer_id}/clusters/{id}/config`. The node updates its LoadReport
advertisements.

**Un-enrolling:** to return a node to pending state:
1. Remove `/nodes/{peer_id}` from Statute (operator action)
2. On the node: delete `/etc/aos/enrollment/` and restart the daemon
3. The node returns to pending state and accepts a new enrollment

## Enrollment Lifetime and Expiry

The enrollment lifetime controls how long the node's credentials are valid:

| Lifetime | Behavior |
|---|---|
| `unlimited` (default) | Credentials never expire. Node stays enrolled until manually un-enrolled via Statute delete + local cleanup. |
| Duration (e.g., `90d`) | Credentials expire after the duration. The node returns to pending state on expiry. |

When credentials are approaching expiry, the node logs warnings. The operator
must issue a new UCAN via Statute write to `/nodes/{peer_id}/clusters/{id}/ucan`
before expiry to maintain cluster membership. Expired nodes stop participating
in clusters but remain on the network in pending state — they can accept a new
enrollment without rebooting.

The UCAN `exp` claim is set to match the enrollment lifetime. Intermediate
certs have their own `not_after` field which may be shorter than the
enrollment lifetime (requiring cert renewal even if the enrollment is still
valid).

## Network Listing

To see all nodes on the network and their enrollment status:

```
aos net status
```

This queries:
- `get_providers` on `aos:cluster:{cluster_id}:members` for each known cluster to find
  enrolled members
- mDNS to find pending nodes (they respond to mDNS but don't publish DHT
  records)

Output:

```
Network: ed25519:abc123...
Peers: 14 total (12 enrolled, 2 pending)

PEER ID              STATUS     CLUSTERS           FEATURES
QmPeer1...           enrolled   prod, staging      kvm, big-parallel
QmPeer2...           enrolled   prod               kvm
QmPeer3...           enrolled   staging            kvm
...
QmPeerNew1...        pending    -                  -
QmPeerNew2...        pending    -                  -
```

## Cluster Management

### Create

```
aos net cluster create prod
```

Generates the cluster root keypair and stores it in the key store. Does not
publish anything to the network — the cluster becomes active when the first
node is enrolled into it.

### List

```
aos net cluster list
```

Shows clusters known to the key store and their membership (from DHT provider
records).

### Info

```
aos net cluster info prod
```

Shows cluster configuration, member list, intermediate certs, and resource
allocation across members.

## Protocol Messages

```protobuf
// Stream protocol: /aos/auth/enroll/1.0.0
message EnrollChallenge {
    bytes nonce = 1;                    // random challenge for auth
}

message EnrollRequest {
    // Authentication: proves enrollment authority
    oneof auth {
        bytes network_signature = 1;    // nonce signed by network private key
        CertChainAuth cert_chain = 2;   // delegate cert chain + signature
    }

    repeated ClusterEnrollment clusters = 3;
    EnrollmentConfig config = 4;
    uint64 lifetime = 5;               // microseconds; 0 = unlimited

    // Re-enrollment is not supported. Post-enrollment changes are via Statute.
    // Fields 6-7 reserved.
}

message CertChainAuth {
    repeated IntermediateCert chain = 1; // cert chain from network key to signer
    bytes signature = 2;                 // nonce signed by the leaf cert's key
}

message ClusterEnrollment {
    string cluster_id = 1;
    bytes cluster_root_public_key = 2;
    IntermediateCert intermediate = 3;  // intermediate cert for this node
    string ucan = 4;                    // UCAN for this node in this cluster

    // Per-cluster config overrides
    ClusterNodeConfig node_config = 5;
    ClusterJobsConfig jobs_config = 6;
    ClusterSliceConfig slice_config = 7;
}

message ClusterNodeConfig {
    repeated string features = 1;
    map<string, string> labels = 2;
    repeated Taint taints = 3;
}

message Taint {
    string key = 1;
    string value = 2;
    string effect = 3;                  // NoSchedule, PreferNoSchedule, NoExecute
}

message ClusterJobsConfig {
    uint32 max_jobs = 1;
}

message ClusterSliceConfig {
    uint32 cpu_weight = 1;
    string memory_max = 2;             // e.g., "32G"
    string memory_high = 3;
    uint32 io_weight = 4;
}

message EnrollResponse {
    oneof result {
        EnrollSuccess success = 1;
        StreamError error = 2;
    }
}

message EnrollSuccess {
    string peer_id = 1;                 // the enrolled node's PeerId
    repeated string clusters_joined = 2;
    repeated string clusters_removed = 3;
    uint64 enrolled_at = 4;
    uint64 expires_at = 5;             // 0 = never
}
```

## Relationship to Other Docs

- [daemon.md](daemon.md) -- daemon configuration, multi-cluster architecture,
  systemd slice hierarchy.
- [cloud-init.md](cloud-init.md) -- cloud-init module, the base config that
  enrollment overrides.
- [auth.md](auth.md) -- certificate tree, UCAN model, intermediate certs.
- [protocol.md](protocol.md) -- protobuf definitions for enrollment messages.
- [permissions.md](permissions.md) -- UCAN capabilities issued during
  enrollment.
